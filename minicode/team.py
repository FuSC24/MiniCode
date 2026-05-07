"""Inbox-based message bus + teammate manager + protocol handlers.

agent_runner is injected by minicode.cli at startup."""
import json
import re
import threading
import time
import uuid

from minicode.config import (
    INBOX_DIR, TEAM_DIR, TEAM_MAX_CONSECUTIVE_TURNS, VALID_MSG_TYPES,
    POLL_INTERVAL, IDLE_TIMEOUT, WORKDIR, client, MODEL, TOKEN_THRESHOLD,
)
from minicode.tasks import TASK_MGR, TaskManager
from minicode.security import PERMS, PermissionManager
from minicode.hooks import HOOKS, HookManager
from minicode.mcp import MCP
from minicode.compression import estimate_tokens, microcompact, auto_compact, append_user_text
from minicode.tools import run_bash, run_read, run_write, run_edit

agent_runner = None  # set by minicode.cli at startup; takes a history list and runs one turn-cycle.

# === SECTION: messaging ================================================
class MessageBus:
    """File-backed inbox per teammate. One JSONL file per recipient.

    Per-recipient locks keep `read+truncate` atomic so a `send` interleaved
    between read and truncate won't get clobbered. Different recipients
    don't block each other.
    """

    def __init__(self):
        INBOX_DIR.mkdir(parents=True, exist_ok=True)
        self._locks: dict = {}
        self._locks_lock = threading.Lock()

    def _lock_for(self, name: str) -> threading.Lock:
        with self._locks_lock:
            lk = self._locks.get(name)
            if lk is None:
                lk = self._locks[name] = threading.Lock()
            return lk

    def send(self, sender: str, to: str, content: str,
             msg_type: str = "message", extra: dict = None) -> str:
        if msg_type not in VALID_MSG_TYPES:
            return f"Error: bad msg_type '{msg_type}'. Allowed: {sorted(VALID_MSG_TYPES)}"
        msg = {"type": msg_type, "from": sender, "to": to,
               "content": content, "timestamp": time.time()}
        if extra:
            msg.update(extra)
        with self._lock_for(to):
            with open(INBOX_DIR / f"{to}.jsonl", "a") as f:
                f.write(json.dumps(msg) + "\n")
        return f"Sent {msg_type} to {to}"

    def read_inbox(self, name: str) -> list:
        with self._lock_for(name):
            p = INBOX_DIR / f"{name}.jsonl"
            if not p.exists():
                return []
            text = p.read_text()
            # Truncate while still under the lock so concurrent sends
            # append into a fresh file, not the snapshot we're parsing.
            p.write_text("")
        msgs = []
        for line in text.splitlines():
            try:
                msgs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return msgs

    def broadcast(self, sender: str, content: str, names: list) -> str:
        n = 0
        for name in names:
            if name != sender:
                self.send(sender, name, content, "broadcast")
                n += 1
        return f"Broadcast to {n} teammates"


# === SECTION: team_protocol ============================================
shutdown_requests = {}
plan_requests = {}


# === SECTION: teammates ============================================
class TeammateManager:
    """Spawn long-running teammates that work, idle, then resume on signals.

    Each teammate runs a per-thread loop:
        WORK PHASE: respond to inbox / current goal up to N turns.
        IDLE PHASE: poll the inbox, then auto-claim unclaimed tasks.
    Identity is re-injected when context shrinks so the agent never forgets
    who it is across long idles.
    """

    def __init__(self, bus: MessageBus, task_mgr: TaskManager,
                 perms: PermissionManager, hooks: HookManager,
                 mcp: 'MCPManager'):
        TEAM_DIR.mkdir(parents=True, exist_ok=True)
        self.bus = bus
        self.task_mgr = task_mgr
        self.perms = perms
        self.hooks = hooks
        self.mcp = mcp
        self.config_path = TEAM_DIR / "config.json"
        self.config = self._load()

    def _load(self) -> dict:
        if self.config_path.exists():
            return json.loads(self.config_path.read_text())
        return {"team_name": "default", "members": []}

    def _save(self):
        self.config_path.write_text(json.dumps(self.config, indent=2))

    def _find(self, name: str) -> dict:
        for m in self.config["members"]:
            if m["name"] == name:
                return m
        return None

    def _set_status(self, name: str, status: str):
        m = self._find(name)
        if m:
            m["status"] = status
            self._save()

    def spawn(self, name: str, role: str, prompt: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_-]+$", name):
            return "Error: teammate name must be [a-zA-Z0-9_-]"
        if name == "lead":
            return "Error: 'lead' is reserved"
        m = self._find(name)
        if m:
            if m["status"] not in ("idle", "shutdown"):
                return f"Error: '{name}' is currently {m['status']}"
            m["status"] = "working"
            m["role"] = role
        else:
            self.config["members"].append({"name": name, "role": role, "status": "working"})
        self._save()
        threading.Thread(target=self._loop, args=(name, role, prompt), daemon=True).start()
        return f"Spawned teammate '{name}' (role: {role})"

    def list_all(self) -> str:
        if not self.config["members"]:
            return "No teammates."
        lines = [f"Team: {self.config['team_name']}"]
        for m in self.config["members"]:
            lines.append(f"  {m['name']} ({m['role']}): {m['status']}")
        return "\n".join(lines)

    def member_names(self) -> list:
        return [m["name"] for m in self.config["members"]]

    def _teammate_tools(self):
        return [
            {"name": "bash", "description": "Run shell command.",
             "input_schema": {"type": "object",
                              "properties": {"command": {"type": "string"}},
                              "required": ["command"]}},
            {"name": "read_file", "description": "Read file.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"}},
                              "required": ["path"]}},
            {"name": "write_file", "description": "Write file.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"},
                                             "content": {"type": "string"}},
                              "required": ["path", "content"]}},
            {"name": "edit_file", "description": "Edit file by replacing exact text.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"},
                                             "old_text": {"type": "string"},
                                             "new_text": {"type": "string"}},
                              "required": ["path", "old_text", "new_text"]}},
            {"name": "send_message", "description": "Send a message to another teammate or 'lead'.",
             "input_schema": {"type": "object",
                              "properties": {"to": {"type": "string"},
                                             "content": {"type": "string"}},
                              "required": ["to", "content"]}},
            {"name": "claim_task", "description": "Claim a task from the board by ID.",
             "input_schema": {"type": "object",
                              "properties": {"task_id": {"type": "integer"}},
                              "required": ["task_id"]}},
            {"name": "task_update", "description": "Update a task you own.",
             "input_schema": {"type": "object",
                              "properties": {"task_id": {"type": "integer"},
                                             "status": {"type": "string",
                                                        "enum": ["pending", "in_progress",
                                                                 "completed", "deleted"]}},
                              "required": ["task_id"]}},
            {"name": "request_plan_approval",
             "description": "Send a plan to lead for approval before executing.",
             "input_schema": {"type": "object",
                              "properties": {"plan": {"type": "string"}},
                              "required": ["plan"]}},
            {"name": "idle", "description": "Signal no more current work; enter idle phase.",
             "input_schema": {"type": "object", "properties": {}}},
        ]

    def _exec_teammate_tool(self, name: str, block) -> tuple:
        """Returns (content, is_error) -- same contract as execute_one_tool."""
        # Permission check shared with the lead.
        decision = self.perms.check(block.name, dict(block.input or {}))
        if decision["behavior"] == "deny":
            return (f"Error: permission denied for teammate '{name}'. "
                    f"Reason: {decision['reason']}. The tool did NOT run."), True
        if decision["behavior"] == "ask":
            # Teammates can't pop a modal -- treat ask as deny.
            return (f"Error: tool requires user confirmation but teammates "
                    f"cannot prompt the user. Reason: {decision['reason']}. "
                    f"The tool did NOT run -- ask 'lead' for approval via "
                    f"request_plan_approval, or escalate via send_message."), True
        try:
            if block.name == "bash":
                out = run_bash(block.input["command"], block.id)
            elif block.name == "read_file":
                out = run_read(block.input["path"], block.id, block.input.get("limit"))
            elif block.name == "write_file":
                out = run_write(block.input["path"], block.input["content"])
            elif block.name == "edit_file":
                out = run_edit(block.input["path"], block.input["old_text"],
                               block.input["new_text"])
            elif block.name == "send_message":
                out = self.bus.send(name, block.input["to"], block.input["content"])
            elif block.name == "claim_task":
                out = self.task_mgr.claim(block.input["task_id"], name)
            elif block.name == "task_update":
                out = self.task_mgr.update(block.input["task_id"],
                                            block.input.get("status"),
                                            actor=name)
            elif block.name == "request_plan_approval":
                req_id = str(uuid.uuid4())[:8]
                plan_requests[req_id] = {"from": name, "plan": block.input["plan"],
                                          "status": "pending"}
                self.bus.send(name, "lead", block.input["plan"],
                              "plan_approval_request", {"request_id": req_id})
                out = f"Plan approval requested ({req_id})"
            else:
                return f"Error: unknown teammate tool '{block.name}'", True
        except Exception as e:
            return f"Error: {e}", True
        is_error = isinstance(out, str) and out.lstrip().startswith("Error:")
        return out, is_error

    def _loop(self, name: str, role: str, prompt: str):
        try:
            self._loop_body(name, role, prompt)
        except Exception as e:
            # Top-level guard so a thread can't die silently with status
            # stuck on "working" -- the team panel would otherwise show a
            # zombie member forever.
            import traceback
            print(f"  [{name}] CRASHED: {e}\n{traceback.format_exc()}")
            self._set_status(name, "crashed")

    def _loop_body(self, name: str, role: str, prompt: str):
        team_name = self.config["team_name"]
        sys_prompt = (f"You are '{name}', role: {role}, team: {team_name}, at {WORKDIR}. "
                      "Use idle when you have no more current work. "
                      "Auto-claim pending tasks on the board if no one is blocking you. "
                      "Use request_plan_approval before doing anything destructive.")
        messages = [{"role": "user", "content": prompt}]
        tools = self._teammate_tools()
        while True:
            # WORK PHASE
            for _ in range(TEAM_MAX_CONSECUTIVE_TURNS):
                inbox = self.bus.read_inbox(name)
                shutdown_now = False
                inbox_payload = []
                for msg in inbox:
                    if msg.get("type") == "shutdown_request":
                        shutdown_now = True
                        break
                    inbox_payload.append(json.dumps(msg))
                if shutdown_now:
                    self._set_status(name, "shutdown")
                    return
                if inbox_payload:
                    # Combine multiple inbox messages into a single user
                    # entry to avoid consecutive {"role":"user"} entries.
                    append_user_text(
                        messages,
                        "<inbox>\n" + "\n".join(inbox_payload) + "\n</inbox>")
                try:
                    response = client.messages.create(
                        model=MODEL, system=sys_prompt, messages=messages,
                        tools=tools, max_tokens=8000)
                except Exception as e:
                    print(f"  [{name}] LLM error: {e}; entering shutdown")
                    self._set_status(name, "shutdown")
                    return
                messages.append({"role": "assistant", "content": response.content})
                if response.stop_reason != "tool_use":
                    break
                results = []
                idle_requested = False
                for block in response.content:
                    if block.type == "tool_use":
                        if block.name == "idle":
                            idle_requested = True
                            output, is_error = "Entering idle phase.", False
                        else:
                            try:
                                output, is_error = self._exec_teammate_tool(name, block)
                            except Exception as e:
                                output, is_error = f"Error: {e}", True
                        tag = "!" if is_error else " "
                        print(f"  [{name}]{tag}{block.name}: {str(output)[:120]}")
                        tr = {"type": "tool_result",
                              "tool_use_id": block.id, "content": str(output)}
                        if is_error:
                            tr["is_error"] = True
                        results.append(tr)
                messages.append({"role": "user", "content": results})
                if idle_requested:
                    break
                # Compress on the long-running thread too.
                microcompact(messages)
                if estimate_tokens(messages) > TOKEN_THRESHOLD:
                    messages[:] = auto_compact(messages, focus=f"role={role}")

            # IDLE PHASE
            self._set_status(name, "idle")
            resume = False
            for _ in range(IDLE_TIMEOUT // max(POLL_INTERVAL, 1)):
                time.sleep(POLL_INTERVAL)
                inbox = self.bus.read_inbox(name)
                if inbox:
                    payload = []
                    for msg in inbox:
                        if msg.get("type") == "shutdown_request":
                            self._set_status(name, "shutdown")
                            return
                        payload.append(json.dumps(msg))
                    if payload:
                        append_user_text(
                            messages,
                            "<inbox>\n" + "\n".join(payload) + "\n</inbox>")
                    resume = True
                    break
                # claim() races with peers; skip Error to the next candidate.
                task = None
                for candidate in self.task_mgr.unclaimed():
                    if not self.task_mgr.claim(candidate["id"], name).startswith("Error:"):
                        task = candidate
                        break
                if task:
                    if len(messages) <= 3:
                        # Identity re-injection after a compact.
                        messages.insert(0, {"role": "user", "content":
                            f"<identity>You are '{name}', role: {role}, team: {team_name}.</identity>"})
                        messages.insert(1, {"role": "assistant",
                                            "content": f"I am {name}. Continuing."})
                    append_user_text(
                        messages,
                        f"<auto-claimed>Task #{task['id']}: {task['subject']}\n"
                        f"{task.get('description', '')}</auto-claimed>")
                    messages.append({"role": "assistant",
                                     "content": f"Claimed task #{task['id']}. Working on it."})
                    resume = True
                    break
            if not resume:
                self._set_status(name, "shutdown")
                return
            self._set_status(name, "working")


# === SECTION: shutdown / plan_approval =================================
def handle_shutdown_request(bus: MessageBus, teammate: str) -> str:
    req_id = str(uuid.uuid4())[:8]
    shutdown_requests[req_id] = {"target": teammate, "status": "pending"}
    bus.send("lead", teammate, "Please shut down.", "shutdown_request",
             {"request_id": req_id})
    return f"Shutdown request {req_id} sent to '{teammate}'"


def handle_plan_review(bus: MessageBus, request_id: str,
                       approve: bool, feedback: str = "") -> str:
    req = plan_requests.get(request_id)
    if not req:
        return f"Error: unknown plan request_id '{request_id}'"
    req["status"] = "approved" if approve else "rejected"
    bus.send("lead", req["from"], feedback, "plan_approval_response",
             {"request_id": request_id, "approve": approve, "feedback": feedback})
    return f"Plan {req['status']} for '{req['from']}'"


BUS = MessageBus()
TEAM = TeammateManager(BUS, TASK_MGR, PERMS, HOOKS, MCP)
