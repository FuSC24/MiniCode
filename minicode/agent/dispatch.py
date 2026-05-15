"""Tool registry, parallel safety, prompt caching, single-tool execution."""
import json
import os
import threading

from minicode.config import client
from minicode.services.security import PermissionManager, PERMS
from minicode.services.hooks import HookManager, HOOKS
from minicode.tools import (
    run_bash, run_read, run_write, run_edit, run_grep, run_glob,
)
from minicode.tools.subagent import run_subagent
from minicode.tools.todos import TODO
from minicode.tools.skills import SKILLS
from minicode.tools.tasks import TASK_MGR, BG
from minicode.tools.memory import MEMORY
from minicode.tools.scheduling import CRON
from minicode.tools.worktree import WORKTREES
from minicode.tools.mcp import MCP
from minicode.tools.team import BUS, TEAM, handle_shutdown_request, handle_plan_review
from minicode.prompts import build_system_prompt


# === SECTION: tool_dispatch ============================================
TOOL_HANDLERS = {
    "bash":             lambda **kw: run_bash(kw["command"], kw.get("tool_use_id", ""), kw.get("timeout", 120)),
    "read_file":        lambda **kw: run_read(kw["path"], kw.get("tool_use_id", ""),
                                              kw.get("limit"), kw.get("offset")),
    "write_file":       lambda **kw: run_write(kw["path"], kw["content"]),
    "edit_file":        lambda **kw: run_edit(kw["path"], kw["old_text"], kw["new_text"]),
    "grep":             lambda **kw: run_grep(kw["pattern"], kw.get("path", "."),
                                              kw.get("glob", "*"), kw.get("tool_use_id", "")),
    "glob":             lambda **kw: run_glob(kw["pattern"], kw.get("tool_use_id", "")),
    "TodoWrite":        lambda **kw: TODO.update(kw["items"]),
    "task":             lambda **kw: run_subagent(kw["prompt"], kw.get("agent_type", "Explore"),
                                                  kw.get("max_turns", 30)),
    "load_skill":       lambda **kw: SKILLS.load(kw["name"]),
    "list_skills":      lambda **kw: SKILLS.list_all(),
    "compress":         lambda **kw: "Compressing...",
    "background_run":   lambda **kw: BG.run(kw["command"], kw.get("timeout", 600)),
    "check_background": lambda **kw: BG.check(kw.get("task_id")),
    "kill_background":  lambda **kw: BG.kill(kw["task_id"]),
    "task_create":      lambda **kw: TASK_MGR.create(kw["subject"], kw.get("description", ""),
                                                     kw.get("blocked_by"), kw.get("worktree")),
    "task_get":         lambda **kw: TASK_MGR.get(kw["task_id"]),
    "task_update":      lambda **kw: TASK_MGR.update(
                                        kw["task_id"], kw.get("status"),
                                        kw.get("add_blocked_by"), kw.get("add_blocks"),
                                        kw.get("worktree"), actor="lead"),
    "task_list":        lambda **kw: TASK_MGR.list_all(),
    "save_memory":      lambda **kw: MEMORY.save(kw["name"], kw["description"],
                                                 kw["mem_type"], kw["content"]),
    "delete_memory":    lambda **kw: MEMORY.delete(kw["name"]),
    "list_memory":      lambda **kw: MEMORY.list_all(),
    "schedule_create":  lambda **kw: CRON.create(kw["cron"], kw["prompt"],
                                                 kw.get("recurring", True),
                                                 kw.get("durable", False)),
    "schedule_delete":  lambda **kw: CRON.delete(kw["task_id"]),
    "schedule_list":    lambda **kw: CRON.list_tasks(),
    "worktree_create":  lambda **kw: WORKTREES.create(kw["name"], kw.get("base", "HEAD")),
    "worktree_remove":  lambda **kw: WORKTREES.remove(kw["name"], kw.get("force", False)),
    "worktree_bind":    lambda **kw: WORKTREES.bind_task(kw["name"], kw["task_id"]),
    "list_worktrees":   lambda **kw: WORKTREES.list_all(),
    "list_mcp_tools":   lambda **kw: MCP.list_tools(),
    "spawn_teammate":   lambda **kw: TEAM.spawn(kw["name"], kw["role"], kw["prompt"]),
    "list_teammates":   lambda **kw: TEAM.list_all(),
    "send_message":     lambda **kw: BUS.send("lead", kw["to"], kw["content"],
                                              kw.get("msg_type", "message")),
    "read_inbox":       lambda **kw: json.dumps(BUS.read_inbox("lead"), indent=2),
    "broadcast":        lambda **kw: BUS.broadcast("lead", kw["content"], TEAM.member_names()),
    "shutdown_request": lambda **kw: handle_shutdown_request(BUS, kw["teammate"]),
    "plan_approval":    lambda **kw: handle_plan_review(BUS, kw["request_id"],
                                                        kw["approve"], kw.get("feedback", "")),
    "claim_task":       lambda **kw: TASK_MGR.claim(kw["task_id"], "lead"),
}


from minicode.tools.memory import MEMORY_TYPES
from minicode.config import VALID_MSG_TYPES

TOOLS_BASE = [
    {"name": "bash", "description": "Run a shell command in the workspace.",
     "input_schema": {"type": "object",
                      "properties": {"command": {"type": "string"},
                                     "timeout": {"type": "integer", "default": 120}},
                      "required": ["command"]}},
    {"name": "read_file", "description": "Read file contents (returns numbered lines).",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"},
                                     "limit": {"type": "integer"},
                                     "offset": {"type": "integer"}},
                      "required": ["path"]}},
    {"name": "write_file", "description": "Write content to a file (overwrites).",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"},
                                     "content": {"type": "string"}},
                      "required": ["path", "content"]}},
    {"name": "edit_file", "description": "Replace one exact occurrence of old_text with new_text.",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"},
                                     "old_text": {"type": "string"},
                                     "new_text": {"type": "string"}},
                      "required": ["path", "old_text", "new_text"]}},
    {"name": "grep", "description": "Recursive regex grep across the workspace.",
     "input_schema": {"type": "object",
                      "properties": {"pattern": {"type": "string"},
                                     "path": {"type": "string", "default": "."},
                                     "glob": {"type": "string", "default": "*"}},
                      "required": ["pattern"]}},
    {"name": "glob", "description": "Glob match files relative to WORKDIR.",
     "input_schema": {"type": "object",
                      "properties": {"pattern": {"type": "string"}},
                      "required": ["pattern"]}},
    {"name": "TodoWrite",
     "description": "Update the in-memory todo list. Items: content, status, activeForm.",
     "input_schema": {"type": "object",
                      "properties": {"items": {"type": "array", "items": {
                          "type": "object",
                          "properties": {"content": {"type": "string"},
                                         "status": {"type": "string",
                                                    "enum": ["pending", "in_progress", "completed"]},
                                         "activeForm": {"type": "string"}},
                          "required": ["content", "status", "activeForm"]}}},
                      "required": ["items"]}},
    {"name": "task", "description": "Spawn a subagent for isolated exploration or work.",
     "input_schema": {"type": "object",
                      "properties": {"prompt": {"type": "string"},
                                     "agent_type": {"type": "string",
                                                    "enum": ["Explore", "general-purpose"]},
                                     "max_turns": {"type": "integer", "default": 30}},
                      "required": ["prompt"]}},
    {"name": "load_skill", "description": "Load a named skill's body into context.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "list_skills", "description": "List skills with descriptions.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "compress", "description": "Manually compact the conversation context.",
     "input_schema": {"type": "object",
                      "properties": {"focus": {"type": "string"}}}},
    {"name": "background_run", "description": "Run a shell command in a background thread.",
     "input_schema": {"type": "object",
                      "properties": {"command": {"type": "string"},
                                     "timeout": {"type": "integer", "default": 600}},
                      "required": ["command"]}},
    {"name": "check_background", "description": "Check status of background tasks.",
     "input_schema": {"type": "object", "properties": {"task_id": {"type": "string"}}}},
    {"name": "kill_background", "description": "Mark a background task as killed.",
     "input_schema": {"type": "object",
                      "properties": {"task_id": {"type": "string"}},
                      "required": ["task_id"]}},
    {"name": "task_create", "description": "Create a durable file-backed task.",
     "input_schema": {"type": "object",
                      "properties": {"subject": {"type": "string"},
                                     "description": {"type": "string"},
                                     "blocked_by": {"type": "array", "items": {"type": "integer"}},
                                     "worktree": {"type": "string"}},
                      "required": ["subject"]}},
    {"name": "task_get", "description": "Get task details by integer ID.",
     "input_schema": {"type": "object",
                      "properties": {"task_id": {"type": "integer"}},
                      "required": ["task_id"]}},
    {"name": "task_update",
     "description": "Update a task's status / dependencies / worktree.",
     "input_schema": {"type": "object",
                      "properties": {"task_id": {"type": "integer"},
                                     "status": {"type": "string",
                                                "enum": ["pending", "in_progress",
                                                         "completed", "deleted"]},
                                     "add_blocked_by": {"type": "array",
                                                        "items": {"type": "integer"}},
                                     "add_blocks": {"type": "array",
                                                    "items": {"type": "integer"}},
                                     "worktree": {"type": "string"}},
                      "required": ["task_id"]}},
    {"name": "task_list", "description": "List all tasks.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "save_memory", "description":
     "Save a cross-session memory. mem_type one of user/feedback/project/reference.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"},
                                     "description": {"type": "string"},
                                     "mem_type": {"type": "string",
                                                  "enum": list(MEMORY_TYPES)},
                                     "content": {"type": "string"}},
                      "required": ["name", "description", "mem_type", "content"]}},
    {"name": "delete_memory", "description": "Delete a memory by name.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "list_memory", "description": "List saved memories.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "schedule_create", "description":
     "Schedule a prompt to fire on a 5-field cron expression.",
     "input_schema": {"type": "object",
                      "properties": {"cron": {"type": "string"},
                                     "prompt": {"type": "string"},
                                     "recurring": {"type": "boolean", "default": True},
                                     "durable": {"type": "boolean", "default": False}},
                      "required": ["cron", "prompt"]}},
    {"name": "schedule_delete", "description": "Delete a scheduled cron task by ID.",
     "input_schema": {"type": "object",
                      "properties": {"task_id": {"type": "string"}},
                      "required": ["task_id"]}},
    {"name": "schedule_list", "description": "List scheduled cron tasks.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "worktree_create",
     "description": "Create a git worktree (or directory lane if not a git repo).",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"},
                                     "base": {"type": "string", "default": "HEAD"}},
                      "required": ["name"]}},
    {"name": "worktree_remove", "description": "Remove a worktree.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"},
                                     "force": {"type": "boolean", "default": False}},
                      "required": ["name"]}},
    {"name": "worktree_bind",
     "description": "Bind an existing worktree to a task ID.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"},
                                     "task_id": {"type": "integer"}},
                      "required": ["name", "task_id"]}},
    {"name": "list_worktrees", "description": "List worktrees.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "list_mcp_tools", "description": "List loaded MCP tools.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "spawn_teammate",
     "description": "Spawn a persistent teammate that can claim tasks autonomously.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"},
                                     "role": {"type": "string"},
                                     "prompt": {"type": "string"}},
                      "required": ["name", "role", "prompt"]}},
    {"name": "list_teammates", "description": "List teammates and their statuses.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "send_message",
     "description": "Send a typed message from lead to a teammate.",
     "input_schema": {"type": "object",
                      "properties": {"to": {"type": "string"},
                                     "content": {"type": "string"},
                                     "msg_type": {"type": "string",
                                                  "enum": list(VALID_MSG_TYPES)}},
                      "required": ["to", "content"]}},
    {"name": "read_inbox", "description": "Read and drain the lead's inbox.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "broadcast", "description": "Broadcast a message to all teammates.",
     "input_schema": {"type": "object",
                      "properties": {"content": {"type": "string"}},
                      "required": ["content"]}},
    {"name": "shutdown_request", "description": "Ask a teammate to shut down.",
     "input_schema": {"type": "object",
                      "properties": {"teammate": {"type": "string"}},
                      "required": ["teammate"]}},
    {"name": "plan_approval", "description":
     "Approve or reject a teammate's pending plan_approval_request.",
     "input_schema": {"type": "object",
                      "properties": {"request_id": {"type": "string"},
                                     "approve": {"type": "boolean"},
                                     "feedback": {"type": "string"}},
                      "required": ["request_id", "approve"]}},
    {"name": "claim_task", "description": "Claim a task as the lead.",
     "input_schema": {"type": "object",
                      "properties": {"task_id": {"type": "integer"}},
                      "required": ["task_id"]}},
]


def all_tools() -> list:
    return TOOLS_BASE + MCP.tool_specs()


# === SECTION: prompt_caching =================================================
# Anthropic prompt caching: mark the END of each cacheable section with a
# `cache_control: ephemeral` block. The provider keys the cache by the prefix
# up to and including the marked block. We mark two stable sections:
#   1. The system prompt (changes only when memories or skills change)
#   2. The tool list   (essentially fixed within a session)
#
# `MINICODE_CACHE=0` disables both, in case the proxy returns a 400 on the
# unknown field. Anthropic-native always supports this; third-party
# Anthropic-compatible proxies may or may not.
CACHE_ENABLED = os.environ.get("MINICODE_CACHE", "1") != "0"


def system_blocks_cached():
    """Return system as a list-of-blocks with the prefix cached."""
    text = build_system_prompt()
    if not CACHE_ENABLED:
        return text
    return [{
        "type": "text",
        "text": text,
        "cache_control": {"type": "ephemeral"},
    }]


def tools_cached():
    """Return tools list with cache_control on the last entry (caches them all)."""
    tools = list(all_tools())
    if CACHE_ENABLED and tools:
        tools[-1] = {**tools[-1], "cache_control": {"type": "ephemeral"}}
    return tools


# === SECTION: parallel_dispatch ==============================================
# Tools that have no side effects can run concurrently within a single turn.
# Everything else (write_file, edit_file, bash, mutation of tasks/memory/team,
# cron / mcp / compress, ...) stays serial in declaration order.
PARALLEL_SAFE_TOOLS = {
    "read_file", "grep", "glob",
    "load_skill", "list_skills",
    "task_get", "task_list",
    "list_memory", "list_teammates", "list_mcp_tools",
    "list_worktrees", "schedule_list",
    "check_background", "read_inbox",
}
PARALLEL_MAX_WORKERS = 6
# Serializes permission prompts when multiple tools want to ask the user at
# once. The TUI modal and the REPL `input()` both can only handle one prompt
# at a time, so we lock around `perms.ask_user`.
_PERMS_ASK_LOCK = threading.Lock()


def execute_one_tool(block, hooks: HookManager, perms: PermissionManager) -> tuple:
    """Run PreToolUse hook -> permission -> handler -> PostToolUse hook.

    Returns (content, is_error). The caller MUST forward `is_error=True`
    into the tool_result, otherwise the model treats "Permission denied"
    as a normal success string and may hallucinate the action happened.
    """
    tool_input = dict(block.input or {})
    context = {"tool_name": block.name, "tool_input": tool_input}
    pre = hooks.run("PreToolUse", context)
    if pre.get("blocked"):
        return (f"Error: a PreToolUse hook blocked this call. "
                f"Reason: {pre.get('block_reason', 'no reason given')}. "
                f"The tool did NOT run."), True
    if pre.get("permission_override") == "deny":
        return ("Error: hook denied this tool via permission_override. "
                "The tool did NOT run."), True
    if pre.get("permission_override") != "allow":
        decision = perms.check(block.name, tool_input)
        if decision["behavior"] == "deny":
            return (f"Error: permission denied by policy. "
                    f"Reason: {decision['reason']}. The tool did NOT run. "
                    f"Tell the user; do not claim the action succeeded."), True
        if decision["behavior"] == "ask":
            print(f"  [perm] {decision['reason']}")
            # Serialize permission prompts when running concurrent tools.
            with _PERMS_ASK_LOCK:
                approved = perms.ask_user(block.name, tool_input)
            if not approved:
                return ("Error: the user explicitly denied permission for this "
                        "tool call. The tool did NOT run. You MUST tell the user "
                        "the action was not performed; do not claim success."), True
    # MCP tools route through MCPManager.
    if MCP.is_mcp_tool(block.name):
        try:
            output = MCP.call(block.name, tool_input)
        except Exception as e:
            return f"Error: MCP call failed: {e}", True
    else:
        handler = TOOL_HANDLERS.get(block.name)
        if not handler:
            return f"Error: unknown tool '{block.name}'", True
        try:
            tool_input["tool_use_id"] = block.id
            output = handler(**tool_input)
        except Exception as e:
            return f"Error: {e}", True
    # Treat handler-returned strings starting with "Error:" as errors so the
    # model sees consistent error semantics across the whole tool pipeline.
    is_error = isinstance(output, str) and output.lstrip().startswith("Error:")
    post = hooks.run("PostToolUse",
                     {"tool_name": block.name, "tool_input": tool_input,
                      "tool_output": output})
    extra = "\n".join(post.get("messages", []))
    if extra:
        output = f"{output}\n[hook-context]\n{extra}"
    return output, is_error
