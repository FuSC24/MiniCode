#!/usr/bin/env python3
# MiniCode - a complete, runnable coding-agent harness in one file.


import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# === SECTION: bootstrap ===
from minicode.config import (
    WORKDIR, client, MODEL,
    STATE_DIR, TRANSCRIPT_DIR,
    TRUST_MARKER,
    TOKEN_THRESHOLD, PERSIST_TRIGGER_DEFAULT,
    PERSIST_PREVIEW_CHARS, VALID_MSG_TYPES,
)


# === SECTION: persisted_output =========================================
from minicode.persisted_output import (
    _persist_tool_result, _format_size, _preview_slice,
    _build_persisted_marker, maybe_persist_output,
)


# === SECTION: path_safety ====================================================
# === SECTION: bash_security ============================================
# === SECTION: permissions ==============================================
from minicode.security import (
    safe_path,
    BashSecurityValidator,
    PermissionManager, PERM_MODES, PERMS,
)


# === SECTION: hooks ====================================================
from minicode.hooks import HookManager, HOOKS


# === SECTION: memory ===================================================
from minicode.memory import MemoryManager, MEMORY, MEMORY_TYPES


# === SECTION: base_tools ===============================================
from minicode.tools import (
    run_bash, run_read, run_write, run_edit, run_grep, run_glob,
)


# === SECTION: skills ===================================================
from minicode.skills import SkillLoader, SKILLS


# === SECTION: todos ====================================================
from minicode.todos import TodoManager, TODO


# === SECTION: subagent =================================================
from minicode.subagent import run_subagent

# === SECTION: compression ==============================================
from minicode.compression import estimate_tokens, microcompact, auto_compact


# === SECTION: tasks ====================================================
# === SECTION: background ===============================================
from minicode.tasks import TaskManager, BackgroundManager, TASK_MGR, BG


# === SECTION: cron =====================================================
from minicode.scheduling import cron_matches, _cron_field, CronScheduler, CRON


# === SECTION: messaging ================================================
# === SECTION: team_protocol ============================================
# === SECTION: teammates ============================================
# === SECTION: shutdown / plan_approval =================================
from minicode.team import (
    MessageBus, BUS,
    TeammateManager, TEAM,
    handle_shutdown_request, handle_plan_review,
)
# === SECTION: worktree =================================================
from minicode.worktree import WorktreeManager, WORKTREES


# === SECTION: mcp ======================================================
from minicode.mcp import MCPClient, MCPManager, MCP


# === SECTION: instances ======================================================


# === SECTION: system_prompt ============================================
from minicode.prompts import build_system_prompt, HELP_TEXT


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


def append_user_text(messages: list, text: str) -> None:
    """Append `text` to the trailing user message (or start a new one).

    Anthropic rejects two consecutive {"role":"user"} entries, so multiple
    snippets drained in one iteration must be folded into one message.
    """
    if not text:
        return
    if messages and messages[-1].get("role") == "user":
        prev = messages[-1]["content"]
        if isinstance(prev, str):
            messages[-1]["content"] = prev + "\n" + text
            return
        if isinstance(prev, list):
            prev.append({"type": "text", "text": text})
            return
    messages.append({"role": "user", "content": text})


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


# === SECTION: agent_loop =========================================
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


def agent_loop(messages: list):
    """Main loop. Returns when the model stops without requesting tools."""
    rounds_without_todo = 0
    consecutive_errors = 0
    while True:
        # compression pipeline.
        microcompact(messages)
        if estimate_tokens(messages) > TOKEN_THRESHOLD:
            print("[auto-compact triggered]")
            messages[:] = auto_compact(messages)

        # Collect all auto-injected context (BG / cron / inbox) into a
        # single user message so we never produce consecutive {"role":"user"}.
        injected = []
        notifs = BG.drain()
        if notifs:
            txt = "\n".join(f"[bg:{n['task_id']}] {n['status']}: {n['result']}"
                            for n in notifs)
            injected.append(f"<background-results>\n{txt}\n</background-results>")
        for c in CRON.drain():
            injected.append(
                f"<scheduled-trigger id='{c['task_id']}' cron='{c['cron']}' "
                f"at='{c['fired_at']}'>\n{c['prompt']}\n</scheduled-trigger>")
        inbox = BUS.read_inbox("lead")
        if inbox:
            injected.append(f"<inbox>{json.dumps(inbox, indent=2)}</inbox>")
        if injected:
            append_user_text(messages, "\n".join(injected))

        # The actual model call -- streaming so text shows up as it arrives.
        # Cached system + tools cut TTFT on every turn after the first.
        try:
            try:
                stream_ctx = client.messages.stream(
                    model=MODEL, system=system_blocks_cached(),
                    messages=messages, tools=tools_cached(), max_tokens=8000,
                )
            except TypeError:
                # Some older SDKs / proxies reject `cache_control`; retry plain.
                stream_ctx = client.messages.stream(
                    model=MODEL, system=build_system_prompt(),
                    messages=messages, tools=all_tools(), max_tokens=8000,
                )
            with stream_ctx as stream:
                for text_delta in stream.text_stream:
                    if text_delta:
                        sys.stdout.write(text_delta)
                        sys.stdout.flush()
                response = stream.get_final_message()
            # Make sure the buffered streaming line ends with a newline so the
            # next log entry doesn't append to the same visual line.
            sys.stdout.write("\n")
            sys.stdout.flush()
            consecutive_errors = 0
            if _BATCH is not None:
                u = getattr(response, "usage", None)
                if u is not None:
                    _BATCH["input_tokens"] += getattr(u, "input_tokens", 0) or 0
                    _BATCH["output_tokens"] += getattr(u, "output_tokens", 0) or 0
                    _BATCH["cache_creation_input_tokens"] += (
                        getattr(u, "cache_creation_input_tokens", 0) or 0)
                    _BATCH["cache_read_input_tokens"] += (
                        getattr(u, "cache_read_input_tokens", 0) or 0)
                _BATCH["turns"] += 1
        except Exception as e:
            # If the proxy rejects cache_control with a 4xx, fall back once.
            if CACHE_ENABLED and "cache_control" in str(e).lower():
                print("[cache] proxy rejected cache_control; falling back")
                globals()["CACHE_ENABLED"] = False
                continue
            consecutive_errors += 1
            print(f"[model error] {e}")
            if consecutive_errors >= 3:
                print("[error recovery] 3 consecutive model errors -- aborting turn")
                return
            time.sleep(min(2 ** consecutive_errors, 30))
            continue

        messages.append({"role": "assistant", "content": response.content})
        # Warn when output was cut off so the user knows the reply is partial.
        if response.stop_reason == "max_tokens":
            print("[warning] response truncated (hit max_tokens); "
                  "use /compact or ask the model to continue")
        if response.stop_reason != "tool_use":
            return

        # --max-turns hard cap (batch mode only).
        if _BATCH is not None and _BATCH.get("max_turns"):
            if _BATCH["turns"] >= _BATCH["max_turns"]:
                _BATCH["stop_reason"] = "max_turns"
                print(f"[batch] hit --max-turns ({_BATCH['max_turns']}); stopping")
                return

        # Collect all tool_use blocks, classify, then dispatch.
        tool_blocks = [b for b in response.content if b.type == "tool_use"]
        results = []
        used_todo = False
        manual_compress = False
        compact_focus = None
        # Note compress + TodoWrite flags from the BLOCK list before dispatch
        # so we set them even if execution reorders.
        for b in tool_blocks:
            if b.name == "compress":
                manual_compress = True
                compact_focus = (b.input or {}).get("focus")
            if b.name == "TodoWrite":
                used_todo = True

        outputs = [None] * len(tool_blocks)  # (content, is_error) per index
        parallel_idx = [i for i, b in enumerate(tool_blocks)
                        if b.name in PARALLEL_SAFE_TOOLS]
        serial_idx = [i for i, b in enumerate(tool_blocks)
                      if b.name not in PARALLEL_SAFE_TOOLS]

        # Run side-effect-free tools concurrently. Permission prompts are
        # serialized internally via _PERMS_ASK_LOCK.
        if len(parallel_idx) > 1:
            with ThreadPoolExecutor(
                max_workers=min(PARALLEL_MAX_WORKERS, len(parallel_idx)),
                thread_name_prefix="minicode-tool",
            ) as pool:
                future_to_idx = {
                    pool.submit(execute_one_tool, tool_blocks[i],
                                HOOKS, PERMS): i
                    for i in parallel_idx
                }
                for fut in as_completed(future_to_idx):
                    i = future_to_idx[fut]
                    try:
                        outputs[i] = fut.result()
                    except Exception as e:
                        outputs[i] = (f"Error: {e}", True)
        elif parallel_idx:
            i = parallel_idx[0]
            outputs[i] = execute_one_tool(tool_blocks[i], HOOKS, PERMS)

        # Mutating / side-effectful tools: serial in declaration order.
        for i in serial_idx:
            outputs[i] = execute_one_tool(tool_blocks[i], HOOKS, PERMS)

        # Build tool_result list in original block order so the API sees
        # the same shape it expected.
        for block, (output, is_error) in zip(tool_blocks, outputs):
            tag = "!" if is_error else ">"
            print(f"{tag} {block.name}: {str(output)[:200]}")
            tr = {"type": "tool_result", "tool_use_id": block.id,
                  "content": str(output)}
            if is_error:
                tr["is_error"] = True
            results.append(tr)

        # nag the model if it has open todos but stops touching them.
        rounds_without_todo = 0 if used_todo else rounds_without_todo + 1
        if TODO.has_open_items() and rounds_without_todo >= 3:
            results.insert(0, {"type": "text",
                               "text": "<reminder>You have open todos. Update them.</reminder>"})

        messages.append({"role": "user", "content": results})

        if manual_compress:
            print("[manual compact]")
            messages[:] = auto_compact(messages, focus=compact_focus)


# === SECTION: repl ===========================================================


def repl():
    print(f"MiniCode @ {WORKDIR} (model: {MODEL}, perm-mode: {PERMS.mode})")
    print("Type /help for commands. Ctrl-D to exit.")

    # SessionStart hook + initial loads.
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY.load_all()
    CRON.start()
    MCP.start()
    HOOKS.run("SessionStart")

    history = []
    try:
        while True:
            try:
                query = input("\033[36mminicode >> \033[0m")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            q = query.strip()
            if not q:
                continue
            if q.lower() in ("q", "/quit", "/exit", "exit"):
                break
            if q in ("/help", "?"):
                print(HELP_TEXT)
                continue
            if q == "/tasks":
                print(TASK_MGR.list_all())
                continue
            if q == "/team":
                print(TEAM.list_all())
                continue
            if q == "/inbox":
                print(json.dumps(BUS.read_inbox("lead"), indent=2))
                continue
            if q == "/memory":
                print(MEMORY.list_all())
                continue
            if q == "/skills":
                SKILLS.reload()
                print(SKILLS.list_all())
                continue
            if q == "/cron":
                print(CRON.list_tasks())
                continue
            if q == "/worktree":
                print(WORKTREES.list_all())
                continue
            if q == "/mcp":
                print(MCP.list_tools())
                continue
            if q == "/trust":
                TRUST_MARKER.parent.mkdir(parents=True, exist_ok=True)
                TRUST_MARKER.write_text("trusted")
                print(f"Created trust marker at {TRUST_MARKER.relative_to(WORKDIR)}")
                continue
            if q.startswith("/mode"):
                parts = q.split(maxsplit=1)
                if len(parts) == 1:
                    print(f"Current perm mode: {PERMS.mode} (modes: {PERM_MODES})")
                else:
                    try:
                        PERMS.set_mode(parts[1].strip())
                        print(f"Perm mode -> {PERMS.mode}")
                    except ValueError as e:
                        print(f"Error: {e}")
                continue
            if q.startswith("/compact"):
                parts = q.split(maxsplit=1)
                focus = parts[1] if len(parts) > 1 else None
                if history:
                    print(f"[manual compact{f' focus={focus}' if focus else ''}]")
                    history[:] = auto_compact(history, focus=focus)
                continue

            history.append({"role": "user", "content": q})
            try:
                agent_loop(history)
            except KeyboardInterrupt:
                print("\n[interrupted; entering REPL]")
            print()
    finally:
        HOOKS.run("SessionEnd")
        CRON.stop()
        MCP.stop()


# === SECTION: batch entry ====================================================
_BATCH = None  # Set by run_prompt(); agent_loop checks this to record usage.


def _arg(name: str, default=None):
    """Tiny CLI helper: read --name VALUE or --name=VALUE from sys.argv."""
    for i, a in enumerate(sys.argv):
        if a == name and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def run_prompt():
    """Non-interactive entry: read a prompt, run agent_loop once, exit.

    Flags (read from sys.argv):
      --prompt <text> | --prompt-file <path>   prompt source (one required)
      --max-turns <N>                          hard turn cap (default: no cap)
      --usage-out <path>                       write per-run token usage JSON
    """
    global _BATCH
    prompt = _arg("--prompt")
    prompt_file = _arg("--prompt-file")
    if prompt is None and prompt_file is None:
        print("error: --prompt or --prompt-file required", file=sys.stderr)
        sys.exit(2)
    if prompt_file is not None:
        prompt = Path(prompt_file).read_text()

    max_turns = _arg("--max-turns")
    max_turns = int(max_turns) if max_turns else None
    usage_out = _arg("--usage-out")

    _BATCH = {
        "turns": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "max_turns": max_turns,
        "stop_reason": None,
        "started_at": time.time(),
    }

    print(f"MiniCode batch @ {WORKDIR} (model: {MODEL}, perm-mode: {PERMS.mode})")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    MEMORY.load_all()
    CRON.start()
    MCP.start()
    HOOKS.run("SessionStart")

    history = [{"role": "user", "content": prompt}]
    exit_code = 0
    try:
        agent_loop(history)
        if _BATCH["stop_reason"] is None:
            _BATCH["stop_reason"] = "end_turn"
    except KeyboardInterrupt:
        _BATCH["stop_reason"] = "interrupted"
        exit_code = 130
    except Exception as e:
        print(f"[batch] agent_loop raised: {e}", file=sys.stderr)
        _BATCH["stop_reason"] = "exception"
        exit_code = 1
    finally:
        _BATCH["wall_clock_seconds"] = round(time.time() - _BATCH["started_at"], 2)
        if usage_out:
            Path(usage_out).parent.mkdir(parents=True, exist_ok=True)
            Path(usage_out).write_text(json.dumps({
                k: v for k, v in _BATCH.items() if k != "started_at"
            }, indent=2))
        HOOKS.run("SessionEnd")
        CRON.stop()
        MCP.stop()
    sys.exit(exit_code)


# === SECTION: main ===========================================================
if __name__ == "__main__":
    if "--help" in sys.argv:
        print(HELP_TEXT)
        sys.exit(0)
    if "--version" in sys.argv:
        print("minicode 0.1")
        sys.exit(0)
    if "--prompt" in sys.argv or any(a.startswith("--prompt=") for a in sys.argv) \
       or "--prompt-file" in sys.argv or any(a.startswith("--prompt-file=") for a in sys.argv):
        run_prompt()
    repl()
