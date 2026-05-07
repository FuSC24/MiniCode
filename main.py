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
from pathlib import Path

# === SECTION: bootstrap ===
from minicode.config import (
    WORKDIR, client, MODEL,
    STATE_DIR, TRANSCRIPT_DIR,
    TRUST_MARKER,
    PERSIST_TRIGGER_DEFAULT,
    PERSIST_PREVIEW_CHARS,
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
from minicode.memory import MemoryManager, MEMORY


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
from minicode.compression import auto_compact


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
from minicode.prompts import HELP_TEXT


# === SECTION: tool_dispatch ============================================
# === SECTION: prompt_caching =================================================
# === SECTION: parallel_dispatch ==============================================
from minicode.dispatch import (
    TOOL_HANDLERS, TOOLS_BASE,
)


# === SECTION: agent_loop =========================================
from minicode.loop import agent_loop


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
# _BATCH lives in minicode.loop (agent_loop reads it). Initialized by run_prompt().


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
    import minicode.loop
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

    minicode.loop._BATCH = {
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
        if minicode.loop._BATCH["stop_reason"] is None:
            minicode.loop._BATCH["stop_reason"] = "end_turn"
    except KeyboardInterrupt:
        minicode.loop._BATCH["stop_reason"] = "interrupted"
        exit_code = 130
    except Exception as e:
        print(f"[batch] agent_loop raised: {e}", file=sys.stderr)
        minicode.loop._BATCH["stop_reason"] = "exception"
        exit_code = 1
    finally:
        minicode.loop._BATCH["wall_clock_seconds"] = round(time.time() - minicode.loop._BATCH["started_at"], 2)
        if usage_out:
            Path(usage_out).parent.mkdir(parents=True, exist_ok=True)
            Path(usage_out).write_text(json.dumps({
                k: v for k, v in minicode.loop._BATCH.items() if k != "started_at"
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
