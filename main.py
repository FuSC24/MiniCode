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
# === SECTION: prompt_caching =================================================
# === SECTION: parallel_dispatch ==============================================
from minicode.dispatch import (
    TOOL_HANDLERS, TOOLS_BASE, all_tools,
    system_blocks_cached, tools_cached, CACHE_ENABLED,
    PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS, _PERMS_ASK_LOCK,
    execute_one_tool,
)
from minicode.compression import append_user_text


# === SECTION: agent_loop =========================================
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
