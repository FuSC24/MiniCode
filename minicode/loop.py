"""Main agent message loop."""

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from minicode.config import client, MODEL, TOKEN_THRESHOLD
from minicode.services.security import PERMS
from minicode.services.hooks import HOOKS
from minicode.todos import TODO
from minicode.tasks import BG
from minicode.scheduling import CRON
from minicode.team import BUS
from minicode.compression import auto_compact, microcompact, estimate_tokens, append_user_text
from minicode.dispatch import (
    all_tools, system_blocks_cached, tools_cached, CACHE_ENABLED,
    execute_one_tool, PARALLEL_SAFE_TOOLS, PARALLEL_MAX_WORKERS,
)
from minicode.prompts import build_system_prompt

_BATCH = None  # Set by minicode.cli.run_prompt(); agent_loop reads it to record usage.


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
