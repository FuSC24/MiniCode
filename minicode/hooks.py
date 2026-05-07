"""User-configured shell hooks (PreToolUse, PostToolUse, SessionStart, SessionEnd)."""

import json
import os
import subprocess
from pathlib import Path

from minicode.config import HOOKS_FILE, WORKDIR, TRUST_MARKER

# === SECTION: hooks ====================================================
HOOK_EVENTS = ("PreToolUse", "PostToolUse", "SessionStart", "SessionEnd")
HOOK_TIMEOUT = 30


class HookManager:
    """Load .hooks.json and run external commands at extension points.

    Exit-code contract:
      0 -> continue (stdout printed; structured JSON stdout supported)
      1 -> block tool (PreToolUse only)
      2 -> inject stderr as additional context

    Structured stdout fields (optional):
      updatedInput        -- replace tool_input
      additionalContext   -- inject string into context
      permissionDecision  -- override permission ("allow"/"deny")
    """

    def __init__(self, config_path: Path = None, sdk_mode: bool = False):
        self.hooks = {e: [] for e in HOOK_EVENTS}
        self._sdk_mode = sdk_mode
        path = config_path or HOOKS_FILE
        if path.exists():
            try:
                cfg = json.loads(path.read_text())
                for event in HOOK_EVENTS:
                    self.hooks[event] = cfg.get("hooks", {}).get(event, [])
                print(f"[hooks] loaded from {path.relative_to(WORKDIR)}")
            except Exception as e:
                print(f"[hooks] config error: {e}")

    def _trusted(self) -> bool:
        return self._sdk_mode or TRUST_MARKER.exists()

    def run(self, event: str, context: dict = None) -> dict:
        result = {"blocked": False, "messages": [], "permission_override": None}
        if not self._trusted():
            return result
        for h in self.hooks.get(event, []):
            matcher = h.get("matcher")
            if matcher and context:
                if matcher != "*" and matcher != context.get("tool_name", ""):
                    continue
            command = h.get("command", "")
            if not command:
                continue
            env = dict(os.environ)
            env["HOOK_EVENT"] = event
            if context:
                env["HOOK_TOOL_NAME"] = context.get("tool_name", "")
                env["HOOK_TOOL_INPUT"] = json.dumps(
                    context.get("tool_input", {}), ensure_ascii=False)[:10000]
                if "tool_output" in context:
                    env["HOOK_TOOL_OUTPUT"] = str(context["tool_output"])[:10000]
            try:
                r = subprocess.run(command, shell=True, cwd=WORKDIR, env=env,
                                   capture_output=True, text=True, timeout=HOOK_TIMEOUT)
                if r.returncode == 0:
                    if r.stdout.strip():
                        try:
                            data = json.loads(r.stdout)
                            if "updatedInput" in data and context:
                                context["tool_input"] = data["updatedInput"]
                            if "additionalContext" in data:
                                result["messages"].append(data["additionalContext"])
                            if "permissionDecision" in data:
                                result["permission_override"] = data["permissionDecision"]
                        except (json.JSONDecodeError, TypeError):
                            print(f"  [hook:{event}] {r.stdout.strip()[:120]}")
                elif r.returncode == 1:
                    result["blocked"] = True
                    result["block_reason"] = r.stderr.strip() or "Blocked by hook"
                    print(f"  [hook:{event}] BLOCKED: {result['block_reason'][:200]}")
                elif r.returncode == 2:
                    msg = r.stderr.strip()
                    if msg:
                        result["messages"].append(msg)
                        print(f"  [hook:{event}] INJECT: {msg[:200]}")
            except subprocess.TimeoutExpired:
                print(f"  [hook:{event}] timeout ({HOOK_TIMEOUT}s)")
            except Exception as e:
                print(f"  [hook:{event}] error: {e}")
        return result


HOOKS = HookManager()
