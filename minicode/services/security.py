"""Filesystem path safety, bash command validation, and permission prompting."""
import json
import os
import re
from fnmatch import fnmatch
from pathlib import Path

from minicode.config import WORKDIR

# === SECTION: path_safety ====================================================
def safe_path(p: str) -> Path:
    """Reject paths that escape WORKDIR via .. or absolute paths outside it."""
    raw = Path(p)
    candidate = raw if raw.is_absolute() else (WORKDIR / raw)
    resolved = candidate.resolve()
    if not resolved.is_relative_to(WORKDIR):
        raise ValueError(f"Path escapes workspace: {p}")
    return resolved


# === SECTION: bash_security ============================================
class BashSecurityValidator:
    """Pre-permission scan for obviously dangerous bash patterns."""

    VALIDATORS = [
        ("sudo",          r"\bsudo\b"),
        # rm + any flag tokens (-r, --, --recursive) + / bounded by
        # whitespace / end / shell separator / glob (`*` covers /*).
        ("rm_rf_root",    r"\brm\s+(?:--?[a-zA-Z]*\s+)*/(?=\s|$|[;&|*])"),
        ("rm_rf",         r"\brm\s+-[a-zA-Z]*r"),
        ("fork_bomb",     r":\(\)\s*\{"),
        ("dd_disk",       r"\bdd\b.*of=/dev/"),
        ("shell_pipe_to_root", r">\s*/dev/sd"),
    ]

    SEVERE = {"sudo", "rm_rf_root", "fork_bomb", "dd_disk", "shell_pipe_to_root"}

    def validate(self, command: str) -> list:
        out = []
        for name, pattern in self.VALIDATORS:
            if re.search(pattern, command):
                out.append((name, pattern))
        return out

    def describe(self, command: str) -> str:
        f = self.validate(command)
        if not f:
            return "No issues"
        return "Bash flags: " + ", ".join(f"{n}({p})" for n, p in f)


bash_validator = BashSecurityValidator()


# === SECTION: permissions ==============================================
PERM_MODES = ("default", "plan", "auto", "yolo")
READ_ONLY_TOOLS = {"read_file", "task_list", "task_get", "list_teammates",
                   "list_skills", "list_memory", "list_mcp_tools",
                   "list_worktrees", "schedule_list", "read_inbox"}
WRITE_TOOLS = {"write_file", "edit_file", "bash"}


class PermissionManager:
    """Pipeline: bash-validator -> deny rules -> mode -> allow rules -> ask user.

    Modes:
      default - ask for writes, allow reads
      plan    - block all writes, allow reads only (used for /plan)
      auto    - auto-allow reads, ask for writes
      yolo    - auto-allow everything except severe bash patterns

    Rules format: {"tool": "<name|*>", "path": "<glob|*>",
                   "content": "<glob|*>", "behavior": "allow|deny"}
    First match wins inside each behavior bucket.
    """

    DEFAULT_RULES = [
        {"tool": "bash", "content": "rm -rf /*", "behavior": "deny"},
        {"tool": "bash", "content": "*sudo*",     "behavior": "deny"},
        {"tool": "read_file", "path": "*", "behavior": "allow"},
        {"tool": "write_file", "path": ".minicode/*", "behavior": "allow"},
        {"tool": "TodoWrite", "path": "*", "behavior": "allow"},
        # Internal management tools never need a prompt.
        {"tool": "task_create", "path": "*", "behavior": "allow"},
        {"tool": "task_update", "path": "*", "behavior": "allow"},
        {"tool": "task_get",    "path": "*", "behavior": "allow"},
        {"tool": "task_list",   "path": "*", "behavior": "allow"},
        {"tool": "load_skill",  "path": "*", "behavior": "allow"},
        {"tool": "list_skills", "path": "*", "behavior": "allow"},
        {"tool": "save_memory", "path": "*", "behavior": "allow"},
        {"tool": "list_memory", "path": "*", "behavior": "allow"},
        {"tool": "compress",    "path": "*", "behavior": "allow"},
    ]

    def __init__(self, mode: str = "default", rules: list = None):
        if mode not in PERM_MODES:
            raise ValueError(f"Unknown perm mode: {mode}")
        self.mode = mode
        self.rules = rules or list(self.DEFAULT_RULES)

    def set_mode(self, mode: str):
        if mode not in PERM_MODES:
            raise ValueError(f"Unknown perm mode: {mode}")
        self.mode = mode

    def check(self, tool_name: str, tool_input: dict) -> dict:
        # Step 0: bash validator runs before everything else.
        if tool_name == "bash":
            command = tool_input.get("command", "")
            failures = bash_validator.validate(command)
            severe_hits = [f for f in failures if f[0] in bash_validator.SEVERE]
            if severe_hits:
                return {"behavior": "deny",
                        "reason": f"Bash validator: {bash_validator.describe(command)}"}
            if failures and self.mode != "yolo":
                return {"behavior": "ask",
                        "reason": f"Bash validator soft-flag: {bash_validator.describe(command)}"}

        # Step 1: deny rules (bypass-immune).
        for rule in self.rules:
            if rule["behavior"] == "deny" and self._matches(rule, tool_name, tool_input):
                return {"behavior": "deny", "reason": f"Blocked by deny rule: {rule}"}

        # Step 2: mode handling.
        if self.mode == "yolo":
            return {"behavior": "allow", "reason": "yolo mode"}
        if self.mode == "plan":
            if tool_name in WRITE_TOOLS:
                return {"behavior": "deny",
                        "reason": "plan mode: writes blocked. Use /mode default to leave plan mode."}
            return {"behavior": "allow", "reason": "plan mode: read-only allowed"}
        if self.mode == "auto":
            if tool_name in READ_ONLY_TOOLS or tool_name == "read_file":
                return {"behavior": "allow", "reason": "auto mode: read auto-allow"}

        # Step 3: allow rules.
        for rule in self.rules:
            if rule["behavior"] == "allow" and self._matches(rule, tool_name, tool_input):
                return {"behavior": "allow", "reason": f"Matched allow rule: {rule}"}

        # Step 4: ask user.
        return {"behavior": "ask", "reason": f"No rule matched for {tool_name}, asking user"}

    def ask_user(self, tool_name: str, tool_input: dict) -> bool:
        preview = json.dumps(tool_input, ensure_ascii=False)[:200]
        print(f"\n  [Permission] {tool_name}: {preview}")
        try:
            answer = input("  Allow? (y/n/always): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if answer == "always":
            self.rules.append({"tool": tool_name, "path": "*", "behavior": "allow"})
            return True
        return answer in ("y", "yes")

    def _matches(self, rule: dict, tool_name: str, tool_input: dict) -> bool:
        if rule.get("tool") and rule["tool"] != "*" and rule["tool"] != tool_name:
            return False
        if "path" in rule and rule["path"] != "*":
            if not fnmatch(tool_input.get("path", ""), rule["path"]):
                return False
        if "content" in rule and rule["content"] != "*":
            if not fnmatch(tool_input.get("command", ""), rule["content"]):
                return False
        return True


PERMS = PermissionManager(mode=os.getenv("MINICODE_PERM_MODE", "default"))
