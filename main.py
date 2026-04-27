#!/usr/bin/env python3
# MiniCode - a complete, runnable coding-agent harness in one file.
#
# REPL slash commands: /help /tasks /team /inbox /memory /cron /worktree
#                       /mcp /skills /mode /compact /quit
#
# Run:
#   pip install anthropic python-dotenv
#   echo "MODEL_ID=claude-opus-4-7" > .env
#   echo "ANTHROPIC_API_KEY=sk-..." >> .env
#   python main.py

import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from queue import Queue, Empty

from anthropic import Anthropic
from dotenv import load_dotenv

# === SECTION: bootstrap ===
load_dotenv(override=True)
if os.getenv("ANTHROPIC_BASE_URL"):
    # Some proxies require dropping the auth-token env when base_url is set.
    os.environ.pop("ANTHROPIC_AUTH_TOKEN", None)

WORKDIR = Path.cwd()
client = Anthropic(base_url=os.getenv("ANTHROPIC_BASE_URL"))
MODEL = os.environ.get("MODEL_ID", "claude-opus-4-5")

# Filesystem layout. Every directory is created lazily.
STATE_DIR = WORKDIR / ".minicode"
TASKS_DIR = STATE_DIR / "tasks"
TEAM_DIR = STATE_DIR / "team"
INBOX_DIR = TEAM_DIR / "inbox"
TASK_OUTPUT_DIR = STATE_DIR / "task_outputs"
TOOL_RESULTS_DIR = TASK_OUTPUT_DIR / "tool-results"
TRANSCRIPT_DIR = STATE_DIR / "transcripts"
CRON_DIR = STATE_DIR / "cron"
WORKTREE_DIR = STATE_DIR / "worktrees"
MCP_DIR = STATE_DIR / "mcp"
MEMORY_DIR = WORKDIR / ".memory"
SKILLS_DIR = WORKDIR / "skills"
HOOKS_FILE = WORKDIR / ".hooks.json"
TRUST_MARKER = WORKDIR / ".minicode" / ".trusted"

TOKEN_THRESHOLD = 100000
PERSIST_TRIGGER_DEFAULT = 50000
PERSIST_TRIGGER_BASH = 30000
PERSIST_PREVIEW_CHARS = 2000
CONTEXT_TRUNCATE_CHARS = 50000
KEEP_RECENT_RESULTS = 3
PRESERVE_RESULT_TOOLS = {"read_file"}
POLL_INTERVAL = 5
IDLE_TIMEOUT = 60
TEAM_MAX_CONSECUTIVE_TURNS = 50

VALID_MSG_TYPES = {
    "message", "broadcast",
    "shutdown_request", "shutdown_response",
    "plan_approval_request", "plan_approval_response",
}


# === SECTION: persisted_output (s06) =========================================
# Large tool outputs are written to disk and replaced in the conversation
# with a small marker that points to the file. This stops one big bash output
# from blowing the context window.
def _persist_tool_result(tool_use_id: str, content: str) -> Path:
    TOOL_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^a-zA-Z0-9_.-]", "_", tool_use_id or "unknown")
    path = TOOL_RESULTS_DIR / f"{safe_id}.txt"
    if not path.exists():
        path.write_text(content)
    return path.relative_to(WORKDIR)


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f}KB"
    return f"{size / (1024 * 1024):.1f}MB"


def _preview_slice(text: str, limit: int) -> tuple:
    if len(text) <= limit:
        return text, False
    idx = text[:limit].rfind("\n")
    cut = idx if idx > (limit * 0.5) else limit
    return text[:cut], True


def _build_persisted_marker(stored_path: Path, content: str) -> str:
    preview, has_more = _preview_slice(content, PERSIST_PREVIEW_CHARS)
    marker = (
        f"<persisted-output>\n"
        f"Output too large ({_format_size(len(content))}). "
        f"Full output saved to: {stored_path}\n\n"
        f"Preview (first {_format_size(PERSIST_PREVIEW_CHARS)}):\n"
        f"{preview}"
    )
    if has_more:
        marker += "\n..."
    marker += "\n</persisted-output>"
    return marker


def maybe_persist_output(tool_use_id: str, output: str, trigger_chars: int = None) -> str:
    if not isinstance(output, str):
        return str(output)
    trigger = PERSIST_TRIGGER_DEFAULT if trigger_chars is None else int(trigger_chars)
    if len(output) <= trigger:
        return output
    stored_path = _persist_tool_result(tool_use_id, output)
    return _build_persisted_marker(stored_path, output)


# === SECTION: path_safety ====================================================
def safe_path(p: str) -> Path:
    """Reject paths that escape WORKDIR via .. or absolute paths outside it."""
    raw = Path(p)
    candidate = raw if raw.is_absolute() else (WORKDIR / raw)
    resolved = candidate.resolve()
    if not resolved.is_relative_to(WORKDIR):
        raise ValueError(f"Path escapes workspace: {p}")
    return resolved


# === SECTION: bash_security (s07) ============================================
class BashSecurityValidator:
    """Pre-permission scan for obviously dangerous bash patterns."""

    VALIDATORS = [
        ("sudo",          r"\bsudo\b"),
        ("rm_rf_root",    r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*\s+)?/\s*$"),
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


# === SECTION: permissions (s07) ==============================================
PERM_MODES = ("default", "plan", "auto", "yolo")
READ_ONLY_TOOLS = {"read_file", "task_list", "task_get", "list_teammates",
                   "list_skills", "list_memory", "list_mcp_tools",
                   "list_worktrees", "list_cron", "read_inbox"}
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
        self.consecutive_denials = 0

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
                self.consecutive_denials = 0
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
            self.consecutive_denials = 0
            return True
        if answer in ("y", "yes"):
            self.consecutive_denials = 0
            return True
        self.consecutive_denials += 1
        return False

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


# === SECTION: hooks (s08) ====================================================
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


# === SECTION: memory (s09) ===================================================
MEMORY_TYPES = ("user", "feedback", "project", "reference")
MEMORY_INDEX = MEMORY_DIR / "MEMORY.md"
MAX_INDEX_LINES = 200


class MemoryManager:
    """Persistent cross-session memory. One markdown file per memory."""

    def __init__(self, memory_dir: Path = None):
        self.memory_dir = memory_dir or MEMORY_DIR
        self.memories = {}

    def load_all(self):
        self.memories = {}
        if not self.memory_dir.exists():
            return
        for md in sorted(self.memory_dir.glob("*.md")):
            if md.name == "MEMORY.md":
                continue
            parsed = self._parse_frontmatter(md.read_text())
            if parsed:
                name = parsed.get("name", md.stem)
                self.memories[name] = {
                    "description": parsed.get("description", ""),
                    "type": parsed.get("type", "project"),
                    "content": parsed.get("content", ""),
                    "file": md.name,
                }
        if self.memories:
            print(f"[memory] loaded {len(self.memories)} memories")

    def render_for_prompt(self) -> str:
        if not self.memories:
            return ""
        lines = ["# Memories (persistent across sessions)", ""]
        for mt in MEMORY_TYPES:
            typed = {k: v for k, v in self.memories.items() if v["type"] == mt}
            if not typed:
                continue
            lines.append(f"## [{mt}]")
            for name, mem in typed.items():
                lines.append(f"### {name}: {mem['description']}")
                if mem["content"].strip():
                    lines.append(mem["content"].strip())
                lines.append("")
        return "\n".join(lines)

    def save(self, name: str, description: str, mem_type: str, content: str) -> str:
        if mem_type not in MEMORY_TYPES:
            return f"Error: type must be one of {MEMORY_TYPES}"
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name.lower())
        if not safe:
            return "Error: invalid memory name"
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        body = (f"---\nname: {name}\ndescription: {description}\n"
                f"type: {mem_type}\n---\n{content}\n")
        path = self.memory_dir / f"{safe}.md"
        path.write_text(body)
        self.memories[name] = {"description": description, "type": mem_type,
                                "content": content, "file": path.name}
        self._rebuild_index()
        try:
            shown = path.relative_to(WORKDIR)
        except ValueError:
            shown = path
        return f"Saved memory '{name}' [{mem_type}] -> {shown}"

    def delete(self, name: str) -> str:
        mem = self.memories.pop(name, None)
        if not mem:
            return f"No memory named '{name}'"
        (self.memory_dir / mem["file"]).unlink(missing_ok=True)
        self._rebuild_index()
        return f"Deleted memory '{name}'"

    def list_all(self) -> str:
        if not self.memories:
            return "(no memories)"
        return "\n".join(f"- {n} [{m['type']}]: {m['description']}"
                         for n, m in self.memories.items())

    def _rebuild_index(self):
        lines = ["# Memory Index", ""]
        for n, m in self.memories.items():
            lines.append(f"- {n}: {m['description']} [{m['type']}]")
            if len(lines) >= MAX_INDEX_LINES:
                lines.append(f"... (truncated at {MAX_INDEX_LINES})")
                break
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        (self.memory_dir / "MEMORY.md").write_text("\n".join(lines) + "\n")

    def _parse_frontmatter(self, text: str) -> dict:
        m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", text, re.DOTALL)
        if not m:
            return None
        header, body = m.group(1), m.group(2)
        result = {"content": body.strip()}
        for line in header.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
        return result


# === SECTION: base_tools (s02) ===============================================
def run_bash(command: str, tool_use_id: str = "", timeout: int = 120) -> str:
    try:
        r = subprocess.run(command, shell=True, cwd=WORKDIR,
                           capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).strip()
        if not out:
            return f"(no output, exit={r.returncode})"
        out = maybe_persist_output(tool_use_id, out, trigger_chars=PERSIST_TRIGGER_BASH)
        return out[:CONTEXT_TRUNCATE_CHARS] if isinstance(out, str) else str(out)[:CONTEXT_TRUNCATE_CHARS]
    except subprocess.TimeoutExpired:
        return f"Error: bash timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"


def run_read(path: str, tool_use_id: str = "", limit: int = None, offset: int = None) -> str:
    try:
        lines = safe_path(path).read_text().splitlines()
        start = max(int(offset), 0) if offset else 0
        end = (start + int(limit)) if limit else len(lines)
        sliced = lines[start:end]
        if end < len(lines):
            sliced.append(f"... ({len(lines) - end} more)")
        out = "\n".join(f"{start + i + 1:6d}\t{ln}" for i, ln in enumerate(sliced))
        out = maybe_persist_output(tool_use_id, out)
        return out[:CONTEXT_TRUNCATE_CHARS] if isinstance(out, str) else str(out)[:CONTEXT_TRUNCATE_CHARS]
    except Exception as e:
        return f"Error: {e}"


def run_write(path: str, content: str) -> str:
    try:
        fp = safe_path(path)
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content)
        return f"Wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error: {e}"


def run_edit(path: str, old_text: str, new_text: str) -> str:
    try:
        fp = safe_path(path)
        c = fp.read_text()
        if old_text not in c:
            return f"Error: old_text not found in {path}"
        if c.count(old_text) > 1:
            return f"Error: old_text matches {c.count(old_text)} times in {path}; provide more context"
        fp.write_text(c.replace(old_text, new_text, 1))
        return f"Edited {path}"
    except Exception as e:
        return f"Error: {e}"


def run_grep(pattern: str, path: str = ".", glob: str = "*", tool_use_id: str = "") -> str:
    try:
        target = safe_path(path)
        cmd = ["grep", "-rEn", "--include", glob, pattern, str(target)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = (r.stdout or r.stderr).strip() or "(no matches)"
        out = maybe_persist_output(tool_use_id, out, trigger_chars=PERSIST_TRIGGER_BASH)
        return out[:CONTEXT_TRUNCATE_CHARS]
    except Exception as e:
        return f"Error: {e}"


def run_glob(pattern: str, tool_use_id: str = "") -> str:
    try:
        results = sorted(str(p.relative_to(WORKDIR)) for p in WORKDIR.glob(pattern)
                         if p.is_file())
        out = "\n".join(results) or "(no matches)"
        return maybe_persist_output(tool_use_id, out)[:CONTEXT_TRUNCATE_CHARS]
    except Exception as e:
        return f"Error: {e}"


# === SECTION: skills (s05) ===================================================
class SkillLoader:
    """Skills live as `skills/<name>/SKILL.md` with YAML frontmatter."""

    def __init__(self, skills_dir: Path):
        self.skills_dir = skills_dir
        self.skills = {}
        self.reload()

    def reload(self):
        self.skills = {}
        if not self.skills_dir.exists():
            return
        for f in sorted(self.skills_dir.rglob("SKILL.md")):
            text = f.read_text()
            m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.DOTALL)
            meta, body = {}, text
            if m:
                for line in m.group(1).strip().splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        meta[k.strip()] = v.strip()
                body = m.group(2).strip()
            name = meta.get("name", f.parent.name)
            try:
                shown = str(f.relative_to(WORKDIR))
            except ValueError:
                shown = str(f)
            self.skills[name] = {"meta": meta, "body": body, "path": shown}

    def descriptions(self) -> str:
        if not self.skills:
            return "(no skills)"
        return "\n".join(f"  - {n}: {s['meta'].get('description', '-')}"
                         for n, s in self.skills.items())

    def load(self, name: str) -> str:
        s = self.skills.get(name)
        if not s:
            return f"Error: unknown skill '{name}'. Available: {list(self.skills)}"
        return f'<skill name="{name}">\n{s["body"]}\n</skill>'

    def list_all(self) -> str:
        if not self.skills:
            return "(no skills)"
        return "\n".join(f"{n} -- {s['meta'].get('description', '-')} ({s['path']})"
                         for n, s in self.skills.items())


# === SECTION: todos (s03) ====================================================
class TodoManager:
    """In-memory checklist with the at-most-one-in-progress invariant."""

    def __init__(self):
        self.items = []

    def update(self, items: list) -> str:
        validated, ip = [], 0
        for i, item in enumerate(items):
            content = str(item.get("content", "")).strip()
            status = str(item.get("status", "pending")).lower()
            af = str(item.get("activeForm", "")).strip()
            if not content:
                raise ValueError(f"Item {i}: content required")
            if status not in ("pending", "in_progress", "completed"):
                raise ValueError(f"Item {i}: invalid status '{status}'")
            if not af:
                raise ValueError(f"Item {i}: activeForm required")
            if status == "in_progress":
                ip += 1
            validated.append({"content": content, "status": status, "activeForm": af})
        if len(validated) > 20:
            raise ValueError("Max 20 todos")
        if ip > 1:
            raise ValueError("Only one in_progress allowed")
        self.items = validated
        return self.render()

    def render(self) -> str:
        if not self.items:
            return "No todos."
        lines = []
        for it in self.items:
            mark = {"completed": "[x]", "in_progress": "[>]", "pending": "[ ]"}.get(it["status"], "[?]")
            suffix = f" <- {it['activeForm']}" if it["status"] == "in_progress" else ""
            lines.append(f"{mark} {it['content']}{suffix}")
        done = sum(1 for t in self.items if t["status"] == "completed")
        lines.append(f"\n({done}/{len(self.items)} completed)")
        return "\n".join(lines)

    def has_open_items(self) -> bool:
        return any(it["status"] != "completed" for it in self.items)


# === SECTION: subagent (s04) =================================================
def run_subagent(prompt: str, agent_type: str = "Explore", max_turns: int = 30) -> str:
    """Spawn a one-shot subagent. Default is read-only Explore."""
    sub_tools = [
        {"name": "bash", "description": "Run shell command (read-oriented).",
         "input_schema": {"type": "object",
                          "properties": {"command": {"type": "string"}},
                          "required": ["command"]}},
        {"name": "read_file", "description": "Read file contents.",
         "input_schema": {"type": "object",
                          "properties": {"path": {"type": "string"},
                                         "limit": {"type": "integer"}},
                          "required": ["path"]}},
        {"name": "grep", "description": "Recursive regex grep.",
         "input_schema": {"type": "object",
                          "properties": {"pattern": {"type": "string"},
                                         "path": {"type": "string"},
                                         "glob": {"type": "string"}},
                          "required": ["pattern"]}},
    ]
    if agent_type != "Explore":
        sub_tools += [
            {"name": "write_file", "description": "Write a file.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"},
                                             "content": {"type": "string"}},
                              "required": ["path", "content"]}},
            {"name": "edit_file", "description": "Edit an existing file by replacing exact text.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"},
                                             "old_text": {"type": "string"},
                                             "new_text": {"type": "string"}},
                              "required": ["path", "old_text", "new_text"]}},
        ]
    handlers = {
        "bash":       lambda **kw: run_bash(kw["command"], kw.get("tool_use_id", "")),
        "read_file":  lambda **kw: run_read(kw["path"], kw.get("tool_use_id", ""), kw.get("limit")),
        "grep":       lambda **kw: run_grep(kw["pattern"], kw.get("path", "."),
                                            kw.get("glob", "*"), kw.get("tool_use_id", "")),
        "write_file": lambda **kw: run_write(kw["path"], kw["content"]),
        "edit_file":  lambda **kw: run_edit(kw["path"], kw["old_text"], kw["new_text"]),
    }
    sys_prompt = (f"You are a subagent ({agent_type}). "
                  f"You operate in a fresh isolated context at {WORKDIR}. "
                  "Return a concise final report; the parent only sees your final text.")
    msgs = [{"role": "user", "content": prompt}]
    resp = None
    for _ in range(max_turns):
        try:
            resp = client.messages.create(model=MODEL, system=sys_prompt,
                                          messages=msgs, tools=sub_tools, max_tokens=8000)
        except Exception as e:
            return f"(subagent failed: {e})"
        msgs.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            break
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                h = handlers.get(b.name, lambda **kw: f"Unknown subtool: {b.name}")
                inp = dict(b.input or {})
                inp["tool_use_id"] = b.id
                try:
                    out = h(**inp)
                except Exception as e:
                    out = f"Error: {e}"
                results.append({"type": "tool_result", "tool_use_id": b.id,
                                "content": str(out)[:CONTEXT_TRUNCATE_CHARS]})
        msgs.append({"role": "user", "content": results})
    if resp:
        return "".join(b.text for b in resp.content if hasattr(b, "text")) or "(no summary)"
    return "(subagent produced no response)"


# === SECTION: compression (s06) ==============================================
def estimate_tokens(messages: list) -> int:
    """Cheap token approximation. Good enough to trigger compaction."""
    return len(json.dumps(messages, default=str)) // 4


def microcompact(messages: list):
    """Replace older tool_result payloads with placeholders, in place."""
    tool_results = []
    for msg in messages:
        if msg["role"] == "user" and isinstance(msg.get("content"), list):
            for part in msg["content"]:
                if isinstance(part, dict) and part.get("type") == "tool_result":
                    tool_results.append(part)
    if len(tool_results) <= KEEP_RECENT_RESULTS:
        return
    tool_name_map = {}
    for msg in messages:
        if msg["role"] == "assistant":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if hasattr(block, "type") and block.type == "tool_use":
                        tool_name_map[block.id] = block.name
    for part in tool_results[:-KEEP_RECENT_RESULTS]:
        if not isinstance(part.get("content"), str) or len(part["content"]) <= 100:
            continue
        tool_id = part.get("tool_use_id", "")
        tool_name = tool_name_map.get(tool_id, "unknown")
        if tool_name in PRESERVE_RESULT_TOOLS:
            continue
        part["content"] = f"[Previous: used {tool_name}]"


def auto_compact(messages: list, focus: str = None) -> list:
    """Persist a transcript, summarize, return a fresh seed conversation."""
    TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    path = TRANSCRIPT_DIR / f"transcript_{int(time.time())}.jsonl"
    with open(path, "w") as f:
        for msg in messages:
            f.write(json.dumps(msg, default=str) + "\n")
    conv = json.dumps(messages, default=str)[:80000]
    prompt = (
        "Summarize this conversation for continuity. Structure your summary:\n"
        "1) Task overview: core request, success criteria, constraints\n"
        "2) Current state: completed work, files touched, artifacts created\n"
        "3) Key decisions and discoveries: constraints, errors, failed approaches\n"
        "4) Next steps: remaining actions, blockers, priority order\n"
        "5) Context to preserve: user preferences, domain details, commitments\n"
        "Be concise but preserve critical details.\n"
    )
    if focus:
        prompt += f"\nPay special attention to: {focus}\n"
    try:
        resp = client.messages.create(model=MODEL, max_tokens=4000,
                                      messages=[{"role": "user", "content": prompt + "\n" + conv}])
        summary = resp.content[0].text
    except Exception as e:
        summary = f"(compact failed: {e}; raw transcript at {path.relative_to(WORKDIR)})"
    cont = (
        "This session is being continued from a previous conversation that ran out "
        "of context. The summary below covers the earlier portion of the conversation.\n\n"
        f"{summary}\n\n"
        "Please continue from where we left off without asking the user further questions."
    )
    return [{"role": "user", "content": cont}]


# === SECTION: tasks (s12) ====================================================
class TaskManager:
    """File-backed task board: each task is one JSON file under .minicode/tasks/."""

    def __init__(self):
        TASKS_DIR.mkdir(parents=True, exist_ok=True)

    def _next_id(self) -> int:
        ids = [int(f.stem.split("_")[1]) for f in TASKS_DIR.glob("task_*.json")]
        return max(ids, default=0) + 1

    def _path(self, tid: int) -> Path:
        return TASKS_DIR / f"task_{tid}.json"

    def _load(self, tid: int) -> dict:
        p = self._path(tid)
        if not p.exists():
            raise ValueError(f"Task {tid} not found")
        return json.loads(p.read_text())

    def _save(self, task: dict):
        self._path(task["id"]).write_text(json.dumps(task, indent=2))

    def create(self, subject: str, description: str = "",
               blocked_by: list = None, worktree: str = None) -> str:
        task = {
            "id": self._next_id(),
            "subject": subject,
            "description": description,
            "status": "pending",
            "owner": None,
            "worktree": worktree,
            "blockedBy": list(blocked_by or []),
            "blocks": [],
            "createdAt": time.time(),
        }
        self._save(task)
        return json.dumps(task, indent=2)

    def get(self, tid: int) -> str:
        return json.dumps(self._load(tid), indent=2)

    def update(self, tid: int, status: str = None,
               add_blocked_by: list = None, add_blocks: list = None,
               worktree: str = None) -> str:
        task = self._load(tid)
        if status:
            task["status"] = status
            if status == "completed":
                # Unblock any task that was blocked on this one.
                for f in TASKS_DIR.glob("task_*.json"):
                    t = json.loads(f.read_text())
                    if tid in t.get("blockedBy", []):
                        t["blockedBy"].remove(tid)
                        self._path(t["id"]).write_text(json.dumps(t, indent=2))
            if status == "deleted":
                self._path(tid).unlink(missing_ok=True)
                return f"Task {tid} deleted"
        if add_blocked_by:
            task["blockedBy"] = list(set(task.get("blockedBy", []) + add_blocked_by))
        if add_blocks:
            task["blocks"] = list(set(task.get("blocks", []) + add_blocks))
        if worktree is not None:
            task["worktree"] = worktree
        self._save(task)
        return json.dumps(task, indent=2)

    def list_all(self) -> str:
        tasks = [json.loads(f.read_text()) for f in sorted(TASKS_DIR.glob("task_*.json"))]
        if not tasks:
            return "No tasks."
        lines = []
        for t in tasks:
            mark = {"pending": "[ ]", "in_progress": "[>]", "completed": "[x]"}.get(t["status"], "[?]")
            owner = f" @{t['owner']}" if t.get("owner") else ""
            blocked = f" (blocked by: {t['blockedBy']})" if t.get("blockedBy") else ""
            wt = f" wt={t['worktree']}" if t.get("worktree") else ""
            lines.append(f"{mark} #{t['id']}: {t['subject']}{owner}{blocked}{wt}")
        return "\n".join(lines)

    def claim(self, tid: int, owner: str) -> str:
        task = self._load(tid)
        task["owner"] = owner
        task["status"] = "in_progress"
        self._save(task)
        return f"Claimed task #{tid} for {owner}"

    def unclaimed(self) -> list:
        out = []
        for f in sorted(TASKS_DIR.glob("task_*.json")):
            t = json.loads(f.read_text())
            if t.get("status") == "pending" and not t.get("owner") and not t.get("blockedBy"):
                out.append(t)
        return out


# === SECTION: background (s13) ===============================================
class BackgroundManager:
    """Run shell commands in daemon threads. Notifications drain into the loop."""

    def __init__(self):
        self.tasks = {}
        self.notifications = Queue()

    def run(self, command: str, timeout: int = 600) -> str:
        tid = str(uuid.uuid4())[:8]
        self.tasks[tid] = {"status": "running", "command": command, "result": None}
        threading.Thread(target=self._exec, args=(tid, command, timeout), daemon=True).start()
        return f"Background task {tid} started: {command[:80]}"

    def _exec(self, tid: str, command: str, timeout: int):
        try:
            r = subprocess.run(command, shell=True, cwd=WORKDIR,
                               capture_output=True, text=True, timeout=timeout)
            output = (r.stdout + r.stderr).strip()[:50000] or "(no output)"
            self.tasks[tid].update({"status": "completed", "result": output})
        except subprocess.TimeoutExpired:
            self.tasks[tid].update({"status": "timeout", "result": f"timed out after {timeout}s"})
        except Exception as e:
            self.tasks[tid].update({"status": "error", "result": str(e)})
        self.notifications.put({"task_id": tid,
                                "status": self.tasks[tid]["status"],
                                "result": str(self.tasks[tid]["result"])[:500]})

    def check(self, tid: str = None) -> str:
        if tid:
            t = self.tasks.get(tid)
            if not t:
                return f"Unknown bg task: {tid}"
            return f"[{t['status']}] {t.get('result', '(running)')}"
        if not self.tasks:
            return "No background tasks."
        return "\n".join(f"{k}: [{v['status']}] {v['command'][:60]}"
                         for k, v in self.tasks.items())

    def kill(self, tid: str) -> str:
        t = self.tasks.get(tid)
        if not t:
            return f"Unknown bg task: {tid}"
        t["status"] = "killed"
        return f"Marked {tid} as killed (already-detached subprocess will run to completion)"

    def drain(self) -> list:
        out = []
        while True:
            try:
                out.append(self.notifications.get_nowait())
            except Empty:
                break
        return out


# === SECTION: cron (s14) =====================================================
def cron_matches(expr: str, dt: datetime) -> bool:
    """Match a 5-field cron expression against a datetime."""
    fields = expr.strip().split()
    if len(fields) != 5:
        return False
    cron_dow = (dt.weekday() + 1) % 7  # cron: 0=Sun
    values = [dt.minute, dt.hour, dt.day, dt.month, cron_dow]
    ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]
    for field, val, (lo, hi) in zip(fields, values, ranges):
        if not _cron_field(field, val, lo, hi):
            return False
    return True


def _cron_field(field: str, value: int, lo: int, hi: int) -> bool:
    if field == "*":
        return True
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, sstr = part.split("/", 1)
            try:
                step = int(sstr)
            except ValueError:
                return False
        if part == "*":
            if (value - lo) % step == 0:
                return True
        elif "-" in part:
            try:
                a, b = (int(x) for x in part.split("-", 1))
            except ValueError:
                return False
            if a <= value <= b and (value - a) % step == 0:
                return True
        else:
            try:
                if int(part) == value:
                    return True
            except ValueError:
                return False
    return False


class CronScheduler:
    """Background scheduler. Fires prompts back into the agent loop."""

    DURABLE_FILE = CRON_DIR / "tasks.json"

    def __init__(self):
        self.tasks = []
        self.queue = Queue()
        self._stop = threading.Event()
        self._thread = None
        self._last_minute = -1

    def start(self):
        self._load_durable()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        if self.tasks:
            print(f"[cron] loaded {len(self.tasks)} scheduled tasks")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def create(self, cron_expr: str, prompt: str,
               recurring: bool = True, durable: bool = False) -> str:
        # Validate immediately so bad expressions fail loud.
        if len(cron_expr.strip().split()) != 5:
            return "Error: cron expression must have 5 fields (m h dom mon dow)"
        tid = str(uuid.uuid4())[:8]
        self.tasks.append({
            "id": tid, "cron": cron_expr, "prompt": prompt,
            "recurring": recurring, "durable": durable,
            "createdAt": time.time(),
        })
        if durable:
            self._save_durable()
        mode = "recurring" if recurring else "one-shot"
        store = "durable" if durable else "session"
        return f"Created cron {tid} ({mode}/{store}): {cron_expr} -> {prompt[:60]}"

    def delete(self, tid: str) -> str:
        before = len(self.tasks)
        self.tasks = [t for t in self.tasks if t["id"] != tid]
        if len(self.tasks) < before:
            self._save_durable()
            return f"Deleted cron {tid}"
        return f"Cron {tid} not found"

    def list_tasks(self) -> str:
        if not self.tasks:
            return "No scheduled tasks."
        lines = []
        for t in self.tasks:
            mode = "recurring" if t["recurring"] else "one-shot"
            store = "durable" if t["durable"] else "session"
            age_h = (time.time() - t["createdAt"]) / 3600
            lines.append(f"  {t['id']}  {t['cron']}  [{mode}/{store}] "
                         f"({age_h:.1f}h old): {t['prompt'][:60]}")
        return "\n".join(lines)

    def drain(self) -> list:
        out = []
        while True:
            try:
                out.append(self.queue.get_nowait())
            except Empty:
                break
        return out

    def _loop(self):
        while not self._stop.is_set():
            now = datetime.now()
            current = now.hour * 60 + now.minute
            if current != self._last_minute:
                self._last_minute = current
                self._fire_due(now)
            self._stop.wait(timeout=1)

    def _fire_due(self, now: datetime):
        fired_oneshot = []
        for t in self.tasks:
            if cron_matches(t["cron"], now):
                self.queue.put({
                    "task_id": t["id"], "cron": t["cron"], "prompt": t["prompt"],
                    "fired_at": now.isoformat(timespec="seconds"),
                })
                if not t["recurring"]:
                    fired_oneshot.append(t["id"])
        if fired_oneshot:
            self.tasks = [t for t in self.tasks if t["id"] not in fired_oneshot]
            self._save_durable()

    def _save_durable(self):
        CRON_DIR.mkdir(parents=True, exist_ok=True)
        durable_only = [t for t in self.tasks if t.get("durable")]
        self.DURABLE_FILE.write_text(json.dumps(durable_only, indent=2))

    def _load_durable(self):
        if not self.DURABLE_FILE.exists():
            return
        try:
            self.tasks = json.loads(self.DURABLE_FILE.read_text()) or []
        except Exception as e:
            print(f"[cron] could not load durable file: {e}")


# === SECTION: messaging (s15) ================================================
class MessageBus:
    """File-backed inbox per teammate. One JSONL file per recipient."""

    def __init__(self):
        INBOX_DIR.mkdir(parents=True, exist_ok=True)

    def send(self, sender: str, to: str, content: str,
             msg_type: str = "message", extra: dict = None) -> str:
        if msg_type not in VALID_MSG_TYPES:
            return f"Error: bad msg_type '{msg_type}'. Allowed: {sorted(VALID_MSG_TYPES)}"
        msg = {"type": msg_type, "from": sender, "to": to,
               "content": content, "timestamp": time.time()}
        if extra:
            msg.update(extra)
        with open(INBOX_DIR / f"{to}.jsonl", "a") as f:
            f.write(json.dumps(msg) + "\n")
        return f"Sent {msg_type} to {to}"

    def read_inbox(self, name: str) -> list:
        p = INBOX_DIR / f"{name}.jsonl"
        if not p.exists():
            return []
        msgs = [json.loads(l) for l in p.read_text().strip().splitlines() if l]
        p.write_text("")  # drain semantics
        return msgs

    def broadcast(self, sender: str, content: str, names: list) -> str:
        n = 0
        for name in names:
            if name != sender:
                self.send(sender, name, content, "broadcast")
                n += 1
        return f"Broadcast to {n} teammates"


# === SECTION: worktree (s18) =================================================
class WorktreeManager:
    """Git-worktree-based parallel execution lanes.

    A worktree is one isolated checkout. Tasks bind to a worktree by name
    via TaskManager.update(worktree=...). The registry is just a JSON index.
    """

    INDEX_FILE = WORKTREE_DIR / "index.json"

    def __init__(self):
        WORKTREE_DIR.mkdir(parents=True, exist_ok=True)
        self.index = self._load_index()

    def _load_index(self) -> dict:
        if not self.INDEX_FILE.exists():
            return {"worktrees": []}
        try:
            return json.loads(self.INDEX_FILE.read_text())
        except Exception:
            return {"worktrees": []}

    def _save_index(self):
        self.INDEX_FILE.write_text(json.dumps(self.index, indent=2))

    def _is_git_repo(self) -> bool:
        return (WORKDIR / ".git").exists() or (WORKDIR / ".git").is_file()

    def create(self, name: str, base: str = "HEAD") -> str:
        if not re.match(r"^[a-zA-Z0-9._-]+$", name):
            return "Error: worktree name must be [a-zA-Z0-9._-]"
        if any(w["name"] == name for w in self.index["worktrees"]):
            return f"Worktree '{name}' already exists"
        path = WORKTREE_DIR / name
        if not self._is_git_repo():
            # No git: fall back to a copy-based lane (just mkdir).
            path.mkdir(parents=True, exist_ok=True)
            self.index["worktrees"].append({
                "name": name, "path": str(path.relative_to(WORKDIR)),
                "branch": None, "task_id": None, "status": "active",
                "kind": "directory", "createdAt": time.time(),
            })
            self._save_index()
            return f"Created directory lane '{name}' at {path.relative_to(WORKDIR)}"
        branch = f"wt/{name}"
        cmd = ["git", "worktree", "add", "-B", branch, str(path), base]
        r = subprocess.run(cmd, cwd=WORKDIR, capture_output=True, text=True)
        if r.returncode != 0:
            return f"Error: git worktree add failed: {r.stderr.strip()}"
        self.index["worktrees"].append({
            "name": name, "path": str(path.relative_to(WORKDIR)),
            "branch": branch, "task_id": None, "status": "active",
            "kind": "git", "createdAt": time.time(),
        })
        self._save_index()
        return f"Created worktree '{name}' at {path.relative_to(WORKDIR)} on branch {branch}"

    def remove(self, name: str, force: bool = False) -> str:
        wt = next((w for w in self.index["worktrees"] if w["name"] == name), None)
        if not wt:
            return f"Worktree '{name}' not found"
        path = WORKDIR / wt["path"]
        if wt.get("kind") == "git" and self._is_git_repo():
            args = ["git", "worktree", "remove", str(path)]
            if force:
                args.append("--force")
            r = subprocess.run(args, cwd=WORKDIR, capture_output=True, text=True)
            if r.returncode != 0 and not force:
                return f"Error: {r.stderr.strip()} (use force=true to override)"
        else:
            try:
                if path.exists():
                    subprocess.run(["rm", "-rf", str(path)], cwd=WORKDIR, check=True)
            except Exception as e:
                return f"Error removing dir lane: {e}"
        self.index["worktrees"] = [w for w in self.index["worktrees"] if w["name"] != name]
        self._save_index()
        return f"Removed worktree '{name}'"

    def bind_task(self, name: str, task_id: int) -> str:
        wt = next((w for w in self.index["worktrees"] if w["name"] == name), None)
        if not wt:
            return f"Worktree '{name}' not found"
        wt["task_id"] = task_id
        self._save_index()
        return f"Bound task #{task_id} to worktree '{name}'"

    def list_all(self) -> str:
        if not self.index["worktrees"]:
            return "No worktrees."
        lines = []
        for w in self.index["worktrees"]:
            tid = f" task=#{w['task_id']}" if w.get("task_id") else ""
            br = f" branch={w['branch']}" if w.get("branch") else ""
            lines.append(f"  {w['name']} ({w['kind']}, {w['status']}){br}{tid} -> {w['path']}")
        return "\n".join(lines)


# === SECTION: mcp (s19) ======================================================
class MCPClient:
    """Minimal stdio JSON-RPC client for an MCP-like server.

    Speaks: initialize, tools/list, tools/call. Servers that follow that
    handful of methods plug in directly. Everything else (resources, prompts,
    auth flows) is intentionally out of scope here.
    """

    def __init__(self, name: str, command: list, env: dict = None):
        self.name = name
        self.command = command
        self.env = env or {}
        self.proc = None
        self._lock = threading.Lock()
        self._next_id = 1
        self.tools = []  # list of {name, description, input_schema}

    def start(self) -> str:
        try:
            full_env = dict(os.environ)
            full_env.update(self.env)
            self.proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=full_env, cwd=str(WORKDIR),
                text=True, bufsize=1,
            )
        except Exception as e:
            return f"Error starting MCP server '{self.name}': {e}"
        # Initialize handshake.
        init = self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "minicode", "version": "0.1"},
        })
        if init is None:
            return f"Error: '{self.name}' did not respond to initialize"
        # List tools.
        listed = self._call("tools/list", {})
        if isinstance(listed, dict):
            for t in listed.get("tools", []):
                self.tools.append({
                    "name": t.get("name"),
                    "description": t.get("description", ""),
                    "input_schema": t.get("inputSchema") or t.get("input_schema") or {"type": "object"},
                })
        return f"MCP server '{self.name}' started with {len(self.tools)} tools"

    def call_tool(self, tool_name: str, arguments: dict) -> str:
        result = self._call("tools/call", {"name": tool_name, "arguments": arguments})
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                texts = []
                for piece in content:
                    if isinstance(piece, dict):
                        if "text" in piece:
                            texts.append(piece["text"])
                        else:
                            texts.append(json.dumps(piece))
                    else:
                        texts.append(str(piece))
                return "\n".join(texts) or json.dumps(result)
            return json.dumps(result)
        return str(result)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()

    def _call(self, method: str, params: dict):
        if not self.proc or self.proc.poll() is not None:
            return None
        with self._lock:
            req_id = self._next_id
            self._next_id += 1
            req = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
            try:
                self.proc.stdin.write(json.dumps(req) + "\n")
                self.proc.stdin.flush()
            except Exception as e:
                print(f"  [mcp:{self.name}] write error: {e}")
                return None
            # Naive line-based read, looking for matching id.
            deadline = time.time() + 30
            while time.time() < deadline:
                line = self.proc.stdout.readline()
                if not line:
                    continue
                try:
                    msg = json.loads(line.strip())
                except Exception:
                    continue
                if msg.get("id") == req_id:
                    if "error" in msg:
                        return {"_error": msg["error"]}
                    return msg.get("result")
            return None


class MCPManager:
    """Loads .minicode/mcp/config.json and routes prefixed tools to the right server."""

    CONFIG_FILE = MCP_DIR / "config.json"

    def __init__(self):
        self.clients = {}
        self._tool_index = {}  # prefixed_name -> (client_name, raw_tool_name, schema)

    def start(self):
        if not self.CONFIG_FILE.exists():
            return
        try:
            cfg = json.loads(self.CONFIG_FILE.read_text())
        except Exception as e:
            print(f"[mcp] config error: {e}")
            return
        for name, spec in cfg.get("servers", {}).items():
            cmd = spec.get("command")
            if not cmd:
                continue
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
            client_obj = MCPClient(name, cmd, env=spec.get("env"))
            msg = client_obj.start()
            print(f"[mcp] {msg}")
            self.clients[name] = client_obj
            for t in client_obj.tools:
                key = f"mcp__{name}__{t['name']}"
                self._tool_index[key] = (name, t["name"], t)

    def stop(self):
        for c in self.clients.values():
            c.stop()

    def tool_specs(self) -> list:
        out = []
        for key, (_, _, t) in self._tool_index.items():
            out.append({
                "name": key,
                "description": f"[mcp] {t.get('description', '')}",
                "input_schema": t.get("input_schema") or {"type": "object"},
            })
        return out

    def list_tools(self) -> str:
        if not self._tool_index:
            return "(no MCP tools loaded)"
        return "\n".join(f"- {k}" for k in sorted(self._tool_index))

    def is_mcp_tool(self, name: str) -> bool:
        return name in self._tool_index

    def call(self, name: str, arguments: dict) -> str:
        if name not in self._tool_index:
            return f"Error: unknown MCP tool '{name}'"
        client_name, raw, _ = self._tool_index[name]
        return self.clients[client_name].call_tool(raw, arguments)


# === SECTION: team_protocol (s16) ============================================
shutdown_requests = {}
plan_requests = {}


# === SECTION: teammates (s15/s17) ============================================
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
                                            block.input.get("status"))
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
                for msg in inbox:
                    if msg.get("type") == "shutdown_request":
                        shutdown_now = True
                        break
                    messages.append({"role": "user", "content": json.dumps(msg)})
                if shutdown_now:
                    self._set_status(name, "shutdown")
                    return
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
                    for msg in inbox:
                        if msg.get("type") == "shutdown_request":
                            self._set_status(name, "shutdown")
                            return
                        messages.append({"role": "user", "content": json.dumps(msg)})
                    resume = True
                    break
                # Auto-claim a pending task.
                unclaimed = self.task_mgr.unclaimed()
                if unclaimed:
                    task = unclaimed[0]
                    self.task_mgr.claim(task["id"], name)
                    if len(messages) <= 3:
                        # Identity re-injection after a compact.
                        messages.insert(0, {"role": "user", "content":
                            f"<identity>You are '{name}', role: {role}, team: {team_name}.</identity>"})
                        messages.insert(1, {"role": "assistant",
                                            "content": f"I am {name}. Continuing."})
                    messages.append({"role": "user", "content":
                        f"<auto-claimed>Task #{task['id']}: {task['subject']}\n"
                        f"{task.get('description', '')}</auto-claimed>"})
                    messages.append({"role": "assistant",
                                     "content": f"Claimed task #{task['id']}. Working on it."})
                    resume = True
                    break
            if not resume:
                self._set_status(name, "shutdown")
                return
            self._set_status(name, "working")


# === SECTION: shutdown / plan_approval (s16) =================================
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


# === SECTION: instances ======================================================
TODO = TodoManager()
PERMS = PermissionManager(mode=os.getenv("MINICODE_PERM_MODE", "default"))
HOOKS = HookManager()
MEMORY = MemoryManager()
SKILLS = SkillLoader(SKILLS_DIR)
TASK_MGR = TaskManager()
BG = BackgroundManager()
CRON = CronScheduler()
BUS = MessageBus()
WORKTREES = WorktreeManager()
MCP = MCPManager()
TEAM = TeammateManager(BUS, TASK_MGR, PERMS, HOOKS, MCP)


# === SECTION: system_prompt (s10) ============================================
def build_system_prompt() -> str:
    parts = [
        f"You are MiniCode, a coding agent operating at {WORKDIR}.",
        "Use tools to solve tasks. Prefer surgical changes that trace back to the user's request.",
        "Use TodoWrite for short multi-step plans (<= 20 items, one in_progress at a time).",
        "Use task_create / task_update / task_list for durable file-backed work.",
        "Use task (subagent) for isolated exploration that should not pollute the main context.",
        "Use load_skill before specialized work; available skills are listed below.",
        "Before destructive actions, prefer compress and explain your plan.",
        f"Permission mode: {PERMS.mode}.",
        "",
        "## Skills",
        SKILLS.descriptions(),
    ]
    mem_block = MEMORY.render_for_prompt()
    if mem_block:
        parts.append("")
        parts.append(mem_block)
    return "\n".join(parts)


# === SECTION: tool_dispatch (s02) ============================================
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
                                        kw.get("worktree")),
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


def _bool(default):
    return {"type": "boolean", "default": default}


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


# === SECTION: agent_loop (s01 + s11) =========================================
def execute_one_tool(block, hooks: HookManager, perms: PermissionManager) -> tuple:
    """One pass through the tool pipeline:
       hook PreToolUse -> permission -> handler -> hook PostToolUse.

    Returns (content, is_error). When is_error=True, the caller MUST mark the
    tool_result with `is_error: true` so the model knows the call failed.
    Without that flag, "Permission denied" looks like a normal success string
    and the model is liable to hallucinate that the action happened.
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
        # s06: compression pipeline.
        microcompact(messages)
        if estimate_tokens(messages) > TOKEN_THRESHOLD:
            print("[auto-compact triggered]")
            messages[:] = auto_compact(messages)

        # s13: drain background notifications into the conversation.
        notifs = BG.drain()
        if notifs:
            txt = "\n".join(f"[bg:{n['task_id']}] {n['status']}: {n['result']}" for n in notifs)
            messages.append({"role": "user",
                             "content": f"<background-results>\n{txt}\n</background-results>"})
            messages.append({"role": "assistant", "content": "Noted background results."})

        # s14: drain cron firings.
        cron_msgs = CRON.drain()
        for c in cron_msgs:
            messages.append({"role": "user", "content":
                f"<scheduled-trigger id='{c['task_id']}' cron='{c['cron']}' "
                f"at='{c['fired_at']}'>\n{c['prompt']}\n</scheduled-trigger>"})

        # s15/s16: pick up lead inbox.
        inbox = BUS.read_inbox("lead")
        if inbox:
            messages.append({"role": "user",
                             "content": f"<inbox>{json.dumps(inbox, indent=2)}</inbox>"})

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
        if response.stop_reason != "tool_use":
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

        # s03: nag the model if it has open todos but stops touching them.
        rounds_without_todo = 0 if used_todo else rounds_without_todo + 1
        if TODO.has_open_items() and rounds_without_todo >= 3:
            results.insert(0, {"type": "text",
                               "text": "<reminder>You have open todos. Update them.</reminder>"})

        messages.append({"role": "user", "content": results})

        if manual_compress:
            print("[manual compact]")
            messages[:] = auto_compact(messages, focus=compact_focus)


# === SECTION: repl ===========================================================
HELP_TEXT = """\
MiniCode REPL commands:
  /help              show this help
  /quit | /exit | q  exit
  /tasks             list tasks
  /team              list teammates
  /inbox             show & drain lead inbox
  /memory            list memories
  /skills            list skills (also reloads)
  /cron              list scheduled tasks
  /worktree          list worktrees
  /mcp               list MCP tools
  /mode <mode>       set permission mode (default|plan|auto|yolo)
  /compact [focus]   manually compact context
  /trust             create the trust marker (enables hooks)
Anything else is sent to the agent.
"""


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


# === SECTION: main ===========================================================
if __name__ == "__main__":
    if "--help" in sys.argv:
        print(HELP_TEXT)
        sys.exit(0)
    if "--version" in sys.argv:
        print("minicode 0.1")
        sys.exit(0)
    repl()
