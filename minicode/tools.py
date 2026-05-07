"""Base tool implementations: bash, file IO, grep, glob."""

import subprocess

from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS, PERSIST_TRIGGER_BASH
from minicode.persisted_output import maybe_persist_output
from minicode.security import safe_path


def _clamp_timeout(value, default: int, hi: int) -> int:
    """Coerce a possibly-None / negative / oversized timeout into a sane int.

    Models sometimes pass `null` or wild values for `timeout`. Without this,
    `subprocess.run(timeout=None)` would block forever and a huge value
    would let a runaway shell hang the agent indefinitely.
    """
    try:
        v = int(value) if value is not None else default
    except (TypeError, ValueError):
        return default
    if v <= 0:
        return default
    return min(v, hi)


def run_bash(command: str, tool_use_id: str = "", timeout: int = 120) -> str:
    timeout = _clamp_timeout(timeout, default=120, hi=600)
    try:
        r = subprocess.run(command, shell=True, cwd=WORKDIR,
                           capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).strip()
        if not out:
            return f"(no output, exit={r.returncode})"
        out = maybe_persist_output(tool_use_id, out, trigger_chars=PERSIST_TRIGGER_BASH)
        return out[:CONTEXT_TRUNCATE_CHARS]
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
        return out[:CONTEXT_TRUNCATE_CHARS]
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
