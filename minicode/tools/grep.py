"""Recursive regex grep across WORKDIR."""
import subprocess

from minicode.config import CONTEXT_TRUNCATE_CHARS, PERSIST_TRIGGER_BASH
from minicode.tools.persisted_output import maybe_persist_output
from minicode.services.security import safe_path


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
