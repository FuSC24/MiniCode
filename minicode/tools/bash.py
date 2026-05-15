"""Bash tool: run shell command in WORKDIR."""
import subprocess

from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS, PERSIST_TRIGGER_BASH
from minicode.tools._common import _clamp_timeout
from minicode.tools.persisted_output import maybe_persist_output


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
