"""Glob match files relative to WORKDIR."""
from minicode.config import WORKDIR, CONTEXT_TRUNCATE_CHARS
from minicode.tools.persisted_output import maybe_persist_output


def run_glob(pattern: str, tool_use_id: str = "") -> str:
    try:
        results = sorted(str(p.relative_to(WORKDIR)) for p in WORKDIR.glob(pattern)
                         if p.is_file())
        out = "\n".join(results) or "(no matches)"
        return maybe_persist_output(tool_use_id, out)[:CONTEXT_TRUNCATE_CHARS]
    except Exception as e:
        return f"Error: {e}"
