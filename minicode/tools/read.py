"""Read tool."""
from minicode.config import CONTEXT_TRUNCATE_CHARS
from minicode.tools.persisted_output import maybe_persist_output
from minicode.services.security import safe_path


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
