"""Persist large tool outputs to disk; replace in transcript with a marker."""
import re
from pathlib import Path

from minicode.config import (
    WORKDIR, TOOL_RESULTS_DIR, PERSIST_TRIGGER_DEFAULT,
    PERSIST_PREVIEW_CHARS,
)

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
