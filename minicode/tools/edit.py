"""Edit tool: single-occurrence string replacement."""
from minicode.services.security import safe_path


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
