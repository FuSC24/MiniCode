"""On-disk persistent memory entries (.memory/MEMORY.md + per-entry files)."""
import re
from pathlib import Path

from minicode.config import MEMORY_DIR, WORKDIR

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


MEMORY = MemoryManager()
