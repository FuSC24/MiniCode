"""Skill discovery and on-demand loading from skills/ directory."""
import re
from pathlib import Path

from minicode.config import WORKDIR, SKILLS_DIR


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


SKILLS = SkillLoader(SKILLS_DIR)
