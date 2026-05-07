"""Git worktree manager."""

import json
import re
import subprocess
import time

from minicode.config import WORKDIR, WORKTREE_DIR
from minicode.security import safe_path


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
        # `.git` is a directory in normal repos and a file in git worktrees.
        # Path.exists() covers both.
        return (WORKDIR / ".git").exists()

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
        # Re-resolve the recorded path through safe_path so a tampered index
        # cannot trick us into deleting outside the workspace.
        try:
            path = safe_path(wt["path"])
        except ValueError:
            return f"Error: worktree path escapes workspace: {wt['path']}"
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
                    r = subprocess.run(["rm", "-rf", str(path)], cwd=WORKDIR,
                                       capture_output=True, text=True)
                    if r.returncode != 0:
                        return f"Error removing dir lane: {r.stderr.strip()}"
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


WORKTREES = WorktreeManager()
