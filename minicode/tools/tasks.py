"""File-backed durable task tracker + background subprocess manager."""

import json
import subprocess
import threading
import time
import uuid
from pathlib import Path
from queue import Queue, Empty

from minicode.config import TASKS_DIR, WORKDIR
from minicode.tools._common import _clamp_timeout


# === SECTION: tasks ====================================================
class TaskManager:
    """File-backed task board: each task is one JSON file under .minicode/tasks/.

    A single lock guards id-allocation + read-modify-write so concurrent
    `create` / `update` / `claim` calls from the lead and N teammate threads
    don't corrupt files (two creates picking the same id, claim racing with
    update, etc.).
    """

    def __init__(self):
        TASKS_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        ids = [int(f.stem.split("_")[1]) for f in TASKS_DIR.glob("task_*.json")]
        return max(ids, default=0) + 1

    def _path(self, tid: int) -> Path:
        return TASKS_DIR / f"task_{tid}.json"

    def _load(self, tid: int) -> dict:
        p = self._path(tid)
        if not p.exists():
            raise ValueError(f"Task {tid} not found")
        return json.loads(p.read_text())

    def _save(self, task: dict):
        self._path(task["id"]).write_text(json.dumps(task, indent=2))

    def create(self, subject: str, description: str = "",
               blocked_by: list = None, worktree: str = None) -> str:
        with self._lock:
            task = {
                "id": self._next_id(),
                "subject": subject,
                "description": description,
                "status": "pending",
                "owner": None,
                "worktree": worktree,
                "blockedBy": list(blocked_by or []),
                "blocks": [],
                "createdAt": time.time(),
            }
            self._save(task)
        return json.dumps(task, indent=2)

    def get(self, tid: int) -> str:
        with self._lock:
            return json.dumps(self._load(tid), indent=2)

    def update(self, tid: int, status: str = None,
               add_blocked_by: list = None, add_blocks: list = None,
               worktree: str = None, actor: str = None) -> str:
        with self._lock:
            task = self._load(tid)
            owner = task.get("owner")
            # `lead` and absent actor (internal/legacy callers) bypass.
            if actor and actor != "lead" and owner and owner != actor:
                return (f"Error: task #{tid} is owned by '{owner}', "
                        f"'{actor}' cannot update it. The tool did NOT run.")
            if status:
                task["status"] = status
                if status in ("completed", "deleted"):
                    # Unblock any task that was waiting on this one.
                    for f in TASKS_DIR.glob("task_*.json"):
                        t = json.loads(f.read_text())
                        if tid in t.get("blockedBy", []):
                            t["blockedBy"].remove(tid)
                            self._path(t["id"]).write_text(json.dumps(t, indent=2))
                if status == "deleted":
                    self._path(tid).unlink(missing_ok=True)
                    return f"Task {tid} deleted"
            if add_blocked_by:
                task["blockedBy"] = list(set(task.get("blockedBy", []) + add_blocked_by))
            if add_blocks:
                task["blocks"] = list(set(task.get("blocks", []) + add_blocks))
            if worktree is not None:
                task["worktree"] = worktree
            self._save(task)
            return json.dumps(task, indent=2)

    def list_all(self) -> str:
        with self._lock:
            tasks = [json.loads(f.read_text())
                     for f in sorted(TASKS_DIR.glob("task_*.json"))]
        if not tasks:
            return "No tasks."
        lines = []
        for t in tasks:
            mark = {"pending": "[ ]", "in_progress": "[>]", "completed": "[x]"}.get(t["status"], "[?]")
            owner = f" @{t['owner']}" if t.get("owner") else ""
            blocked = f" (blocked by: {t['blockedBy']})" if t.get("blockedBy") else ""
            wt = f" wt={t['worktree']}" if t.get("worktree") else ""
            lines.append(f"{mark} #{t['id']}: {t['subject']}{owner}{blocked}{wt}")
        return "\n".join(lines)

    def claim(self, tid: int, owner: str) -> str:
        with self._lock:
            task = self._load(tid)
            # Refuse to re-claim a task another teammate already owns.
            if task.get("owner") and task["owner"] != owner:
                return (f"Error: task #{tid} already owned by '{task['owner']}'. "
                        f"The tool did NOT run.")
            task["owner"] = owner
            task["status"] = "in_progress"
            self._save(task)
        return f"Claimed task #{tid} for {owner}"

    def unclaimed(self) -> list:
        with self._lock:
            out = []
            for f in sorted(TASKS_DIR.glob("task_*.json")):
                t = json.loads(f.read_text())
                if t.get("status") == "pending" and not t.get("owner") and not t.get("blockedBy"):
                    out.append(t)
            return out


# === SECTION: background ===============================================
class BackgroundManager:
    """Run shell commands in daemon threads. Notifications drain into the loop."""

    def __init__(self):
        self.tasks = {}
        self.notifications = Queue()

    def run(self, command: str, timeout: int = 600) -> str:
        timeout = _clamp_timeout(timeout, default=600, hi=3600)
        tid = str(uuid.uuid4())[:8]
        self.tasks[tid] = {"status": "running", "command": command, "result": None}
        threading.Thread(target=self._exec, args=(tid, command, timeout), daemon=True).start()
        return f"Background task {tid} started: {command[:80]}"

    def _exec(self, tid: str, command: str, timeout: int):
        try:
            r = subprocess.run(command, shell=True, cwd=WORKDIR,
                               capture_output=True, text=True, timeout=timeout)
            output = (r.stdout + r.stderr).strip()[:50000] or "(no output)"
            self.tasks[tid].update({"status": "completed", "result": output})
        except subprocess.TimeoutExpired:
            self.tasks[tid].update({"status": "timeout", "result": f"timed out after {timeout}s"})
        except Exception as e:
            self.tasks[tid].update({"status": "error", "result": str(e)})
        self.notifications.put({"task_id": tid,
                                "status": self.tasks[tid]["status"],
                                "result": str(self.tasks[tid]["result"])[:500]})

    def check(self, tid: str = None) -> str:
        if tid:
            t = self.tasks.get(tid)
            if not t:
                return f"Unknown bg task: {tid}"
            return f"[{t['status']}] {t.get('result', '(running)')}"
        if not self.tasks:
            return "No background tasks."
        return "\n".join(f"{k}: [{v['status']}] {v['command'][:60]}"
                         for k, v in self.tasks.items())

    def kill(self, tid: str) -> str:
        t = self.tasks.get(tid)
        if not t:
            return f"Unknown bg task: {tid}"
        t["status"] = "killed"
        return f"Marked {tid} as killed (already-detached subprocess will run to completion)"

    def drain(self) -> list:
        out = []
        while True:
            try:
                out.append(self.notifications.get_nowait())
            except Empty:
                break
        return out


TASK_MGR = TaskManager()
BG = BackgroundManager()
