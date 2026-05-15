"""Cron-style scheduler. agent_runner is injected by minicode.commands at startup."""

import json
import threading
import time
import uuid
from datetime import datetime
from queue import Queue, Empty

from minicode.config import CRON_DIR

agent_runner = None  # set by minicode.commands at startup; takes a history list and runs one turn-cycle.


def cron_matches(expr: str, dt: datetime) -> bool:
    """Match a 5-field cron expression against a datetime."""
    fields = expr.strip().split()
    if len(fields) != 5:
        return False
    cron_dow = (dt.weekday() + 1) % 7  # cron: 0=Sun
    values = [dt.minute, dt.hour, dt.day, dt.month, cron_dow]
    ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]
    for field, val, (lo, hi) in zip(fields, values, ranges):
        if not _cron_field(field, val, lo, hi):
            return False
    return True


def _cron_field(field: str, value: int, lo: int, hi: int) -> bool:
    if field == "*":
        return True
    for part in field.split(","):
        step = 1
        if "/" in part:
            part, sstr = part.split("/", 1)
            try:
                step = int(sstr)
            except ValueError:
                return False
        if part == "*":
            if (value - lo) % step == 0:
                return True
        elif "-" in part:
            try:
                a, b = (int(x) for x in part.split("-", 1))
            except ValueError:
                return False
            if a <= value <= b and (value - a) % step == 0:
                return True
        else:
            try:
                start = int(part)
            except ValueError:
                return False
            # `N` alone matches exact value; `N/M` means start at N then step
            # by M up to hi (cron-style: e.g. `5/10` -> 5,15,25,35,45,55).
            if step == 1:
                if start == value:
                    return True
            else:
                if start <= value <= hi and (value - start) % step == 0:
                    return True
    return False


class CronScheduler:
    """Background scheduler. Fires prompts back into the agent loop."""

    DURABLE_FILE = CRON_DIR / "tasks.json"

    def __init__(self):
        self.tasks = []
        self.queue = Queue()
        self._stop = threading.Event()
        self._thread = None
        self._last_minute = -1

    def start(self):
        self._load_durable()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        if self.tasks:
            print(f"[cron] loaded {len(self.tasks)} scheduled tasks")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def create(self, cron_expr: str, prompt: str,
               recurring: bool = True, durable: bool = False) -> str:
        # Validate immediately so bad expressions fail loud.
        if len(cron_expr.strip().split()) != 5:
            return "Error: cron expression must have 5 fields (m h dom mon dow)"
        tid = str(uuid.uuid4())[:8]
        self.tasks.append({
            "id": tid, "cron": cron_expr, "prompt": prompt,
            "recurring": recurring, "durable": durable,
            "createdAt": time.time(),
        })
        if durable:
            self._save_durable()
        mode = "recurring" if recurring else "one-shot"
        store = "durable" if durable else "session"
        return f"Created cron {tid} ({mode}/{store}): {cron_expr} -> {prompt[:60]}"

    def delete(self, tid: str) -> str:
        before = len(self.tasks)
        self.tasks = [t for t in self.tasks if t["id"] != tid]
        if len(self.tasks) < before:
            self._save_durable()
            return f"Deleted cron {tid}"
        return f"Cron {tid} not found"

    def list_tasks(self) -> str:
        if not self.tasks:
            return "No scheduled tasks."
        lines = []
        for t in self.tasks:
            mode = "recurring" if t["recurring"] else "one-shot"
            store = "durable" if t["durable"] else "session"
            age_h = (time.time() - t["createdAt"]) / 3600
            lines.append(f"  {t['id']}  {t['cron']}  [{mode}/{store}] "
                         f"({age_h:.1f}h old): {t['prompt'][:60]}")
        return "\n".join(lines)

    def drain(self) -> list:
        out = []
        while True:
            try:
                out.append(self.queue.get_nowait())
            except Empty:
                break
        return out

    def _loop(self):
        while not self._stop.is_set():
            now = datetime.now()
            current = now.hour * 60 + now.minute
            if current != self._last_minute:
                self._last_minute = current
                self._fire_due(now)
            self._stop.wait(timeout=1)

    def _fire_due(self, now: datetime):
        fired_oneshot = []
        for t in self.tasks:
            if cron_matches(t["cron"], now):
                self.queue.put({
                    "task_id": t["id"], "cron": t["cron"], "prompt": t["prompt"],
                    "fired_at": now.isoformat(timespec="seconds"),
                })
                if not t["recurring"]:
                    fired_oneshot.append(t["id"])
        if fired_oneshot:
            self.tasks = [t for t in self.tasks if t["id"] not in fired_oneshot]
            self._save_durable()

    def _save_durable(self):
        CRON_DIR.mkdir(parents=True, exist_ok=True)
        durable_only = [t for t in self.tasks if t.get("durable")]
        self.DURABLE_FILE.write_text(json.dumps(durable_only, indent=2))

    def _load_durable(self):
        if not self.DURABLE_FILE.exists():
            return
        try:
            self.tasks = json.loads(self.DURABLE_FILE.read_text()) or []
        except Exception as e:
            print(f"[cron] could not load durable file: {e}")


CRON = CronScheduler()
