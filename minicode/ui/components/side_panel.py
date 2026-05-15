"""Side-panel widget showing live workspace state."""
from __future__ import annotations

from textual.widgets import Static

from minicode.tools.tasks import TASK_MGR, BG
from minicode.tools.scheduling import CRON
from minicode.tools.team import TEAM


class _SidePanel(Static):
    """Right-hand panel: live snapshot of tasks / team / cron."""

    def on_mount(self) -> None:
        self.refresh_panel()
        self.set_interval(3.0, self.refresh_panel)

    def refresh_panel(self) -> None:
        try:
            tasks = TASK_MGR.list_all()
        except Exception as e:
            tasks = f"(tasks error: {e})"
        try:
            team = TEAM.list_all()
        except Exception as e:
            team = f"(team error: {e})"
        try:
            cron = CRON.list_tasks()
        except Exception as e:
            cron = f"(cron error: {e})"
        bg = BG.check() if BG.tasks else "No background tasks."
        text = (
            "[bold yellow]TASKS[/]\n"
            f"{tasks}\n\n"
            "[bold yellow]TEAM[/]\n"
            f"{team}\n\n"
            "[bold yellow]CRON[/]\n"
            f"{cron}\n\n"
            "[bold yellow]BACKGROUND[/]\n"
            f"{bg}"
        )
        self.update(text)
