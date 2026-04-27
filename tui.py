#!/usr/bin/env python3
# MiniCode TUI -- a Textual frontend for the harness in main.py.
#
# Layout:
#   [header: workdir | model | perm-mode | status]
#   [conversation log (scrollable, styled)]
#   [right side panel: tasks / team / cron summary, refreshed periodically]
#   [input bar]
#   [footer: keybindings]
#
# Design notes:
# - main.py uses print() / input() for I/O. The TUI redirects sys.stdout to
#   a styled RichLog, and overrides PermissionManager.ask_user with a modal
#   dialog so permission prompts work without blocking on stdin.
# - agent_loop runs in a worker thread; the UI thread stays responsive.
# - Slash commands are handled in the TUI before falling back to agent_loop.

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (Button, Footer, Header, Input, Label, RichLog,
                             Static)


# === SECTION: bootstrap ======================================================
def _resolve_workdir() -> Path:
    """Pick the user-requested workspace before importing main."""
    parser = argparse.ArgumentParser(prog="minicode-tui",
                                     description="MiniCode TUI launcher")
    parser.add_argument("workdir", nargs="?", default=".",
                        help="Workspace directory (default: current)")
    parser.add_argument("--mode", default=None,
                        choices=["default", "plan", "auto", "yolo"],
                        help="Initial permission mode")
    args, _ = parser.parse_known_args()
    wd = Path(args.workdir).expanduser().resolve()
    if not wd.exists():
        print(f"workdir does not exist: {wd}", file=sys.stderr)
        sys.exit(2)
    if args.mode:
        os.environ["MINICODE_PERM_MODE"] = args.mode
    os.chdir(wd)
    return wd


WORKDIR = _resolve_workdir()
import main  # noqa: E402  -- must come after chdir so WORKDIR resolves correctly


# === SECTION: stdout capture =================================================
class _StreamCapture:
    """Forward stdout writes to the TUI.

    Strategy: complete lines (terminated by `\n`) are committed to the
    permanent RichLog; the trailing partial line is shown live in a
    `#stream-preview` Static so streaming model output appears character by
    character without spamming the log with stub entries.
    """

    def __init__(self, app: "MiniCodeApp"):
        self._app = app
        self._buf = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._app.commit_stream_line(line)
        if self._buf:
            self._app.update_stream_preview(self._buf)
        return len(s)

    def flush(self):
        # Each delta-write already updated the preview; nothing extra to do.
        pass

    def isatty(self) -> bool:
        return False


# === SECTION: permission modal ===============================================
class _PermissionModal(ModalScreen[str]):
    """y / n / always for one tool call."""

    BINDINGS = [
        Binding("y", "approve", "Allow once"),
        Binding("a", "approve_always", "Always allow"),
        Binding("n", "deny", "Deny"),
        Binding("escape", "deny", "Deny"),
    ]

    def __init__(self, tool_name: str, preview: str):
        super().__init__()
        self._tool_name = tool_name
        self._preview = preview

    def compose(self) -> ComposeResult:
        with Vertical(id="perm-box"):
            yield Label(f"Permission requested: [bold cyan]{self._tool_name}[/]",
                        id="perm-title")
            yield Static(self._preview, id="perm-preview")
            with Horizontal(id="perm-buttons"):
                yield Button("Allow  (y)", id="perm-allow")
                yield Button("Always (a)", id="perm-always")
                yield Button("Deny   (n)", id="perm-deny")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "perm-allow":
            self.dismiss("y")
        elif event.button.id == "perm-always":
            self.dismiss("always")
        else:
            self.dismiss("n")

    def action_approve(self) -> None:
        self.dismiss("y")

    def action_approve_always(self) -> None:
        self.dismiss("always")

    def action_deny(self) -> None:
        self.dismiss("n")


# === SECTION: side panel =====================================================
class _SidePanel(Static):
    """Right-hand panel: live snapshot of tasks / team / cron."""

    def on_mount(self) -> None:
        self.refresh_panel()
        self.set_interval(3.0, self.refresh_panel)

    def refresh_panel(self) -> None:
        try:
            tasks = main.TASK_MGR.list_all()
        except Exception as e:
            tasks = f"(tasks error: {e})"
        try:
            team = main.TEAM.list_all()
        except Exception as e:
            team = f"(team error: {e})"
        try:
            cron = main.CRON.list_tasks()
        except Exception as e:
            cron = f"(cron error: {e})"
        bg = main.BG.check() if main.BG.tasks else "No background tasks."
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


# === SECTION: app ============================================================
HELP_TEXT = (
    "[bold]Commands[/]\n"
    "  [cyan]/help[/]              this help\n"
    "  [cyan]/mode[/] <mode>       permission mode: default | plan | auto | yolo\n"
    "  [cyan]/tasks[/]             list tasks\n"
    "  [cyan]/team[/]              list teammates\n"
    "  [cyan]/memory[/]            list cross-session memories\n"
    "  [cyan]/skills[/]            reload + list skills\n"
    "  [cyan]/cron[/]              list scheduled cron tasks\n"
    "  [cyan]/worktree[/]          list git worktrees / dir lanes\n"
    "  [cyan]/mcp[/]               list loaded MCP tools\n"
    "  [cyan]/inbox[/]             show and drain lead inbox\n"
    "  [cyan]/compact[/] <focus>   manually compact context\n"
    "  [cyan]/trust[/]             create trust marker (enables hooks)\n"
    "  [cyan]/clear[/]             clear log\n"
    "  [cyan]/quit[/]              exit\n"
    "\n"
    "[bold]Keys[/]\n"
    "  [yellow]Ctrl+C[/]   quit\n"
    "  [yellow]Ctrl+L[/]   clear log\n"
    "  [yellow]Ctrl+P[/]   toggle side panel\n"
    "\n"
    "[dim]Anything else you type is sent to the agent.[/]"
)


class MiniCodeApp(App):
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #log {
        width: 3fr;
        border: round #444;
        padding: 0 1;
    }
    #side {
        width: 1fr;
        border: round #444;
        padding: 1;
        overflow: auto;
    }
    #status {
        dock: top;
        height: 1;
        background: $boost;
        color: $text;
        padding: 0 1;
    }
    #stream-preview {
        dock: bottom;
        height: auto;
        max-height: 8;
        padding: 0 3;
        color: #cccccc;
    }
    #input-area {
        dock: bottom;
        height: auto;
    }
    #input-bar {
        height: auto;
        margin: 0 1 0 1;
        padding: 0 1;
        border: round #6cb6ff;
        background: $surface;
    }
    #input-row {
        height: 1;
        layout: horizontal;
    }
    #input-prompt {
        width: 2;
        color: #6cb6ff;
        text-style: bold;
    }
    #input {
        border: none;
        height: 1;
        background: transparent;
        padding: 0;
    }
    #input:focus { border: none; }
    #input-hint {
        height: 1;
        padding: 0 3;
        color: #888888;
    }
    _PermissionModal {
        align: center middle;
        background: black 60%;
    }
    _PermissionModal #perm-box {
        width: 70;
        height: auto;
        border: thick $warning;
        background: $surface;
        padding: 1 2;
    }
    _PermissionModal #perm-title { padding-bottom: 1; }
    _PermissionModal #perm-preview {
        background: $boost;
        padding: 1;
        height: auto;
        max-height: 12;
        overflow: auto;
    }
    _PermissionModal #perm-buttons {
        padding-top: 1;
        height: auto;
        align-horizontal: center;
    }
    _PermissionModal Button {
        margin: 0 1;
        min-width: 14;
        height: 3;
        color: white;
        text-style: bold;
        border: none;
    }
    _PermissionModal #perm-allow  { background: #2ea043; }
    _PermissionModal #perm-allow:hover  { background: #3fb950; }
    _PermissionModal #perm-always { background: #1f6feb; }
    _PermissionModal #perm-always:hover { background: #388bfd; }
    _PermissionModal #perm-deny   { background: #da3633; }
    _PermissionModal #perm-deny:hover   { background: #f85149; }
    """

    # Disable textual's built-in `^p palette` and our extra hints in the footer.
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("ctrl+c", "quit_app", "Quit", show=True),
        Binding("ctrl+l", "clear_log", "Clear", show=False),
        Binding("ctrl+p", "toggle_side", "Panel", show=False),
    ]

    def __init__(self, workdir: Path):
        super().__init__()
        self.workdir = workdir
        self.history: list = []
        self._busy = False
        self._log_widget: RichLog | None = None
        self._stdout_cap: _StreamCapture | None = None
        self._side_visible = True

    # ---- compose / mount ------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static(self._status_text(), id="status")
        with Horizontal(id="main"):
            yield RichLog(id="log", wrap=True, markup=True, auto_scroll=True,
                          highlight=False)
            yield _SidePanel(id="side")
        yield Static("", id="stream-preview")
        with Vertical(id="input-area"):
            with Container(id="input-bar"):
                with Horizontal(id="input-row"):
                    yield Static("> ", id="input-prompt")
                    yield Input(id="input",
                                placeholder="ask MiniCode anything, or /help")
            yield Static(self._input_hint_text(), id="input-hint")

    def on_mount(self) -> None:
        self.title = "MiniCode"
        self.sub_title = str(self.workdir)
        self._log_widget = self.query_one("#log", RichLog)

        # Hook up the permission modal so worker threads can ask the UI.
        def tui_ask(tool_name: str, tool_input: dict) -> bool:
            # Worker thread calls this; show a modal on the UI thread.
            event = threading.Event()
            answer = {"value": None}

            def on_decided(result: str | None) -> None:
                answer["value"] = result
                event.set()

            preview = main.json.dumps(tool_input, ensure_ascii=False)[:600]
            self.call_from_thread(self._show_permission_modal,
                                  tool_name, preview, on_decided)
            event.wait()
            decision = answer["value"]
            if decision == "always":
                main.PERMS.rules.append(
                    {"tool": tool_name, "path": "*", "behavior": "allow"})
                return True
            return decision == "y"

        main.PERMS.ask_user = tui_ask  # type: ignore[assignment]

        # Redirect stdout so all main.py print() calls land in our log.
        self._stdout_cap = _StreamCapture(self)
        sys.stdout = self._stdout_cap

        # Initial harness setup, the same things repl() does.
        main.STATE_DIR.mkdir(parents=True, exist_ok=True)
        main.MEMORY.load_all()
        main.CRON.start()
        main.MCP.start()
        main.HOOKS.run("SessionStart")

        log = self._log_widget
        log.write("Type [bold]/help[/] for commands. "
                  "[dim]/mode yolo skips permission prompts (demo only).[/]")
        log.write("")
        self.query_one("#input", Input).focus()

    def on_unmount(self) -> None:
        # Restore stdout and tear down background threads.
        if self._stdout_cap is not None:
            sys.stdout = sys.__stdout__
        try:
            main.HOOKS.run("SessionEnd")
        except Exception:
            pass
        main.CRON.stop()
        main.MCP.stop()

    # ---- helpers --------------------------------------------------------
    def _status_text(self) -> str:
        busy = "[red]● busy[/]" if self._busy else "[green]● idle[/]"
        return (f" [bold green]MiniCode[/]  [dim]·[/]  [cyan]{self.workdir}[/]  "
                f"[dim]·[/]  model [cyan]{main.MODEL}[/]  "
                f"[dim]·[/]  {busy}")

    def _input_hint_text(self) -> str:
        return (f"[dim]/help for shortcuts  ·  "
                f"enter to send  ·  "
                f"mode [/][yellow]{main.PERMS.mode}[/]")

    def _refresh_status(self) -> None:
        self.query_one("#status", Static).update(self._status_text())
        try:
            self.query_one("#input-hint", Static).update(self._input_hint_text())
        except Exception:
            pass

    def post_log(self, line: str) -> None:
        """Append to the conversation log, with light styling. Works from any thread."""
        if self._log_widget is None:
            return
        styled = self._style_line(line)
        try:
            # Off the UI thread: marshal back. On the UI thread: this raises.
            self.call_from_thread(self._log_widget.write, styled)
        except RuntimeError:
            self._log_widget.write(styled)

    def commit_stream_line(self, line: str) -> None:
        """A streamed line is complete: commit to log + clear live preview."""
        if line:
            self.post_log(line)
        self._update_preview("")

    def update_stream_preview(self, partial: str) -> None:
        """The current streamed line grew; show it live in the preview Static."""
        # Truncate very long previews so the preview area doesn't blow up
        # (the full text will land in the log once a newline arrives).
        shown = partial if len(partial) < 800 else "…" + partial[-799:]
        self._update_preview(shown)

    def _update_preview(self, text: str) -> None:
        try:
            preview = self.query_one("#stream-preview", Static)
        except Exception:
            return
        try:
            self.call_from_thread(preview.update, text)
        except RuntimeError:
            preview.update(text)

    @staticmethod
    def _style_line(line: str) -> str:
        # Escape Rich markup that may sneak in from tool output.
        safe = line.replace("[", r"\[")
        if line.startswith("> "):
            return f"[cyan]{safe}[/]"
        if line.startswith("["):
            return f"[dim]{safe}[/]"
        return safe

    def _show_permission_modal(self, tool_name: str, preview: str, cb) -> None:
        modal = _PermissionModal(tool_name, preview)
        self.push_screen(modal, cb)

    def action_clear_log(self) -> None:
        if self._log_widget is not None:
            self._log_widget.clear()

    def action_toggle_side(self) -> None:
        side = self.query_one("#side")
        self._side_visible = not self._side_visible
        side.display = self._side_visible

    def action_quit_app(self) -> None:
        self.exit()

    # ---- input ----------------------------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        if self._busy:
            self._log_widget.write("[yellow]busy -- wait for the current turn to finish[/]")
            return
        if self._handle_slash(text):
            return
        self._log_widget.write(f"[bold yellow]>> {text}[/]")
        self.history.append({"role": "user", "content": text})
        self._set_busy(True)
        self._run_agent_turn()

    def _handle_slash(self, text: str) -> bool:
        if not text.startswith("/"):
            return False
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("/quit", "/exit"):
            self.exit()
        elif cmd == "/help":
            self._log_widget.write(HELP_TEXT)
        elif cmd == "/clear":
            self.action_clear_log()
        elif cmd == "/tasks":
            self._log_widget.write(main.TASK_MGR.list_all())
        elif cmd == "/team":
            self._log_widget.write(main.TEAM.list_all())
        elif cmd == "/memory":
            self._log_widget.write(main.MEMORY.list_all())
        elif cmd == "/cron":
            self._log_widget.write(main.CRON.list_tasks())
        elif cmd == "/worktree":
            self._log_widget.write(main.WORKTREES.list_all())
        elif cmd == "/mcp":
            self._log_widget.write(main.MCP.list_tools())
        elif cmd == "/inbox":
            inbox = main.BUS.read_inbox("lead")
            self._log_widget.write(main.json.dumps(inbox, indent=2)
                                   if inbox else "(empty)")
        elif cmd == "/skills":
            main.SKILLS.reload()
            self._log_widget.write(main.SKILLS.list_all())
        elif cmd == "/trust":
            main.TRUST_MARKER.parent.mkdir(parents=True, exist_ok=True)
            main.TRUST_MARKER.write_text("trusted")
            self._log_widget.write(
                f"trust marker created at {main.TRUST_MARKER}")
        elif cmd == "/mode":
            if not arg:
                self._log_widget.write(
                    f"current perm mode: [cyan]{main.PERMS.mode}[/] "
                    f"(modes: {main.PERM_MODES})")
            else:
                try:
                    main.PERMS.set_mode(arg.strip())
                    self._log_widget.write(f"perm mode -> [cyan]{main.PERMS.mode}[/]")
                    self._refresh_status()
                except ValueError as e:
                    self._log_widget.write(f"[red]error:[/] {e}")
        elif cmd == "/compact":
            if self.history:
                self._log_widget.write(
                    f"[dim]manual compact{f' (focus={arg})' if arg else ''}[/]")
                self.history[:] = main.auto_compact(self.history,
                                                    focus=arg or None)
            else:
                self._log_widget.write("(nothing to compact)")
        else:
            self._log_widget.write(f"[red]unknown command:[/] {cmd}")
        return True

    # ---- agent worker ---------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self._refresh_status()

    @work(thread=True, exclusive=True)
    def _run_agent_turn(self) -> None:
        try:
            main.agent_loop(self.history)
        except Exception as e:
            self.post_log(f"[error] {e}")
        finally:
            self.call_from_thread(self._set_busy, False)
            self.call_from_thread(self._log_widget.write,
                                  "[dim]" + ("─" * 80) + "[/]")


# === SECTION: entrypoint =====================================================
def run_app() -> None:
    """Entry point for `python tui.py` and the `minicode-tui` console script.

    Named `run_app` (not `main`) because we already `import main` at the top of
    this file -- defining `def main()` here would shadow the harness module.
    """
    app = MiniCodeApp(WORKDIR)
    app.run()


if __name__ == "__main__":
    run_app()
