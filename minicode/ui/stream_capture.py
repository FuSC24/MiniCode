"""Stream capture utility for redirecting stdout/stderr into the TUI."""
from __future__ import annotations


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
