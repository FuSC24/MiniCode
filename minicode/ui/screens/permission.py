"""Permission approval modal."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static


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
