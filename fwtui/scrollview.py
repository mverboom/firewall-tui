"""Shared scrolling/navigation for the custom list views (DbView, RulesView).

Both views are full-width custom widgets that manage their own scroll offset
and selection. The navigation, mouse handling, and section-bar rendering are
identical, so they live here in one base class. Subclasses supply the row
model, collapse state, and rendering for their own row kinds.
"""

from __future__ import annotations

from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.strip import Strip
from textual.widget import Widget

# Navigation bindings shared by both views (vi-style + arrows + page keys).
NAV_BINDINGS = [
    Binding("up", "move(-1)", "Up", show=False),
    Binding("down", "move(1)", "Down", show=False),
    Binding("pageup", "move(-10)", "Page up", show=False),
    Binding("pagedown", "move(10)", "Page down", show=False),
    Binding("home", "move(-100000)", "Top", show=False),
    Binding("end", "move(100000)", "Bottom", show=False),
    Binding("j", "move(1)", "Down", show=False),
    Binding("k", "move(-1)", "Up", show=False),
    Binding("G", "move(100000)", "Bottom", show=False),
    Binding("ctrl+d", "move_half_page(1)", "Half page down", show=False),
    Binding("ctrl+u", "move_half_page(-1)", "Half page up", show=False),
    Binding("ctrl+f", "move_page(1)", "Page down", show=False),
    Binding("ctrl+b", "move_page(-1)", "Page up", show=False),
    Binding("space", "toggle_collapse", "Collapse/expand", show=False),
    Binding("enter", "activate", "Edit", show=False),
    Binding("/", "search", "Filter", show=False),
]


class ScrollView(Widget, can_focus=True):
    """Base for the custom list views: selection, scroll, navigation, and
    section-bar rendering. Subclasses provide rows, collapse state, and
    rendering of their own row kinds."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.all_rows: list[tuple] = []
        self.rows: list[tuple] = []
        self.selected = 0
        self.scroll = 0

    # -- navigation --------------------------------------------------------
    def action_move(self, delta: int) -> None:
        if delta < 0 and self.selected == 0 and self.scroll == 0:
            # at the very top (including an empty view): back to the menu
            self.post_message(self.NavigateUp())
            return
        if not self.rows:
            return
        self.selected = max(0, min(len(self.rows) - 1, self.selected + delta))
        self._ensure_visible()
        self.refresh()
        self.post_message(self.SelectionChanged(self.selected))

    def action_move_page(self, delta: int) -> None:
        """ctrl+f/ctrl+b: move a full viewport."""
        self.action_move(delta * max(1, self.size.height))

    def action_move_half_page(self, delta: int) -> None:
        """ctrl+d/ctrl+u: move half a viewport."""
        self.action_move(delta * max(1, self.size.height // 2))

    def _ensure_visible(self) -> None:
        height = max(1, self.size.height)
        if self.selected < self.scroll:
            self.scroll = self.selected
        elif self.selected >= self.scroll + height:
            self.scroll = self.selected - height + 1

    def on_click(self, event: events.Click) -> None:
        if self.rows:
            self.selected = min(len(self.rows) - 1, event.y + self.scroll)
            self._ensure_visible()
            self.refresh()
            self.post_message(self.SelectionChanged(self.selected))

    def on_mouse_scroll_down(self, event) -> None:
        if self.rows:
            self.scroll = min(len(self.rows) - 1, self.scroll + 3)
            self.refresh()

    def on_mouse_scroll_up(self, event) -> None:
        if self.rows:
            self.scroll = max(0, self.scroll - 3)
            self.refresh()

    # -- rendering ---------------------------------------------------------
    def _render_section(self, name: str, width: int, selected: bool,
                        fg: str, bg: str, key: str) -> Strip:
        style = f"{fg} on {bg}"
        marker = "▾" if key not in self.collapsed else "▸"
        text = Text(f" {marker} {name}", style=style)
        if text.cell_len > width:
            text = Text(text.plain[: max(0, width - 3)] + "...", style=style)
        text.pad_right(max(0, width - text.cell_len))
        if selected:
            text.stylize("reverse")
        segments = [s for s in self.app.console.render(text) if s.text != "\n"]
        return Strip(segments, width)
