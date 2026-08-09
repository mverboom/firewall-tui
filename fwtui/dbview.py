"""Custom db view: sections as collapsible bars, entries as key/value rows.

Sections default to collapsed (the db sections tend to be long). Space
toggles a section, enter activates the selected row (edit), up at the very
top posts NavigateUp so the app can focus the menu.

Row model (list of tuples):
    ("dbsection", name)
    ("dbentry", key, value, section)
"""

from __future__ import annotations

from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.message import Message
from textual.strip import Strip
from textual.widget import Widget

COLUMNS = ("key", "value")
COL_WIDTHS = (24, 60)

SECTION_FG = "#a9b1d6"
SECTION_BG = "#2a2f45"


class DbView(Widget, can_focus=True):
    """Collapsible grouped view of the db file."""

    BINDINGS = [
        Binding("up", "move(-1)", "Up", show=False),
        Binding("down", "move(1)", "Down", show=False),
        Binding("pageup", "move(-10)", "Page up", show=False),
        Binding("pagedown", "move(10)", "Page down", show=False),
        Binding("home", "move(-100000)", "Top", show=False),
        Binding("end", "move(100000)", "Bottom", show=False),
        Binding("space", "toggle_collapse", "Collapse/expand", show=False),
        Binding("c", "collapse_all", "Collapse all", show=False),
        Binding("o", "expand_all", "Expand all", show=False),
        Binding("enter", "activate", "Edit", show=False),
    ]

    class SelectionChanged(Message):
        def __init__(self, row_index: int) -> None:
            super().__init__()
            self.row_index = row_index

    class Activate(Message):
        def __init__(self, row_index: int) -> None:
            super().__init__()
            self.row_index = row_index

    class NavigateUp(Message):
        pass

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.all_rows: list[tuple] = []
        self.rows: list[tuple] = []
        self.collapsed: set[str] = set()
        self._initialized = False
        self.selected = 0
        self.scroll = 0

    # -- data --------------------------------------------------------------
    def set_rows(self, rows: list[tuple]) -> None:
        self.all_rows = rows
        if not self._initialized:
            # default: everything collapsed
            self.collapsed = {r[1] for r in rows if r[0] == "dbsection"}
            self._initialized = True
        valid = {r[1] for r in rows if r[0] == "dbsection"}
        self.collapsed &= valid
        self._rebuild_visible()
        self.selected = 0
        self.scroll = 0
        self.refresh()
        self.post_message(self.SelectionChanged(0))

    def _rebuild_visible(self) -> None:
        self.rows = []
        hide = False
        for row in self.all_rows:
            if row[0] == "dbsection":
                hide = row[1] in self.collapsed
                self.rows.append(row)
            elif not hide:
                self.rows.append(row)
        self.selected = min(self.selected, max(0, len(self.rows) - 1))
        self._ensure_visible()

    def expand_section(self, name: str) -> None:
        self.collapsed.discard(name)
        self._rebuild_visible()
        self.refresh()

    # -- navigation --------------------------------------------------------
    def action_move(self, delta: int) -> None:
        if not self.rows:
            return
        if delta < 0 and self.selected == 0 and self.scroll == 0:
            self.post_message(self.NavigateUp())
            return
        self.selected = max(0, min(len(self.rows) - 1, self.selected + delta))
        self._ensure_visible()
        self.refresh()
        self.post_message(self.SelectionChanged(self.selected))

    def action_toggle_collapse(self) -> None:
        if not self.rows:
            return
        row = self.rows[self.selected]
        if row[0] == "dbsection":
            name = row[1]
            if name in self.collapsed:
                self.collapsed.discard(name)
            else:
                self.collapsed.add(name)
            self._rebuild_visible()
            self.refresh()
            self.post_message(self.SelectionChanged(self.selected))

    def action_collapse_all(self) -> None:
        self.collapsed = {r[1] for r in self.all_rows
                          if r[0] == "dbsection"}
        self._rebuild_visible()
        self.refresh()
        self.post_message(self.SelectionChanged(self.selected))

    def action_expand_all(self) -> None:
        self.collapsed = set()
        self._rebuild_visible()
        self.refresh()
        self.post_message(self.SelectionChanged(self.selected))

    def action_activate(self) -> None:
        """Enter: toggle collapse on a section bar, else edit the entry."""
        if not self.rows:
            return
        row = self.rows[self.selected]
        if row[0] == "dbsection":
            self.action_toggle_collapse()
        else:
            self.post_message(self.Activate(self.selected))

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
    def render_line(self, y: int) -> Strip:
        width = self.size.width
        vy = int(y + self.scroll)
        if vy >= len(self.rows):
            return Strip.blank(width, self.rich_style)
        row = self.rows[vy]
        selected = (vy == self.selected)
        if row[0] == "dbsection":
            return self._render_section(row[1], width, selected)
        return self._render_entry(row[1], row[2], width, selected)

    def _render_section(self, name: str, width: int, selected: bool) -> Strip:
        style = f"{SECTION_FG} on {SECTION_BG}"
        marker = "▾" if name not in self.collapsed else "▸"
        text = Text(f" {marker} {name}", style=style)
        if text.cell_len > width:
            text = Text(text.plain[: max(0, width - 3)] + "...", style=style)
        text.pad_right(max(0, width - text.cell_len))
        if selected:
            text.stylize("reverse")
        segments = [s for s in self.app.console.render(text) if s.text != "\n"]
        return Strip(segments, width)

    def _render_entry(self, key: str, value: str, width: int,
                      selected: bool) -> Strip:
        cells = [key[:COL_WIDTHS[0]].ljust(COL_WIDTHS[0]),
                 value[:COL_WIDTHS[1]].ljust(COL_WIDTHS[1])]
        line = " ".join(cells)
        text = Text(line)
        text.stylize(self.rich_style)
        if selected:
            text.stylize("reverse")
        segments = [s for s in self.app.console.render(text) if s.text != "\n"]
        return Strip(segments, width)
