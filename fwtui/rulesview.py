"""Custom full-width rules view.

Sections are rendered as full-width header bars (like an HTML table row with
colspan), with the rules of each section as column rows underneath. This
replaces the DataTable for the Rules tab because DataTable cannot span a cell
across columns.

Scrolling is handled manually (own scroll offset) to avoid fighting textual's
virtual-size machinery inside the tabbed layout.

Row model (list of tuples):
    ("section", name)
    ("implicit-section", name)
    ("rule", line, section_name, cols_dict)
    ("implicit", cols_dict)

Keys:
    space  toggle one header
    o      toggle all headers open/closed
    O      toggle visibility of headers with no rules in this view

When hide_empty is on (default), header rows whose section has no rules in
this view are hidden entirely; 'O' reveals them so rules can be added to an
existing (for this table empty) section.
"""

from __future__ import annotations

from rich.text import Text
from textual.binding import Binding
from textual.message import Message
from textual.strip import Strip

from .scrollview import NAV_BINDINGS, ScrollView

COLUMNS = ("chain", "from", "sport", "to", "proto", "port",
           "match", "action", "target")
# chain is 11 so "postrouting" (11 chars) is not truncated; every column is
# joined with a space in the render so values never run together
COL_WIDTHS = (11, 22, 6, 22, 6, 12, 12, 10, 20)

SECTION_FG = "#a9b1d6"
SECTION_BG = "#2a2f45"
IMPLICIT_FG = "#565f89"
IMPLICIT_BG = "#24283b"
INCLUDE_FG = "#e0af68"   # amber, for [#include] bars
INCLUDE_BG = "#2a2f45"


def header_text(widths: list[int] | None = None) -> str:
    """The column header line (for the Static above the view)."""
    widths = widths or COL_WIDTHS
    # joined with a space so columns always have a gap, even when a value
    # exactly fills its column width (e.g. "postrouting" = 10 in a 10-wide col)
    return " ".join(c.ljust(w) for c, w in zip(COLUMNS, widths))


class RulesView(ScrollView):
    """Full-width rules view with spanning section bars."""

    BINDINGS = NAV_BINDINGS + [
        Binding("o", "toggle_all", "Toggle all", show=False),
        Binding("O", "toggle_empty", "Toggle empty", show=False),
        Binding("ctrl+up", "move_up", "Move up", show=False),
        Binding("ctrl+down", "move_down", "Move down", show=False),
    ]

    class SelectionChanged(Message):
        """Posted when the selected row changes."""

        def __init__(self, row_index: int) -> None:
            super().__init__()
            self.row_index = row_index

    class Activate(Message):
        """Posted when enter is pressed on a row (open the editor)."""

        def __init__(self, row_index: int) -> None:
            super().__init__()
            self.row_index = row_index

    class NavigateUp(Message):
        """Posted when up is pressed at the very top (focus the menu)."""

    class MoveRequest(Message):
        """Posted when ctrl+up/down is pressed (reorder the selected row)."""

        def __init__(self, direction: str) -> None:
            super().__init__()
            self.direction = direction

    class SearchRequest(Message):
        """Posted when / is pressed (open the filter prompt)."""

    class WidthsChanged(Message):
        """Posted when the column widths change (keep the header in sync)."""

        def __init__(self, view: "RulesView", widths: list[int]) -> None:
            super().__init__()
            self.view = view
            self.widths = widths

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.collapsed: set[str] = set()  # section names that are collapsed
        self.hide_empty = True  # hide headers with no rules in this view
        self._initialized = False
        self.filter_text = ""
        self.col_widths = list(COL_WIDTHS)  # dynamic, content-based

    # -- data --------------------------------------------------------------
    @staticmethod
    def _key(row: tuple) -> str:
        """Collapse key for a row: sections by name, includes prefixed."""
        if row[0] == "include":
            return "include:" + row[1]
        return row[1]

    def set_rows(self, rows: list[tuple], reset_collapsed: bool = False) -> None:
        self.all_rows = rows
        if reset_collapsed or not self._initialized:
            # default: everything collapsed (like the db view)
            self.collapsed = {self._key(r) for r in rows
                              if r[0] in ("section", "implicit-section",
                                          "include")}
            self._initialized = True
        valid = {self._key(r) for r in rows
                 if r[0] in ("section", "implicit-section", "include")}
        self.collapsed &= valid
        self._rebuild_visible()
        self.selected = 0
        self.scroll = 0
        self.refresh()
        self.post_message(self.SelectionChanged(0))

    def _section_include_keys(self):
        """Yield (name, source, key, include_keys) for each section row,
        where include_keys are the include-bar keys enclosing it."""
        stack: list[tuple[str, str]] = []  # (included file path, key)
        for row in self.all_rows:
            kind = row[0]
            if kind == "include":
                stack.append((row[2] or "", self._key(row)))
            elif kind == "section":
                while stack and stack[-1][0] != (row[2] or ""):
                    stack.pop()
                yield row[1], row[2], self._key(row), [k for _, k in stack]

    def _contentful_keys(self) -> set[str]:
        """Keys of header rows that have at least one rule in this view.

        A section is contentful when any rule row belongs to it (matched by
        name + source file); an include bar is contentful when a section
        inside it (transitively, via the include stack) is."""
        sections = {(row[2], row[1].source) for row in self.all_rows
                    if row[0] == "rule"}
        contentful: set[str] = set()
        for row in self.all_rows:
            if row[0] == "implicit-section":
                contentful.add(self._key(row))
        for name, source, key, inc_keys in self._section_include_keys():
            if (name, source) in sections:
                contentful.add(key)
                contentful.update(inc_keys)
        return contentful

    def _matching_include_keys(self, matching: set) -> set[str]:
        """Include bars that contain a section with matching rules (filter)."""
        result: set[str] = set()
        for name, source, key, inc_keys in self._section_include_keys():
            if (name, source) in matching:
                result.update(inc_keys)
        return result

    def _rebuild_visible(self) -> None:
        """Recompute visible rows; collapsed sections and include groups hide
        their content. A stack tracks nested include groups by source file.
        A filter hides non-matching rows; sections (and include bars) without
        any matching rule are hidden entirely, not left as empty headers.
        When hide_empty is on, headers without rules in this view are hidden
        entirely (so each table tab only shows sections it has rules for)."""
        self.rows = []
        stack: list[tuple[str, bool]] = []  # (included file path, hidden)
        section_hidden = False
        matching = self._matching_sections()
        matching_includes = (self._matching_include_keys(matching)
                             if matching is not None else None)
        contentful = self._contentful_keys() if self.hide_empty else None
        for row in self.all_rows:
            kind = row[0]
            if kind == "include":
                key = self._key(row)
                if row[2]:
                    stack.append((row[2], key in self.collapsed
                                  or (contentful is not None
                                      and key not in contentful)
                                  or (matching_includes is not None
                                      and key not in matching_includes)))
                # missing includes always show (warning state); resolved
                # includes with no rules in this view, or none matching the
                # filter, are hidden like sections
                if contentful is not None and key not in contentful and row[2]:
                    continue
                if (matching_includes is not None
                        and key not in matching_includes and row[2]):
                    continue
                self.rows.append(row)
                continue
            if kind == "section":
                # leave include groups whose content has ended
                while stack and stack[-1][0] != row[2]:
                    stack.pop()
                group_hidden = any(h for _, h in stack)
                filtered = (matching is not None
                            and (row[1], row[2]) not in matching)
                empty = (contentful is not None
                         and self._key(row) not in contentful)
                if empty or filtered:
                    # no rules in this view, or none match the filter:
                    # hide the header entirely (its rules are hidden too)
                    section_hidden = True
                    continue
                section_hidden = (row[1] in self.collapsed) or group_hidden
                self.rows.append(row)
                continue
            if kind == "implicit-section":
                section_hidden = row[1] in self.collapsed
                self.rows.append(row)
                continue
            if matching is not None and kind == "rule" \
                    and not self._matches(row):
                continue
            if not section_hidden:
                self.rows.append(row)
        self.selected = min(self.selected, max(0, len(self.rows) - 1))
        self._ensure_visible()
        self._recompute_widths()

    # -- column widths -----------------------------------------------------
    def _compute_widths(self) -> list[int]:
        """Content-based column widths for the visible rows, shrunk to fit
        the view width so no columns fall outside the window and no space
        is wasted. The widest columns are shrunk first (min 3 chars)."""
        width = self.size.width
        if width <= 0:
            return list(self.col_widths)
        cw = [len(h) for h in COLUMNS]
        for row in self.rows:
            if row[0] not in ("rule", "implicit"):
                continue
            cols = row[-1]
            for i, c in enumerate(COLUMNS):
                cw[i] = max(cw[i], len(str(cols.get(c, "any"))))
        spaces = len(COLUMNS) - 1
        if sum(cw) + spaces <= width:
            return cw
        cw = list(cw)
        while sum(cw) + spaces > width:
            i = max(range(len(cw)), key=lambda i: cw[i])
            if cw[i] <= 3:
                break
            cw[i] -= 1
        return cw

    def _recompute_widths(self) -> None:
        """Recompute the column widths and announce changes (for the header)."""
        new = self._compute_widths()
        if new != self.col_widths:
            self.col_widths = new
            self.post_message(self.WidthsChanged(self, new))

    def on_resize(self, event) -> None:
        self._recompute_widths()
        self.refresh()

    def expand_section(self, name: str) -> None:
        """Expand a collapsed section (used when adding a rule to it), plus
        any include group the section lives in."""
        self.collapsed.discard(name)
        for row in self.all_rows:
            if row[0] == "section" and row[1] == name and row[2]:
                src = row[2]
                for inc in self.all_rows:
                    if inc[0] == "include" and inc[2] == src:
                        self.collapsed.discard("include:" + inc[1])
                break
        self._rebuild_visible()
        self.refresh()

    def action_toggle_collapse(self) -> None:
        if not self.rows:
            return
        row = self.rows[self.selected]
        if row[0] in ("section", "implicit-section", "include"):
            key = self._key(row)
            if key in self.collapsed:
                self.collapsed.discard(key)
                # expanding a section inside an include also expands its
                # parent include bar(s), so the section's rules show
                if row[0] == "section" and row[2]:
                    for inc in self.all_rows:
                        if inc[0] == "include" and inc[2] == row[2]:
                            self.collapsed.discard("include:" + inc[1])
            else:
                self.collapsed.add(key)
            self._rebuild_visible()
            self.refresh()
            self.post_message(self.SelectionChanged(self.selected))

    def action_toggle_all(self) -> None:
        """o: toggle the open/closed state of all headers (all collapsed ->
        expand all; anything open -> collapse all)."""
        keys = {self._key(r) for r in self.all_rows
                if r[0] in ("section", "implicit-section", "include")}
        if keys and keys <= self.collapsed:
            self.collapsed = set()  # all collapsed: expand everything
        else:
            self.collapsed = keys  # collapse everything
        self._rebuild_visible()
        self.refresh()
        self.post_message(self.SelectionChanged(self.selected))

    def action_toggle_empty(self) -> None:
        """O: toggle visibility of headers that have no rules in this view.
        Reveals sections that are empty for the current table tab, so a rule
        can be added to them."""
        self.hide_empty = not self.hide_empty
        self._rebuild_visible()
        self.refresh()
        self.post_message(self.SelectionChanged(self.selected))

    def action_activate(self) -> None:
        """Enter: toggle collapse on a section/header, else open the editor."""
        if not self.rows:
            return
        row = self.rows[self.selected]
        if row[0] in ("section", "implicit-section", "include"):
            self.action_toggle_collapse()
        else:
            self.post_message(self.Activate(self.selected))

    def action_move_up(self) -> None:
        if self.rows:
            self.post_message(self.MoveRequest("up"))

    def action_move_down(self) -> None:
        if self.rows:
            self.post_message(self.MoveRequest("down"))

    def action_search(self) -> None:
        self.post_message(self.SearchRequest())

    def set_filter(self, text: str) -> None:
        """Filter the view to rows matching text (case-insensitive)."""
        self.filter_text = text.strip().lower()
        self._rebuild_visible()
        self.refresh()

    def _matches(self, row: tuple) -> bool:
        if not self.filter_text:
            return True
        if row[0] == "section":
            return self.filter_text in row[1].lower()
        if row[0] == "rule":
            return (self.filter_text in row[1].value.lower()
                    or self.filter_text in row[2].lower())
        if row[0] == "include":
            return self.filter_text in row[1].lower()
        return True  # implicit rows always show (context)

    def _matching_sections(self):
        """Sections that match the filter or contain a matching rule."""
        if not self.filter_text:
            return None
        result = set()
        for row in self.all_rows:
            if row[0] == "section" and self._matches(row):
                result.add((row[1], row[2]))
            if row[0] == "rule" and self._matches(row):
                result.add((row[2], row[1].source))
        return result

    def select_line(self, line) -> bool:
        """Select the row for a rule line after a repopulation."""
        for i, row in enumerate(self.rows):
            if row[0] == "rule" and row[1] is line:
                self.selected = i
                self._ensure_visible()
                self.refresh()
                self.post_message(self.SelectionChanged(i))
                return True
        return False

    def select_section(self, name: str, source: str) -> bool:
        """Select the row for a section after a repopulation."""
        for i, row in enumerate(self.rows):
            if row[0] == "section" and row[1] == name and row[2] == source:
                self.selected = i
                self._ensure_visible()
                self.refresh()
                self.post_message(self.SelectionChanged(i))
                return True
        return False

    def select_include(self, name: str) -> bool:
        """Select the row for an include bar after a repopulation."""
        for i, row in enumerate(self.rows):
            if row[0] == "include" and row[1] == name:
                self.selected = i
                self._ensure_visible()
                self.refresh()
                self.post_message(self.SelectionChanged(i))
                return True
        return False

    # -- rendering ---------------------------------------------------------
    def render_line(self, y: int) -> Strip:
        width = self.size.width
        vy = y + self.scroll
        if vy >= len(self.rows):
            return Strip.blank(width, self.rich_style)
        row = self.rows[vy]
        kind = row[0]
        selected = (vy == self.selected)
        if kind == "include":
            label = "include: " + row[1]
            if not row[2]:
                label += " (missing)"
            return self._render_section(label, width, selected,
                                        INCLUDE_FG, INCLUDE_BG, self._key(row))
        if kind in ("section", "implicit-section"):
            implicit = kind == "implicit-section"
            fg = IMPLICIT_FG if implicit else SECTION_FG
            bg = IMPLICIT_BG if implicit else SECTION_BG
            label = row[1]
            if kind == "section" and len(row) > 3 and row[3]:
                label = f"include: {row[1]}"
            return self._render_section(label, width, selected, fg, bg,
                                        row[1])
        # rule / implicit rows carry their column dict as the last element
        return self._render_rule(row[-1], width, selected, kind == "implicit")

    def _render_rule(self, cols: dict, width: int, selected: bool,
                     implicit: bool) -> Strip:
        cells = []
        for c, w in zip(COLUMNS, self.col_widths):
            val = str(cols.get(c, "any"))
            cells.append(val[:w].ljust(w))
        # join with a space so columns never run together
        line = " ".join(cells)
        text = Text(line)
        text.stylize(self.rich_style)
        if implicit:
            text.stylize("dim")
        if selected:
            text.stylize("reverse")
        segments = [s for s in self.app.console.render(text) if s.text != "\n"]
        return Strip(segments, width)
