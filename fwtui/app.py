"""Textual TUI for managing __firewall rulesets and the shared db.

Layout:
  top bar : host selector
  tabs    : Rules  - filter rules, full-width column overview, sections as
                     groups, implicit rules from [global] shown non-editable
            NAT    - nat rules only (sections with both filter and nat rules
                     appear in both tabs)
            Mangle - mangle rules only
            Global - the [global] settings (implicit)
            db     - shared definitions (services, hosts, networks, groups)

Keys:
  a        add rule / db entry / global key (context dependent)
  e        edit selected rule / section / db entry / global key
  d        delete selected rule / section / db entry / global key
  n        new section (rules / nat / mangle tab)
  v        validate current ruleset
  o        toggle all section headers open/closed
  O        toggle visibility of headers empty for the current tab
  ctrl+s   save current file
  q        quit
"""

from __future__ import annotations

import os
import sys

from rich.markup import escape
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, ListItem, ListView,
    Select, Static, TabbedContent, TabPane, TextArea,
)
from textual.widgets._select import SelectOverlay
from textual.widgets._tabbed_content import ContentTabs

from . import columns, expand, implicit, parser
from .config import load_config
from .dbview import DbView
from .rulesview import RulesView, header_text

FW_DIR_DEFAULT = "/home/cdist/config/files/firewall"

# global settings with a fixed set of valid values (shown as dropdowns)
GLOBAL_OPTIONS = {
    "policy": ["accept", "drop"],
    "policy_input": ["accept", "drop"],
    "policy_output": ["accept", "drop"],
    "policy_forward": ["accept", "drop"],
    "established": ["true", "false"],
    "icmp": ["true", "false"],
    "loopback": ["true", "false"],
    "packageinstall": ["true", "false"],
    "proto": ["4", "6", "4,6"],
}

# All global keys in display order, with the manifest's effective default
# when the key is not present in the rules file (mirrors __firewall/manifest
# and man.rst). policy_* inherits policy, log_* inherits log.
GLOBAL_ORDER = (
    "policy", "policy_input", "policy_output", "policy_forward",
    "established", "icmp", "proto", "log",
    "log_input", "log_forward", "log_output",
    "loopback", "packageinstall",
)
GLOBAL_DEFAULTS = {
    "policy": "accept",
    "policy_input": "",   # inherits policy
    "policy_output": "",
    "policy_forward": "",
    "established": "false",
    "icmp": "(unset)",    # manifest: no icmp rules when unset
    "proto": "4",
    "log": "",
    "log_input": "",
    "log_forward": "",
    "log_output": "",
    "loopback": "true",
    "packageinstall": "true",
}


class NavSelect(Select, inherit_bindings=False):
    """Select that opens only with enter/space; up/down bubble for navigation.

    The stock Select opens its dropdown on up/down too, which blocks using
    those keys to move between form fields / the host selector and tabs.
    type_to_search is off so printable keys (a, s) reach the modal shortcuts.
    """

    BINDINGS = [
        Binding("enter,space", "show_overlay", "Show menu", show=False),
    ]

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("type_to_search", False)
        super().__init__(*args, **kwargs)


class HostSelect(NavSelect):
    """Host selector: type to search. Typing opens the dropdown and feeds
    the key to its search, so printable keys search instead of triggering
    app actions (a/e/d/v/...)."""

    class Focused(Message):
        pass

    def __init__(self, *args, **kwargs) -> None:
        kwargs["type_to_search"] = True
        super().__init__(*args, **kwargs)

    def on_focus(self, event) -> None:
        self.post_message(self.Focused())

    async def _on_key(self, event: events.Key) -> None:
        if (event.character is not None and event.is_printable
                and not self.expanded):
            # typing searches: open the dropdown and feed the key to it.
            # The overlay resets its search query when it gains focus, and
            # focus is applied asynchronously, so feed the char afterwards.
            self.action_show_overlay()
            char = event.character
            event.stop()
            self.call_after_refresh(lambda: self._feed_search(char))
            return
        await super()._on_key(event)

    def _feed_search(self, char: str) -> None:
        """Add a character to the overlay's search query (mirrors
        SelectOverlay._on_key)."""
        overlay = self.query_one(SelectOverlay)
        overlay._search_query += char
        index = overlay._find_search_match(overlay._search_query)
        if index is not None:
            overlay.select(index)


class NavDataTable(DataTable):
    """DataTable for the Global tab: posts NavigateUp at the top row and
    Activate on enter (so enter works like 'e')."""

    class NavigateUp(Message):
        pass

    class Activate(Message):
        pass

    BINDINGS = [
        Binding("enter", "activate", "Edit", show=False),
    ]

    def action_activate(self) -> None:
        self.post_message(self.Activate())

    def action_cursor_up(self) -> None:
        if self.cursor_row == 0:
            self.post_message(self.NavigateUp())
        else:
            super().action_cursor_up()


# ---------------------------------------------------------------------------
# rule editor modal (builder form + raw text)
# ---------------------------------------------------------------------------

ACTIONS = [
    ("ACCEPT", "ACCEPT"),
    ("DROP", "DROP"),
    ("reject(reset)", "reject(reset)"),
    ("reject(unreachable)", "reject(unreachable)"),
    ("reject(prohibited)", "reject(prohibited)"),
    ("log", "log"),
    ("DNAT", "DNAT"),
    ("SNAT", "SNAT"),
    ("MASQUERADE", "MASQUERADE"),
]

CHAINS = [
    ("INPUT", "INPUT"), ("OUTPUT", "OUTPUT"), ("FORWARD", "FORWARD"),
    ("PREROUTING", "PREROUTING"), ("POSTROUTING", "POSTROUTING"),
]

PROTOS = [("both (46)", "46"), ("IPv4", "4"), ("IPv6", "6")]

# Sentinel value for the "(custom ...)" option in the Source/Dest dropdowns
CUSTOM = "__custom__"


def build_rule(chain: str, iface: str, src: str, dst: str, svc: str,
               action: str, to: str, extra: str,
               logprefix: str = "") -> str:
    parts = [f"-A {chain}"]
    if iface:
        parts.append(f"-i {iface}")
    if src:
        parts.append(f"-s {src}")
    if dst:
        parts.append(f"-d {dst}")
    if svc:
        if svc.startswith("dservices("):
            parts.append(svc)  # multiport form, keep as-is
        else:
            parts.append(f"dservice({svc})")
    if action == "DNAT":
        parts.append("-j DNAT")
        if to:
            parts.append(f"--to-destination {to}")
    elif action == "SNAT":
        parts.append("-j SNAT")
        if to:
            parts.append(f"--to-source {to}")
    elif action == "MASQUERADE":
        parts.append("-j MASQUERADE")
    elif action == "log":
        parts.append(f"log({logprefix or 'firewall'})")
    elif action.startswith("reject("):
        parts.append(action)  # e.g. reject(unreachable)
    else:
        parts.append(f"-j {action}")
    if extra:
        parts.append(extra)
    return " ".join(parts)


class RuleEditor(ModalScreen):
    """Modal to add/edit a rule. Builder fields feed a live raw preview;
    the raw text is authoritative on save."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("s", "save", "Save", show=False),
        Binding("a", "add_db_entry", "Add db entry", show=False),
        Binding("up", "prev_field", "Prev field", show=False),
        Binding("down", "next_field", "Next field", show=False),
    ]

    def __init__(self, table: str, proto: str, text: str = "",
                 db: "expand.Db | None" = None,
                 ifaces: list[str] | None = None) -> None:
        super().__init__()
        self.table = table
        self.proto = proto if proto in ("4", "6", "46") else "4"
        self.text = text
        self.db = db or expand.Db()
        self.services = list(self.db.services)
        self.hosts = list(self.db.hosts)
        self.networks = list(self.db.networks)
        self.hostgroups = list(self.db.hostgroups)
        self.networkgroups = list(self.db.networkgroups)
        # interfaces from the host's last explorer run (empty = plain input)
        self.ifaces = ifaces or []

    def _iface_options(self) -> list:
        opts = [("(any)", "")] + [(i, i) for i in self.ifaces]
        opts.append(("(custom ...)", CUSTOM))
        return opts

    def _source_options(self) -> list:
        """Options for the Source/Dest fields: db hosts, networks, groups,
        plus an explicit (custom ...) entry so raw values (plain IPs etc.)
        are known to be allowed."""
        opts = [("(any)", "")]
        for h in self.hosts:
            opts.append((f"host({h})", f"host({h})"))
        for n in self.networks:
            opts.append((f"network({n})", f"network({n})"))
        for g in self.hostgroups:
            opts.append((f"hostgroup({g})", f"hostgroup({g})"))
        for g in self.networkgroups:
            opts.append((f"networkgroup({g})", f"networkgroup({g})"))
        opts.append(("(custom ...)", CUSTOM))
        return opts

    def _set_select_value(self, sel: Select, value: str) -> None:
        """Set a Select's value, adding it as an option if not present (so
        raw values like IPs or hosts(a,b) are preserved on rebuild). New
        values are inserted before the (custom ...) sentinel so that entry
        always stays last."""
        if not value:
            sel.value = ""
            return
        values = [v for _, v in sel._options]
        if value not in values:
            opts = list(sel._options)
            custom_idx = next(
                (i for i, (p, v) in enumerate(opts) if v == CUSTOM), len(opts))
            opts.insert(custom_idx, (value, value))
            sel.set_options(opts)
        sel.value = value

    def _row(self, label: str, widget, classes: str = "") -> Horizontal:
        """One compact form row: label on the left, widget filling the rest."""
        return Horizontal(Label(label, classes="flabel"), widget,
                          classes=f"frow {classes}".strip())

    def compose(self) -> ComposeResult:
        yield Static("Rule editor", classes="modal-title")
        with Horizontal():
            with Vertical(id="builder"):
                yield self._row("Proto", NavSelect(
                    PROTOS, value=self.proto, id="f-proto",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Chain", NavSelect(
                    CHAINS, id="f-chain",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Iface (-i)",
                    NavSelect(self._iface_options(), value="", id="f-iface",
                              classes="fselect -textual-compact",
                              allow_blank=False)
                    if self.ifaces else Input(
                        placeholder="e.g. eth0, vlan10", id="f-iface",
                        classes="finput -textual-compact"))
                yield self._row("Source (-s)", NavSelect(
                    self._source_options(), value="", id="f-src",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Dest (-d)", NavSelect(
                    self._source_options(), value="", id="f-dst",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Service", NavSelect(
                    [("(none)", "")] + [(s, s) for s in self.services]
                    + [("(custom ...)", CUSTOM)],
                    value="", id="f-svc",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Action", NavSelect(
                    ACTIONS, value="ACCEPT", id="f-action",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("To host", NavSelect(
                    [("(none)", "")] + [(f"host({h})", f"host({h})")
                                          for h in self.hosts],
                    value="", id="f-to-host",
                    classes="fselect -textual-compact", allow_blank=False),
                    classes="natrow")
                yield self._row("To svc", NavSelect(
                    [("(none)", "")] + [(f"service({s})", f"service({s})")
                                           for s in self.services],
                    value="", id="f-to-svc",
                    classes="fselect -textual-compact", allow_blank=False),
                    classes="natrow")
                yield self._row("Log prefix", Input(
                    placeholder="e.g. apache dropped", id="f-logprefix",
                    classes="finput -textual-compact"), classes="logrow")
                yield self._row("Extra", Input(
                    placeholder="e.g. -m limit --limit 10/min", id="f-extra",
                    classes="finput -textual-compact"))
                yield Label(
                    "Source/Dest/Service: pick a db entry, or '(custom ...)' "
                    "for any raw value", classes="fhint")
            with Vertical(id="rawcol"):
                yield Label("Raw rule text (authoritative)", classes="frow")
                yield TextArea(self.text, id="f-raw")
        with Horizontal(id="modal-buttons"):
            yield Button("Save", variant="primary", id="btn-save")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        # -textual-compact cannot be passed via classes= (leading-dash tokens
        # are stripped); add it after mount so the fields are 1 line each
        for w in self.query(".fselect, .finput"):
            w.add_class("-textual-compact")
        self._syncing = False
        self._sync_timer = None
        self._sync_from_raw()
        self._update_conditional_rows()

    def on_text_area_changed(self, event) -> None:
        """Raw text edited: re-parse the fields (debounced so partial typing
        doesn't pollute the dropdowns)."""
        if self._syncing:
            return
        if self._sync_timer is not None:
            self._sync_timer.stop()
        self._sync_timer = self.set_timer(0.5, self._sync_from_raw)

    def _update_conditional_rows(self) -> None:
        """Show the To host/To svc rows only for DNAT/SNAT, and the Log
        prefix row only for the log action."""
        action = self.query_one("#f-action", Select).value
        show_nat = action in ("DNAT", "SNAT")
        for row in self.query(".natrow"):
            row.set_class(show_nat, "-show")
        show_log = action == "log"
        for row in self.query(".logrow"):
            row.set_class(show_log, "-show")

    def _sync_from_raw(self) -> None:
        import re
        self._syncing = True
        try:
            raw = self.query_one("#f-raw", TextArea).text
            self.text = raw
            m = re.search(r"-A\s+(\S+)", raw)
            if m:
                self.query_one("#f-chain", Select).value = m.group(1)
            for flag, wid in (("-i", "#f-iface"), ("-s", "#f-src"),
                              ("-d", "#f-dst")):
                m = re.search(rf"{flag}\s+(\S+)", raw)
                if m:
                    if wid in ("#f-src", "#f-dst"):
                        self._set_select_value(self.query_one(wid, Select),
                                               m.group(1))
                    else:
                        w = self.query_one(wid)
                        if isinstance(w, Input):
                            w.value = m.group(1)
                        else:
                            self._set_select_value(w, m.group(1))
            # DNAT/SNAT rules use the long form --destination; capture it too
            m = re.search(r"--destination\s+(\S+)", raw)
            if m:
                self._set_select_value(self.query_one("#f-dst", Select),
                                       m.group(1))
            m = re.search(r"dservices\(([^)]+)\)", raw)
            if m:
                self._set_select_value(self.query_one("#f-svc", Select),
                                       f"dservices({m.group(1)})")
            m = re.search(r"dservice\(([^)]+)\)", raw)
            if m:
                # keep unknown service names as raw options so opening and
                # saving an existing rule never drops a dservice() clause
                self._set_select_value(self.query_one("#f-svc", Select),
                                       m.group(1))
            m = re.search(r"-j\s+(\S+)", raw)
            if m:
                act = m.group(1)
                if act in ("ACCEPT", "DROP", "DNAT", "SNAT", "MASQUERADE"):
                    self.query_one("#f-action", Select).value = act
            # function actions: reject(...) and log(prefix)
            m = re.search(r"reject\((reset|unreachable|prohibited)\)", raw)
            if m:
                self.query_one("#f-action", Select).value = f"reject({m.group(1)})"
            m = re.search(r"log\(([^)]*)\)", raw)
            if m:
                self.query_one("#f-action", Select).value = "log"
                self.query_one("#f-logprefix", Input).value = m.group(1).strip()
            m = re.search(r"--to-(?:destination|source)\s+(\S+)", raw)
            if m:
                target = m.group(1)
                host_part, _, svc_part = target.partition(":")
                if host_part:
                    self._set_select_value(self.query_one("#f-to-host", Select),
                                           host_part)
                if svc_part:
                    self._set_select_value(self.query_one("#f-to-svc", Select),
                                           svc_part)
        finally:
            self._syncing = False
        self._update_conditional_rows()

    def _to_host_options(self) -> set:
        return {f"host({h})" for h in self.hosts}

    def _to_svc_options(self) -> set:
        return {f"service({s})" for s in self.services}

    def _rebuild_raw(self) -> None:
        chain = self.query_one("#f-chain", Select).value or "INPUT"
        iface = self.query_one("#f-iface").value  # Input or Select
        src = self.query_one("#f-src", Select).value or ""
        dst = self.query_one("#f-dst", Select).value or ""
        svc = self.query_one("#f-svc", Select).value or ""
        action = self.query_one("#f-action", Select).value or "ACCEPT"
        to_host = self.query_one("#f-to-host", Select).value or ""
        to_svc = self.query_one("#f-to-svc", Select).value or ""
        to = to_host + (f":{to_svc}" if to_svc else "")
        extra = self.query_one("#f-extra", Input).value
        logprefix = self.query_one("#f-logprefix", Input).value
        self.query_one("#f-raw", TextArea).text = build_rule(
            chain, iface, src, dst, svc, action, to, extra, logprefix)

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._syncing:
            return
        if event.input.id in ("f-iface", "f-extra", "f-logprefix"):
            self._rebuild_raw()

    def on_select_changed(self, event: Select.Changed) -> None:
        if self._syncing:
            return
        if event.value == CUSTOM and event.select.id in (
                "f-src", "f-dst", "f-iface", "f-svc"):
            # "(custom ...)": ask for a raw value; do NOT rebuild the raw
            # text with the sentinel (it still holds the previous value)
            self._open_custom_value(event.select.id)
            return
        if event.select.id in ("f-chain", "f-action", "f-svc",
                               "f-to-host", "f-to-svc", "f-src", "f-dst",
                               "f-iface"):
            self._rebuild_raw()
        if event.select.id == "f-action":
            self._update_conditional_rows()

    def _open_custom_value(self, wid: str) -> None:
        """'(custom ...)' picked in Source/Dest/Iface/Service: prompt for a
        value."""
        if wid == "f-iface":
            title, placeholder = "Interface value", "e.g. eth0, vlan10"
        elif wid == "f-src":
            title, placeholder = ("Source value (db entry or raw IP/address)",
                                  "e.g. 192.168.1.77, host(x), network(y)")
        elif wid == "f-dst":
            title, placeholder = ("Dest value (db entry or raw IP/address)",
                                  "e.g. 192.168.1.77, host(x), network(y)")
        else:  # f-svc
            title, placeholder = ("Service value (db entry or raw name)",
                                  "e.g. ssh, https, or dservices(a,b)")
        self.app.push_screen(
            Prompt(title, value=self._current_field_value(wid),
                   placeholder=placeholder),
            lambda res, w=wid: self._on_custom_value(w, res))

    def _current_field_value(self, wid: str) -> str:
        """The value the field had before '(custom ...)' was picked: the raw
        text is untouched at this point, so parse it."""
        import re
        raw = self.query_one("#f-raw", TextArea).text
        if wid == "f-src":
            m = re.search(r"-s\s+(\S+)", raw)
        elif wid == "f-dst":
            m = (re.search(r"--destination\s+(\S+)", raw)
                 or re.search(r"-d\s+(\S+)", raw))
        elif wid == "f-svc":
            m = (re.search(r"dservices\(([^)]+)\)", raw)
                 or re.search(r"dservice\(([^)]+)\)", raw))
        else:  # f-iface
            m = re.search(r"-i\s+(\S+)", raw)
        return m.group(1) if m else ""

    def _on_custom_value(self, wid: str, res) -> None:
        """Apply the custom value, or restore the previous one on cancel."""
        sel = self.query_one(f"#{wid}", Select)
        value = (res or "").strip()
        if not value:
            self._set_select_value(sel, self._current_field_value(wid))
            return
        self._set_select_value(sel, value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def action_save(self) -> None:
        # the table comes from the tab the rule was edited in; the editor's
        # self.table was set by the caller (active tab's table on add, the
        # rule's own table on edit - which matches the tab it was opened from)
        proto = self.query_one("#f-proto", Select).value or "4"
        text = self.query_one("#f-raw", TextArea).text.strip()
        self.dismiss({"table": self.table, "proto": proto, "text": text})

    def action_cancel(self) -> None:
        self.dismiss(None)

    # -- add a db entry without leaving the editor --------------------------
    def action_add_db_entry(self) -> None:
        self.app.push_screen(
            Prompt("Add db entry (section:key=value)",
                   placeholder="services:name=port/proto"),
            self._on_add_db_entry)

    def _on_add_db_entry(self, text) -> None:
        if not text or ":" not in text or "=" not in text:
            return
        section, kv = text.split(":", 1)
        key, value = kv.split("=", 1)
        section = section.strip()
        key = key.strip()
        value = value.strip()
        if section not in ("services", "hosts", "networks", "hostgroups",
                           "networkgroups", "servicegroups"):
            self.notify(f"Unknown db section '{section}'", severity="error")
            return
        self.app._add_db_entry_direct(section, key, value)
        # refresh this editor's db and dropdowns
        self.db = self.app.db
        self.services = list(self.db.services)
        self.hosts = list(self.db.hosts)
        self.networks = list(self.db.networks)
        self.hostgroups = list(self.db.hostgroups)
        self.networkgroups = list(self.db.networkgroups)
        self._refresh_db_dropdowns()
        self.notify(f"Added {section}:{key}")

    def _refresh_db_dropdowns(self) -> None:
        """Rebuild the db-backed dropdowns, preserving current values
        (raw values that are not db entries are re-added as options)."""
        for wid, opts in (
            ("#f-svc", [("(none)", "")] + [(s, s) for s in self.services]
             + [("(custom ...)", CUSTOM)]),
            ("#f-to-host", [("(none)", "")]
             + [(f"host({h})", f"host({h})") for h in self.hosts]),
            ("#f-to-svc", [("(none)", "")]
             + [(f"service({s})", f"service({s})") for s in self.services]),
        ):
            sel = self.query_one(wid, Select)
            cur = sel.value
            sel.set_options(opts)
            self._set_select_value(sel, cur)
        for wid in ("#f-src", "#f-dst"):
            sel = self.query_one(wid, Select)
            cur = sel.value
            sel.set_options(self._source_options())
            # re-add raw values (plain IPs etc.) that are not db entries
            self._set_select_value(sel, cur)

    # -- form navigation ----------------------------------------------------
    FIELD_IDS = ("f-proto", "f-chain", "f-iface", "f-src",
                 "f-dst", "f-svc", "f-action", "f-to-host", "f-to-svc",
                 "f-logprefix", "f-extra", "f-raw")

    def _fields(self) -> list:
        return [self.query_one(f"#{wid}") for wid in self.FIELD_IDS]

    def action_next_field(self) -> None:
        fields = self._fields()
        if not fields:
            return
        current = self.focused
        if current in fields:
            fields[(fields.index(current) + 1) % len(fields)].focus()
        else:
            fields[0].focus()

    def action_prev_field(self) -> None:
        fields = self._fields()
        if not fields:
            return
        current = self.focused
        if current in fields:
            fields[(fields.index(current) - 1) % len(fields)].focus()
        else:
            fields[-1].focus()

    # -- tab: move between the main components -----------------------------
    def on_key(self, event) -> None:
        if event.key == "tab":
            self._focus_component(self._current_component() + 1)
            event.stop()
        elif event.key == "shift+tab":
            self._focus_component(self._current_component() - 1)
            event.stop()

    def _current_component(self) -> int:
        """0=Rule(builder) 1=Save 2=Cancel 3=Raw."""
        f = self.focused
        if f is None:
            return 0
        if f.id == "btn-save":
            return 1
        if f.id == "btn-cancel":
            return 2
        if f.id == "f-raw":
            return 3
        return 0  # any builder field

    def _focus_component(self, idx: int) -> None:
        idx %= 4
        if idx == 0:
            self.query_one("#f-proto").focus()
        elif idx == 1:
            self.query_one("#btn-save").focus()
        elif idx == 2:
            self.query_one("#btn-cancel").focus()
        else:
            self.query_one("#f-raw").focus()


# ---------------------------------------------------------------------------
# simple text-input modal
# ---------------------------------------------------------------------------

class Prompt(ModalScreen):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, value: str = "", placeholder: str = "") -> None:
        super().__init__()
        self._title = title
        self._value = value
        self._placeholder = placeholder

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="modal-title")
        yield Input(self._value, placeholder=self._placeholder, id="prompt-input")
        with Horizontal(id="modal-buttons"):
            yield Button("OK", variant="primary", id="btn-ok")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ok":
            self.dismiss(self.query_one("#prompt-input", Input).value)
        elif event.button.id == "btn-cancel":
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter accepts the change (same as clicking OK)."""
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommitSelect(NavSelect):
    """NavSelect that announces a picked option even when it equals the
    current value. The stock Select only posts Changed when the value
    differs, so picking the already-selected option would otherwise close
    the overlay but leave the modal open."""

    class Commit(Message):
        def __init__(self, value) -> None:
            super().__init__()
            self.value = value

    class Cancel(Message):
        pass

    def on_select_overlay_update_selection(self, event) -> None:
        """An option was picked in the overlay: post Commit with its value.
        Runs alongside Select's own handler (message.stop() only stops
        bubbling to parents, not sibling handlers on the same widget)."""
        value = self._options[event.option_index][1]
        self.post_message(self.Commit(value))

    def on_select_overlay_dismiss(self, event) -> None:
        """Escape on the open dropdown: cancel the whole modal (one press)."""
        if not event.lost_focus:
            self.post_message(self.Cancel())


class SelectPrompt(ModalScreen):
    """Dropdown of valid options (for global settings). Opens in place at
    the edited row when a position is given; escape cancels in one press."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, options: list, value: str = "",
                 position: tuple[int, int] | None = None) -> None:
        super().__init__()
        self._title = title
        self._options = options
        self._value = value
        self._position = position

    def compose(self) -> ComposeResult:
        if not self._position:
            yield Static(self._title, classes="modal-title")
        yield CommitSelect(self._options, value=self._value, id="sel-option",
                           classes="fselect -textual-compact", allow_blank=False)

    def on_mount(self) -> None:
        sel = self.query_one("#sel-option", CommitSelect)
        sel.add_class("-textual-compact")
        if self._position:
            x, y = self._position
            sel.styles.offset = (x, y)
            sel.styles.width = 20
        # open the dropdown immediately, like the rule editor fields
        self.call_after_refresh(sel.action_show_overlay)

    def on_commit_select_commit(self, event) -> None:
        self.dismiss(event.value)

    def on_commit_select_cancel(self, event) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# unsaved-changes confirmation modal

class ConfirmSwitch(ModalScreen):
    """Confirm switching host with unsaved changes (current host edits
    would be lost; db edits are shared and persist)."""

    BINDINGS = [
        Binding("escape", "no", "Cancel"),
        Binding("y", "yes", "Switch"),
        Binding("n", "no", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("Unsaved changes - switch host?\n"
                     "The current host's edits will be lost.",
                     classes="modal-title")
        with Horizontal(id="modal-buttons"):
            yield Button("Switch", variant="error", id="btn-switch")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-switch":
            self.dismiss(True)
        elif event.button.id == "btn-cancel":
            self.dismiss(False)

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class ConfirmQuit(ModalScreen):
    """Unsaved-changes confirmation, shown as a prominent centered dialog."""

    CSS = """
    ConfirmQuit {
        align: center middle;
    }
    ConfirmQuit > Vertical {
        width: auto;
        height: auto;
        border: round $error;
        background: $surface;
        padding: 1 2;
    }
    ConfirmQuit > Vertical > * {
        width: auto;
    }
    ConfirmQuit #modal-buttons {
        align-horizontal: center;
    }
    """

    BINDINGS = [
        Binding("escape", "no", "Cancel"),
        Binding("y", "yes", "Quit"),
        Binding("n", "no", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="quit-dialog"):
            yield Static("Unsaved changes - quit anyway?", classes="modal-title")
            with Horizontal(id="modal-buttons"):
                yield Button("Quit", variant="error", id="btn-quit")
                yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-quit":
            self.dismiss(True)
        elif event.button.id == "btn-cancel":
            self.dismiss(False)

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


# ---------------------------------------------------------------------------
# validation results modal
# ---------------------------------------------------------------------------

class ValidationReport(ModalScreen):
    """Validation results; enter on an issue closes the window and jumps
    to the rule it refers to."""

    CSS = """
    ValidationReport #report-list {
        height: 20;
    }
    """

    BINDINGS = [Binding("escape", "close", "Close"), Binding("q", "close", "Close")]

    def __init__(self, issues) -> None:
        super().__init__()
        self.issues = issues
        self.entries = list(self._entries())

    def _entries(self):
        """Yield (issue, level, message) for every error and warning."""
        for i in self.issues:
            for e in i.errors:
                yield i, "ERROR", e
            for w in i.warnings:
                yield i, "WARN", w

    def compose(self) -> ComposeResult:
        n_err = sum(1 for i in self.issues for _ in i.errors)
        n_warn = sum(1 for i in self.issues for _ in i.warnings)
        yield Static(f"Validation: {n_err} error(s), {n_warn} warning(s)",
                     classes="modal-title")
        items = [ListItem(Label(self._item_text(i, l, m)))
                 for i, l, m in self.entries]
        if not items:
            items = [ListItem(Label("No issues found."))]
        yield ListView(*items, id="report-list")
        with Horizontal(id="modal-buttons"):
            yield Button("Close", id="btn-close")

    def _item_text(self, issue, level, message) -> str:
        if issue.text:
            return (f"{level} [{issue.section}] {issue.table}{issue.proto}: "
                    f"{issue.text}  --  {message}")
        return f"{level} [{issue.section}]: {message}"

    def on_list_view_selected(self, event) -> None:
        """Enter on an issue: close and jump to its rule."""
        index = event.list_view.index
        if index is not None and index < len(self.entries):
            self.dismiss(self.entries[index][0])
        else:
            self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# generic output modal (deploy, git diff)

class OutputModal(ModalScreen):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("q", "close", "Close")]

    def __init__(self, title: str, text: str) -> None:
        super().__init__()
        self._title = title
        self._text = text

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="modal-title")
        yield TextArea(self._text, read_only=True, id="report")

    def action_close(self) -> None:
        self.dismiss(None)


class DeployModal(ModalScreen):
    """Modal showing the live output of the deploy command as it runs."""

    CSS = """
    DeployModal #deploy-output {
        height: 20;
    }
    """

    BINDINGS = [Binding("escape", "close", "Close"), Binding("q", "close", "Close")]

    def __init__(self, title: str) -> None:
        super().__init__()
        self._title = title
        self._chunks: list[str] = []

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="modal-title")
        yield TextArea("", read_only=True, id="deploy-output")
        with Horizontal(id="modal-buttons"):
            yield Button("Close", id="btn-close")

    def append(self, text: str) -> None:
        """Append output (called from the deploy worker)."""
        if not self.is_mounted:
            return
        self._chunks.append(text)
        ta = self.query_one("#deploy-output", TextArea)
        ta.text = "".join(self._chunks)
        ta.scroll_end(animate=False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class GitHistory(ModalScreen):
    """Git history for the host's ruleset file: pick a commit, view its
    diff (or full content) below, load that version (enter). Tab moves
    between the list and the box; the box scrolls when focused."""

    CSS = """
    GitHistory #commit-list {
        height: 1fr;
    }
    GitHistory #diff-view {
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close"),
        Binding("tab", "toggle_focus", "Toggle focus", show=False),
        Binding("shift+tab", "toggle_focus_reverse", "Toggle focus",
                show=False),
        Binding("enter", "load_version", "Load version", show=False),
        Binding("f", "toggle_view", "Diff/content", show=False),
    ]

    FOCUS_ORDER = ("#commit-list", "#diff-view", "#btn-load", "#btn-close")

    def __init__(self, host: str, fwdir: str) -> None:
        super().__init__()
        self.host = host
        self.fwdir = fwdir
        self.file = os.path.join(fwdir, host)
        # (hash, date, author, subject, added, removed); hash "" = working tree
        self.commits: list[list] = []
        self._show_content = False

    def compose(self) -> ComposeResult:
        yield Static(f"Git history: {self.host}", classes="modal-title")
        yield ListView(id="commit-list")
        yield Static("", id="diff-title")
        yield TextArea("", read_only=True, id="diff-view")
        with Horizontal(id="modal-buttons"):
            yield Button("Load version", id="btn-load")
            yield Button("Close", id="btn-close")
        yield Static("tab: cycle focus   enter: load version   f: diff/content   "
                     "esc: close", id="git-hint")

    def on_mount(self) -> None:
        self._load_commits()
        lv = self.query_one("#commit-list", ListView)
        if lv.children:
            lv.index = 0  # highlight the first entry (shows its diff)
        lv.focus()

    def _git(self, *args: str) -> tuple[str, str]:
        import subprocess
        try:
            proc = subprocess.run(
                ["git", "-C", self.fwdir, *args],
                capture_output=True, text=True, timeout=30)
            return proc.stdout, proc.stderr
        except Exception as e:
            return "", f"Error running git: {e}"

    def _repo_path(self) -> str:
        """The file path relative to the git repo root (for rev:path forms)."""
        out, _ = self._git("rev-parse", "--show-toplevel")
        root = out.strip()
        if root:
            return os.path.relpath(self.file, root)
        return self.file

    def _load_commits(self) -> None:
        lv = self.query_one("#commit-list", ListView)
        # working tree first (uncommitted changes)
        lv.append(ListItem(Label("(working tree)")))
        self.commits.append(["", "", "", "", 0, 0])
        out, _ = self._git("log", "--numstat",
                           "--format=%H%x09%ad%x09%an%x09%s",
                           "--date=short", "--", self.file)
        for line in out.strip().splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                h, date, author, subject = parts
                self.commits.append([h, date, author, subject, 0, 0])
            elif len(parts) == 3 and parts[0].isdigit() \
                    and parts[1].isdigit() and self.commits:
                self.commits[-1][4] = int(parts[0])
                self.commits[-1][5] = int(parts[1])
        for i, c in enumerate(self.commits):
            if not c[0]:
                continue
            h, date, author, subject, a, r = c
            head = "  (HEAD)" if i == 1 else ""
            lv.append(ListItem(Label(escape(
                f"{date}  {h[:8]}  {subject}  +{a} -{r}{head}"))))

    def on_list_view_highlighted(self, event) -> None:
        """Selection moved: show the diff/content for that entry."""
        index = event.list_view.index
        if index is not None and index < len(self.commits):
            self._show_diff(index)

    def _show_diff(self, index: int) -> None:
        h, date, author, subject, a, r = self.commits[index]
        if not h:
            out, err = self._git("diff", "--", self.file)
            text = out or err or "(no changes)"
            title = "working tree"
        elif self._show_content:
            out, err = self._git("show", f"{h}:{self._repo_path()}")
            text = out or err
            title = f"{h[:8]}  {date}  {author}  {subject}  [content]"
        else:
            out, err = self._git("show", h, "--", self.file)
            text = out or err
            title = f"{h[:8]}  {date}  {author}  {subject}  (+{a} -{r})"
        self.query_one("#diff-title", Static).update(escape(title))
        self.query_one("#diff-view", TextArea).text = text

    def action_toggle_view(self) -> None:
        """f: toggle the bottom box between diff and full file content."""
        self._show_content = not self._show_content
        lv = self.query_one("#commit-list", ListView)
        index = lv.index
        if index is not None and index < len(self.commits):
            self._show_diff(index)

    def on_list_view_selected(self, event) -> None:
        """Enter/click on a commit: load that version."""
        self.action_load_version()

    def action_load_version(self) -> None:
        lv = self.query_one("#commit-list", ListView)
        index = lv.index
        if index is None or index >= len(self.commits):
            return
        h, date, author, subject, a, r = self.commits[index]
        if not h:
            # working tree: load the current disk state (e.g. to get back
            # uncommitted changes after loading an older version)
            self.app.push_screen(
                ConfirmLoad("Load the current working tree?\n"
                            "Current edits will be replaced (undo available)."),
                lambda ok: self._do_load_working_tree() if ok else None)
            return
        self.app.push_screen(
            ConfirmLoad(f"Load version {h[:8]} ({subject})?\n"
                        "Current edits will be replaced (undo available)."),
            lambda ok: self._do_load(h) if ok else None)

    def _do_load_working_tree(self) -> None:
        try:
            with open(self.file) as fh:
                content = fh.read()
        except OSError as e:
            self.notify(f"Error reading file: {e}", severity="error")
            return
        self.dismiss({"commit": "working tree", "content": content})

    def _do_load(self, h: str) -> None:
        out, err = self._git("show", f"{h}:{self._repo_path()}")
        if err:
            self.notify(err.strip(), severity="error")
            return
        self.dismiss({"commit": h, "content": out})

    def action_toggle_focus(self) -> None:
        """Tab: cycle focus list -> diff -> buttons -> list."""
        self._focus_cycle(1)

    def action_toggle_focus_reverse(self) -> None:
        """Shift+tab: cycle focus the other way."""
        self._focus_cycle(-1)

    def _focus_cycle(self, step: int) -> None:
        idx = -1
        for i, wid in enumerate(self.FOCUS_ORDER):
            if self.focused is self.query_one(wid):
                idx = i
                break
        if idx < 0:
            self.query_one("#commit-list").focus()
            return
        self.query_one(self.FOCUS_ORDER[(idx + step) % len(self.FOCUS_ORDER)])\
            .focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-load":
            self.action_load_version()
        elif event.button.id == "btn-close":
            self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class ConfirmLoad(ModalScreen):
    """Confirm loading a git version (replaces the current ruleset)."""

    BINDINGS = [
        Binding("escape", "no", "Cancel"),
        Binding("y", "yes", "Load"),
        Binding("n", "no", "Cancel"),
    ]

    def __init__(self, title: str) -> None:
        super().__init__()
        self._title = title

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="modal-title")
        with Horizontal(id="modal-buttons"):
            yield Button("Load", variant="primary", id="btn-load")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-load":
            self.dismiss(True)
        elif event.button.id == "btn-cancel":
            self.dismiss(False)

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


# ---------------------------------------------------------------------------
# main app
# ---------------------------------------------------------------------------

class FirewallApp(App):
    TITLE = "Firewall TUI"
    CSS = """
    #topbar { height: 3; padding: 0 1; align-vertical: middle; }
    #host-select { width: 44; }
        .topbar-select { width: 44; }
    .topbar-btn { width: 6; height: 1; margin: 0 0 0 1; border: none; }
    #main-area { height: 1fr; }
    #main-area.-db-mode #tabs { display: none; }
    #main-area.-db-mode #db-view { display: block; }
    #filter-bar { display: none; height: 1; margin: 0 1; }
    #filter-bar.-show { display: block; }
    #db-view { height: 1fr; display: none; }
    TabbedContent { height: 1fr; }
    DataTable { height: 1fr; }
    #rules-header, #nat-header, #mangle-header { height: 1; text-style: bold; background: $panel; }
    #rules-view, #nat-view, #mangle-view { height: 1fr; }
    #statusbar { height: 1; background: $panel; color: $text; padding: 0 1; }
    .field { margin: 0 1 1 1; }
    #builder { width: 55%; }
    #rawcol { width: 45%; }
    .frow { height: 1; margin: 0 0 1 1; }
    .fhint { margin: 0 0 1 1; text-style: dim; }
    .natrow { display: none; }
    .natrow.-show { display: block; }
    .logrow { display: none; }
    .logrow.-show { display: block; }
    .flabel { width: 22; padding: 0 1 0 0; }
    .fselect { width: 1fr; }
    .finput { width: 1fr; }
    #rawcol TextArea { height: 12; }
    #modal-buttons { height: 3; align-horizontal: left; padding: 0 1; }
    #modal-buttons Button { margin: 0 1; }
    .modal-title { padding: 1; text-style: bold; }
    #report { height: 20; }
    """

    BINDINGS = [
        Binding("a", "add", "Add"),
        Binding("e", "edit", "Edit"),
        Binding("d", "delete", "Delete"),
        Binding("n", "new_section", "New section"),
        Binding("v", "validate", "Validate"),
        Binding("g", "preview", "Preview"),
        Binding("p", "deploy", "Deploy"),
        Binding("i", "git_diff", "Git diff"),
        Binding("ctrl+z", "undo", "Undo"),
        Binding("ctrl+s", "save", "Save"),
        Binding("q", "quit", "Quit"),
        Binding("escape", "focus_tabs", "Back to tabs", show=False),
    ]

    def __init__(self, fwdir: str | None = None,
                 includedir: str | None = None,
                 config_path: str | None = None) -> None:
        super().__init__()
        cfg = load_config(config_path)
        fw = cfg["firewall"]
        self.fwdir = fwdir or fw["dir"]
        self.includedir = includedir or fw["includedir"]
        self.db_path = fw["db"]
        self.deploy_command = fw["deploy_command"]
        self.deploy_env = cfg["env"]
        self.explore_dir = fw["explore_dir"]
        self.firewall_type = fw["firewall_type"]
        self.hosts: list[str] = []
        self.lines: list[parser.Line] = []
        self.dblines: list[parser.DbLine] = []
        self.db = expand.Db()
        self.current_host: str | None = None
        self.current_dbsection: str | None = None
        self.rules_view: RulesView | None = None
        self.nat_view: RulesView | None = None
        self.mangle_view: RulesView | None = None
        self.db_view: DbView | None = None
        self.dbrowmap: dict = {}    # db table: row_key -> kind info
        self.dirty = False
        self.undo_stack: list = []
        self.db_mode = False
        self._pending_host: str | None = None

    # -- setup -------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="topbar"):
            yield HostSelect([("", "")], id="host-select", allow_blank=False,
                             classes="topbar-select")
            yield Button("db", id="db-button", classes="topbar-btn")
        with Vertical(id="main-area"):
            yield Input(placeholder="Filter...", id="filter-bar")
            with TabbedContent(id="tabs"):
                with TabPane("Rules", id="tab-rules"):
                    yield Static("", id="rules-header", classes="colheader")
                    yield RulesView(id="rules-view")
                with TabPane("NAT", id="tab-nat"):
                    yield Static("", id="nat-header", classes="colheader")
                    yield RulesView(id="nat-view")
                with TabPane("Mangle", id="tab-mangle"):
                    yield Static("", id="mangle-header", classes="colheader")
                    yield RulesView(id="mangle-view")
                with TabPane("Global", id="tab-global"):
                    yield NavDataTable(id="global-table", zebra_stripes=True,
                                       cursor_type="row")
            yield DbView(id="db-view")
        yield Static("", id="statusbar")
        yield Footer()

    def on_mount(self) -> None:
        self._load_hosts()
        self._load_db()
        self.rules_view = self.query_one("#rules-view", RulesView)
        self.nat_view = self.query_one("#nat-view", RulesView)
        self.mangle_view = self.query_one("#mangle-view", RulesView)
        self.host_select = self.query_one("#host-select", Select)
        self.tabs = self.query_one("#tabs", TabbedContent)
        for wid in ("#rules-header", "#nat-header", "#mangle-header"):
            self.query_one(wid, Static).update(header_text())
        self.query_one("#filter-bar", Input).add_class("-textual-compact")
        gt = self.query_one("#global-table", DataTable)
        gt.add_column("Option", width=16)
        gt.add_column("value", width=40)
        gt.add_column("state", width=10)
        self.db_view = self.query_one("#db-view", DbView)
        sel = self.query_one("#host-select", Select)
        sel.add_class("-textual-compact")
        sel.set_options([(h, h) for h in self.hosts])
        if self.hosts:
            sel.value = self.hosts[0]
            self._load_ruleset(self.hosts[0])
        self._populate_db()
        self._update_status()
        self.rules_view.focus()

    def _load_hosts(self) -> None:
        self.hosts = sorted(
            f for f in os.listdir(self.fwdir)
            if os.path.isfile(os.path.join(self.fwdir, f))
            and not f.startswith(".")
            and f != "db"
        )

    def _host_interfaces(self, host: str) -> list[str]:
        """Interface names from the last explorer run for a host (strips
        veth peer suffixes like lnw@if55 -> lnw). Empty when unavailable."""
        path = os.path.join(self.explore_dir, host, "interfaces")
        try:
            with open(path) as fh:
                seen: set[str] = set()
                out: list[str] = []
                for line in fh:
                    name = line.strip().split("@", 1)[0]
                    if name and name not in seen:
                        seen.add(name)
                        out.append(name)
                return out
        except OSError:
            return []

    def _current_ifaces(self) -> list[str]:
        """Interfaces for the current host (empty when the feature is off)."""
        if not self.explore_dir or not self.current_host:
            return []
        return self._host_interfaces(self.current_host)

    def _load_db(self) -> None:
        if os.path.exists(self.db_path):
            with open(self.db_path) as fh:
                self.dblines = parser.parse_db(fh.read())
            self.db = expand.Db(self.dblines)

    def _rebuild_db(self) -> None:
        self.db = expand.Db(self.dblines)

    def _load_with_includes(self, path: str, out: list) -> None:
        """Parse a rules file, splicing [#include] content inline.
        Every line is tagged with the file it came from, so edits can be
        written back to the right file."""
        with open(path) as fh:
            lines = parser.parse_rules(fh.read())
        for l in lines:
            l.source = path
            if l.kind == "include":
                out.append(l)
                inc_path = os.path.join(self.includedir, l.name)
                if os.path.isfile(inc_path):
                    self._load_with_includes(inc_path, out)
            else:
                out.append(l)

    def _load_ruleset(self, host: str) -> None:
        path = os.path.join(self.fwdir, host)
        self.lines = []
        self._load_with_includes(path, self.lines)
        self.current_host = host
        self.dirty = False
        self._populate_rules(reset_collapsed=True)
        self._populate_global()
        self._update_status()

    # -- table population ---------------------------------------------------
    def _populate_rules(self, reset_collapsed: bool = False) -> None:
        """Populate the three table tabs (Rules/filter, NAT, Mangle). Each
        tab shows only its own table's rules; implicit [global] rules are
        filter-only and appear in the Rules tab."""
        self.rules_view.set_rows(
            self._build_rows({"filter"}), reset_collapsed=reset_collapsed)
        self.nat_view.set_rows(
            self._build_rows({"nat"}), reset_collapsed=reset_collapsed)
        self.mangle_view.set_rows(
            self._build_rows({"mangle"}), reset_collapsed=reset_collapsed)

    def _build_rows(self, tables: set[str]) -> list[tuple]:
        """Rows for one table tab: implicit filter sections (Rules tab only),
        real sections, and the rules of this table within them. Sections are
        included even when empty for this table (the view's hide_empty flag
        decides whether they show)."""
        rows: list[tuple] = []
        globals_ = {l.key: l.value for l in parser.global_lines(self.lines)}
        show_implicit = "filter" in tables
        if show_implicit:
            top_groups, bottom_groups = implicit.implicit_rules(globals_)
            # implicit rules that come FIRST in the chain (loopback,
            # established, icmp drop when disabled)
            for group, rdicts in top_groups:
                rows.append(("implicit-section", group))
                for r in rdicts:
                    rows.append(("implicit", r))
        # real sections (and [#include] bars), walking the spliced line list
        for l in self.lines:
            if l.kind == "include":
                inc_path = os.path.join(self.includedir, l.name)
                rows.append(("include", l.name,
                             inc_path if os.path.isfile(inc_path) else None))
                continue
            if l.kind == "section" and l.name == "global":
                continue  # [global] is shown as the Global tab
            if l.kind == "section":
                rows.append(("section", l.name, l.source))
                for r in parser.rules_in_section(self.lines, l):
                    if r.table not in tables:
                        continue
                    rows.append(("rule", r, l.name,
                                 columns.rule_columns(r.value, self.db)))
        # implicit rules that come LAST (icmp allow, log, policy)
        if show_implicit:
            for group, rdicts in bottom_groups:
                rows.append(("implicit-section", group))
                for r in rdicts:
                    rows.append(("implicit", r))
        return rows

    def _populate_global(self) -> None:
        """Show every global key: file values, or the manifest default for
        keys not present in the file (marked '(default)')."""
        t = self.query_one("#global-table", DataTable)
        t.clear()
        present = {l.key: l.value for l in parser.global_lines(self.lines)}
        for key in GLOBAL_ORDER:
            if key in present:
                t.add_row(key, present[key], "")
            else:
                t.add_row(key, self._global_default(key), "(default)")

    def _global_default(self, key: str) -> str:
        """Effective default for a global key (policy_* inherits policy,
        log_* inherits log)."""
        if key.startswith("policy_"):
            present = {l.key: l.value for l in parser.global_lines(self.lines)}
            return present.get("policy", GLOBAL_DEFAULTS["policy"])
        if key.startswith("log_"):
            present = {l.key: l.value for l in parser.global_lines(self.lines)}
            return present.get("log", "")
        return GLOBAL_DEFAULTS[key]

    def _insert_global(self, key: str, value: str) -> None:
        """Insert a global key=value line after the [global] header (creating
        the section at the top if the file has none)."""
        host = os.path.join(self.fwdir, self.current_host)
        line = parser.Line(raw=f"{key}={value}", kind="global", key=key,
                           value=value)
        line.source = host
        for i, l in enumerate(self.lines):
            if l.kind == "section" and l.name == "global":
                j = i
                while j + 1 < len(self.lines) \
                        and self.lines[j + 1].kind == "global":
                    j += 1
                self.lines.insert(j + 1, line)
                return
        header = parser.Line(raw="[global]", kind="section", name="global")
        header.source = host
        self.lines.insert(0, header)
        self.lines.insert(1, line)

    def _populate_db(self) -> None:
        rows: list[tuple] = []
        for s in parser.db_sections(self.dblines):
            rows.append(("dbsection", s))
            for e in parser.db_entries(self.dblines, s):
                idx = self.dblines.index(e)
                rows.append(("dbentry", e.key, e.value, s, idx))
        self.db_view.set_rows(rows)

    # -- selection ----------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "db-button":
            self._set_db_mode(not self.db_mode)

    def _set_db_mode(self, on: bool, refocus: bool = True) -> None:
        """Show the global db view (db is not per-ruleset)."""
        self.db_mode = on
        self.query_one("#main-area").set_class(on, "-db-mode")
        if on:
            self.db_view.focus()
        elif refocus:
            self._focus_tabs()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "host-select":
            if event.value is Select.NULL or not event.value:
                return  # placeholder/blank selection: ignore
            if event.value == self.current_host:
                return  # re-selected the current host (e.g. after a
                        # cancelled switch): do not reload it
            if self.dirty:
                # confirm before discarding the current host's edits
                self._pending_host = event.value
                self.push_screen(ConfirmSwitch(), self._on_switch_confirm)
                return
            self._switch_host(event.value)

    def _switch_host(self, host: str) -> None:
        self._set_db_mode(False)
        self._load_ruleset(host)
        self.query_one("#tabs", TabbedContent).active = "tab-rules"

    def _on_switch_confirm(self, result) -> None:
        if result:
            self._switch_host(self._pending_host)
        else:
            # revert the selector to the current host; on_select_changed
            # ignores the re-selection (value == current_host), so the
            # unsaved edits are preserved
            self.host_select.value = self.current_host

    def _active_tab(self) -> str:
        tab = self.query_one("#tabs", TabbedContent).active or ""
        return tab.split("-", 1)[1] if tab.startswith("tab-") else "rules"

    def _active_rules_view(self) -> RulesView | None:
        """The RulesView of the active table tab (Rules/NAT/Mangle), else None."""
        tab = self._active_tab()
        if tab == "rules":
            return self.rules_view
        if tab == "nat":
            return self.nat_view
        if tab == "mangle":
            return self.mangle_view
        return None

    # -- keyboard navigation ------------------------------------------------
    def on_key(self, event) -> None:
        """Vertical navigation: host-select <-> tabs <-> content."""
        focused = self.focused
        if event.key == "down":
            if focused is self.host_select:
                self._focus_tabs()
                event.stop()
            elif isinstance(focused, ContentTabs):
                self._focus_content()
                event.stop()
            elif focused is self.query_one("#db-button", Button):
                # down from the db button: back to the db view (or the tabs)
                if self.db_mode:
                    self.db_view.focus()
                else:
                    self._focus_tabs()
                event.stop()
        elif event.key == "up":
            if isinstance(focused, ContentTabs):
                self.host_select.focus()
                event.stop()
        elif event.key == "right":
            if focused is self.host_select:
                self.query_one("#db-button", Button).focus()
                event.stop()
        elif event.key == "left":
            if focused is self.query_one("#db-button", Button):
                self.host_select.focus()
                event.stop()

    def on_host_select_focused(self, event) -> None:
        """Focusing the host selector while in db mode returns to the ruleset."""
        if self.db_mode:
            self._set_db_mode(False, refocus=False)

    def _focus_tabs(self) -> None:
        """Focus the tab strip (Rules | NAT | Mangle | Global)."""
        self.tabs.query_one(ContentTabs).focus()

    def _focus_content(self) -> None:
        """Focus the content of the active tab (or the db view)."""
        if self.db_mode:
            if self.db_view:
                self.db_view.focus()
            return
        tab = self._active_tab()
        if tab in ("rules", "nat", "mangle"):
            view = self._active_rules_view()
            if view:
                view.focus()
        elif tab == "global":
            self.query_one("#global-table", DataTable).focus()

    def action_focus_tabs(self) -> None:
        """esc: close the filter bar, else back to the menu (top bar in db
        mode, tabs otherwise)."""
        if self.focused is self.query_one("#filter-bar"):
            self._hide_filter(clear=True)
            return
        if self.db_mode:
            self.host_select.focus()
        else:
            self._focus_tabs()

    def action_quit(self) -> None:
        """Quit, warning about unsaved changes."""
        if isinstance(self.screen, ConfirmQuit):
            return
        if self.dirty:
            self.push_screen(ConfirmQuit(), self._on_quit_confirm)
        else:
            self.exit()

    def _on_quit_confirm(self, result) -> None:
        if result:
            self.exit()

    def on_rules_view_activate(self, event) -> None:
        """Enter pressed on a rule: open the editor (like 'e')."""
        if self._active_tab() in ("rules", "nat", "mangle"):
            self._edit_rule()

    def on_rules_view_navigate_up(self, event) -> None:
        """Up at the top of the rules view: focus the menu."""
        self._focus_tabs()

    def on_rules_view_search_request(self, event) -> None:
        """/ pressed: show the live filter bar."""
        self._show_filter()

    def on_db_view_search_request(self, event) -> None:
        """/ pressed in the db view: show the live filter bar."""
        self._show_filter()

    def _show_filter(self) -> None:
        """Show the filter bar, prefilled with the active view's filter."""
        bar = self.query_one("#filter-bar", Input)
        if self.db_mode:
            current = self.db_view.filter_text if self.db_view else ""
        else:
            view = self._active_rules_view()
            current = view.filter_text if view else ""
        bar.value = current
        bar.add_class("-show")
        bar.focus()

    def _hide_filter(self, clear: bool = True) -> None:
        """Hide the filter bar; optionally clear the active filter."""
        bar = self.query_one("#filter-bar", Input)
        bar.remove_class("-show")
        if clear:
            if self.db_mode:
                if self.db_view:
                    self.db_view.set_filter("")
            else:
                view = self._active_rules_view()
                if view:
                    view.set_filter("")
        self._update_status()
        self._focus_content()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live filter as the user types."""
        if event.input.id == "filter-bar":
            if self.db_mode:
                if self.db_view:
                    self.db_view.set_filter(event.value)
            else:
                view = self._active_rules_view()
                if view:
                    view.set_filter(event.value)
            self._update_status()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter in the filter bar: close it, keep the filter."""
        if event.input.id == "filter-bar":
            self._hide_filter(clear=False)

    def on_nav_data_table_navigate_up(self, event) -> None:
        """Up at the top of a table (global/db): focus the menu."""
        self._focus_tabs()

    def on_nav_data_table_activate(self, event) -> None:
        """Enter on a Global row: open the editor (same as 'e')."""
        if self._active_tab() == "global":
            self._edit_global()

    def on_db_view_activate(self, event) -> None:
        """Enter on a db row: edit the entry (like 'e')."""
        if self.db_mode:
            self._edit_db_entry()

    def on_db_view_navigate_up(self, event) -> None:
        """Up at the top of the db view: focus the db button."""
        self.query_one("#db-button", Button).focus()

    def _selected_row(self) -> tuple:
        """Return (index, row_info) of the selected row in the active view."""
        if self.db_mode:
            if not self.db_view or not self.db_view.rows:
                return None, None
            idx = self.db_view.selected
            return idx, self.db_view.rows[idx]
        if self._active_tab() in ("rules", "nat", "mangle"):
            view = self._active_rules_view()
            if not view or not view.rows:
                return None, None
            idx = view.selected
            return idx, view.rows[idx]
        return None, None

    # -- add / edit / delete ------------------------------------------------
    def action_add(self) -> None:
        if self.db_mode:
            self._add_db_entry()
            return
        tab = self._active_tab()
        if tab in ("rules", "nat", "mangle"):
            self._add_rule()
        elif tab == "global":
            self._add_global()

    def _add_rule(self) -> None:
        rk, info = self._selected_row()
        section = None
        section_source = None
        if info and info[0] == "rule":
            section = info[2]
            section_source = info[1].source
        elif info and info[0] == "section":
            section = info[1]
            section_source = info[2]
        if section is None:
            # default to first real section in the host file
            host = os.path.join(self.fwdir, self.current_host)
            for l in self.lines:
                if l.kind == "section" and l.source == host:
                    section = l.name
                    section_source = l.source
                    break
            if section is None:
                for l in self.lines:
                    if l.kind == "section":
                        section = l.name
                        section_source = l.source
                        break
        if section is None:
            self.notify("No section to add a rule to; press 'n' to create one",
                        severity="warning")
            return
        view = self._active_rules_view()
        if view:
            view.expand_section(section)
        # new rules default to the active tab's table
        default_table = {"rules": "filter", "nat": "nat",
                         "mangle": "mangle"}.get(self._active_tab(), "filter")
        self.push_screen(RuleEditor(default_table, "4", db=self.db,
                                    ifaces=self._current_ifaces()),
                         lambda res, s=section, src=section_source:
                         self._on_rule_edited(s, src, res))

    def _on_rule_edited(self, section: str, section_source: str,
                        result) -> None:
        if not result:
            return
        self._snapshot()
        # find the section line (in the file it came from)
        for i, l in enumerate(self.lines):
            if (l.kind == "section" and l.name == section
                    and l.source == section_source):
                j = i
                while j + 1 < len(self.lines) and self.lines[j + 1].kind == "rule":
                    j += 1
                key = result["table"] + result["proto"]
                new_line = parser.Line(
                    raw=f"{key}={result['text']}", kind="rule", key=key,
                    value=result["text"], table=result["table"],
                    proto=result["proto"])
                new_line.source = section_source
                self.lines.insert(j + 1, new_line)
                break
        self.dirty = True
        self._populate_rules()
        # jump to the tab of the rule's table and select it there
        self._jump_to_rule(new_line, section)

    def action_edit(self) -> None:
        if self.db_mode:
            self._edit_db_entry()
            return
        tab = self._active_tab()
        if tab in ("rules", "nat", "mangle"):
            self._edit_rule()
        elif tab == "global":
            self._edit_global()

    def _edit_rule(self) -> None:
        rk, info = self._selected_row()
        if not info:
            return
        kind = info[0]
        if kind in ("implicit", "implicit-section"):
            self.notify("Implicit rules are generated by the [global] settings",
                        severity="warning")
            return
        if kind == "section":
            self.push_screen(
                Prompt("Rename section", value=info[1]),
                lambda res, old=info[1], src=info[2]:
                self._on_rename_section(old, src, res))
            return
        if kind == "rule":
            line = info[1]
            section = info[2]
            self.push_screen(RuleEditor(line.table, line.proto, line.value,
                                        db=self.db,
                                        ifaces=self._current_ifaces()),
                             lambda res, ln=line, s=section:
                             self._on_rule_edited_existing(ln, s, res))

    def _on_rule_edited_existing(self, line, section, result) -> None:
        if not result:
            return
        self._snapshot()
        line.table = result["table"]
        line.proto = result["proto"]
        line.value = result["text"]
        line.key = result["table"] + result["proto"]
        line.raw = line.render()
        self.dirty = True
        self._populate_rules()
        self._jump_to_rule(line, section)

    def _on_rename_section(self, old: str, src: str, name) -> None:
        if not name:
            return
        self._snapshot()
        for l in self.lines:
            if l.kind == "section" and l.name == old and l.source == src:
                l.name = name
                l.raw = l.render()
                break
        self.dirty = True
        self._populate_rules()
        view = self._active_rules_view()
        if view:
            view.select_section(name, src)

    def action_delete(self) -> None:
        if self.db_mode:
            self._delete_db_entry()
            return
        tab = self._active_tab()
        if tab in ("rules", "nat", "mangle"):
            self._delete_rule()
        elif tab == "global":
            self._delete_global()

    def _delete_rule(self) -> None:
        rk, info = self._selected_row()
        if not info:
            return
        self._snapshot()
        kind = info[0]
        if kind in ("implicit", "implicit-section"):
            self.notify("Implicit rules are generated by the [global] settings",
                        severity="warning")
            return
        if kind == "section":
            name = info[1]
            src = info[2]
            # remove the section header and its rules (fixes orphaned rules)
            to_remove = []
            for l in self.lines:
                if (l.kind == "section" and l.name == name
                        and l.source == src):
                    to_remove.append(l)
                    to_remove.extend(parser.rules_in_section(self.lines, l))
            self.lines = [l for l in self.lines
                          if not any(l is r for r in to_remove)]
            self.dirty = True
            self._populate_rules()
            return
        if kind == "rule":
            line = info[1]
            if line in self.lines:
                self.lines.remove(line)
            self.dirty = True
            self._populate_rules()

    # -- reordering ---------------------------------------------------------
    def _snapshot(self) -> None:
        """Push the current lines/dblines onto the undo stack."""
        import copy
        self.undo_stack.append((copy.deepcopy(self.lines),
                                copy.deepcopy(self.dblines)))
        if len(self.undo_stack) > 50:
            self.undo_stack.pop(0)

    def action_undo(self) -> None:
        """ctrl+z: restore the last snapshot."""
        if not self.undo_stack:
            self.notify("Nothing to undo", severity="warning")
            return
        self.lines, self.dblines = self.undo_stack.pop()
        self.db = expand.Db(self.dblines)
        self.dirty = True
        self._populate_rules()
        self._populate_global()
        self._populate_db()

    def on_rules_view_move_request(self, event) -> None:
        """ctrl+up/down: move the selected rule or section."""
        if self._active_tab() not in ("rules", "nat", "mangle"):
            return
        rk, info = self._selected_row()
        if not info:
            return
        view = self._active_rules_view()
        kind = info[0]
        if kind == "rule":
            moved = self._move_rule(info[1], event.direction)
            if moved and view:
                view.select_line(moved)
        elif kind == "section":
            for l in self.lines:
                if (l.kind == "section" and l.name == info[1]
                        and l.source == info[2]):
                    moved = self._move_section(l, event.direction)
                    if moved and view:
                        view.select_section(l.name, l.source)
                    break
        elif kind in ("implicit", "implicit-section"):
            self.notify("Implicit rules cannot be reordered",
                        severity="warning")

    def _move_rule(self, line, direction: str):
        """Move a rule up/down within its section. Returns the line if moved."""
        self._snapshot()
        idx = self.lines.index(line)
        step = 1 if direction == "down" else -1
        j = idx + step
        while 0 <= j < len(self.lines):
            l = self.lines[j]
            if l.kind == "rule":
                break
            if l.kind in ("section", "include"):
                return None  # at the section boundary: nothing to swap with
            j += step
        if not (0 <= j < len(self.lines)) or self.lines[j].kind != "rule":
            return None
        self.lines[idx], self.lines[j] = self.lines[j], self.lines[idx]
        self.dirty = True
        self._populate_rules()
        return line

    def _move_section(self, section_line, direction: str):
        """Move a section block (header + rules) up/down within its file.
        Does not cross include boundaries. Returns the line if moved."""
        self._snapshot()
        idx = self.lines.index(section_line)
        start = idx
        end = idx + 1
        while end < len(self.lines) and self.lines[end].kind == "rule":
            end += 1
        block = self.lines[start:end]
        # find the adjacent section in the same file (not crossing includes)
        step = 1 if direction == "down" else -1
        j = end if direction == "down" else start - 1
        target = None
        while 0 <= j < len(self.lines):
            l = self.lines[j]
            if l.kind == "include":
                break
            if l.kind == "section" and l.source == section_line.source:
                target = j
                break
            j += step
        if target is None:
            return None
        # target block end
        t_end = target + 1
        while t_end < len(self.lines) and self.lines[t_end].kind == "rule":
            t_end += 1
        # remove the block, then adjust the target indices
        del self.lines[start:end]
        if target > start:
            target -= (end - start)
            t_end -= (end - start)
        if direction == "down":
            self.lines[t_end:t_end] = block
        else:
            self.lines[target:target] = block
        self._normalize_section_spacing()
        self.dirty = True
        self._populate_rules()
        return section_line

    def _normalize_section_spacing(self) -> None:
        """After a section move, rebuild the line list so every section is
        preceded by exactly one blank line (blank lines are cosmetic; the
        manifest ignores them)."""
        new_lines = []
        for l in self.lines:
            if l.kind == "section" and l.name != "global":
                if new_lines and new_lines[-1].kind != "blank":
                    blank = parser.Line(raw="", kind="blank")
                    blank.source = l.source
                    new_lines.append(blank)
                new_lines.append(l)
            elif l.kind == "blank":
                continue  # re-added before sections below
            else:
                new_lines.append(l)
        while new_lines and new_lines[-1].kind == "blank":
            new_lines.pop()
        self.lines = new_lines

    def action_new_section(self) -> None:
        if self._active_tab() not in ("rules", "nat", "mangle"):
            self.notify("'n' works in the Rules, NAT and Mangle tabs",
                        severity="warning")
            return
        self.push_screen(Prompt("New section name",
                                placeholder="e.g. allow ssh from admin"),
                         self._on_new_section)

    def _on_new_section(self, name) -> None:
        if not name:
            return
        self._snapshot()
        host = os.path.join(self.fwdir, self.current_host)
        # ensure a blank line before the new section (readable layout)
        if self.lines and self.lines[-1].kind != "blank":
            blank = parser.Line(raw="", kind="blank")
            blank.source = host
            self.lines.append(blank)
        new_line = parser.Line(raw=f"[{name}]", kind="section", name=name)
        new_line.source = host
        self.lines.append(new_line)
        self.dirty = True
        self._populate_rules()

    # -- global tab ---------------------------------------------------------
    def _add_global(self) -> None:
        self.push_screen(Prompt("New global key=value",
                                placeholder="e.g. log=Unmatched traffic"),
                         self._on_global_kv)

    def _on_global_kv(self, kv) -> None:
        if not kv or "=" not in kv:
            return
        key, value = kv.split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in parser.GLOBAL_KEYS:
            self.notify(f"Unknown global key '{key}'", severity="error")
            return
        if key in GLOBAL_OPTIONS and value not in GLOBAL_OPTIONS[key]:
            self.notify(f"'{key}' must be one of: {', '.join(GLOBAL_OPTIONS[key])}",
                        severity="error")
            return
        if value == "(unset)":
            self.notify("'(unset)' is the default; leave the key out of the file",
                        severity="warning")
            return
        if any(l.kind == "global" and l.key == key for l in self.lines):
            self.notify(f"'{key}' is already set in this file; edit it instead",
                        severity="warning")
            return
        self._snapshot()
        self._insert_global(key, value)
        self.dirty = True
        self._populate_global()
        self._populate_rules()

    def _edit_global(self) -> None:
        t = self.query_one("#global-table", DataTable)
        if not t.row_count:
            return
        rk, _ = t.coordinate_to_cell_key(t.cursor_coordinate)
        key, value, _ = t.get_row(rk)
        if key in GLOBAL_OPTIONS:
            opts = [(v, v) for v in GLOBAL_OPTIONS[key]]
            if value not in [v for _, v in opts]:
                opts.append((value, value))  # e.g. the "(unset)" default
            self.push_screen(SelectPrompt(f"Edit {key}", opts, value=value,
                                          position=self._global_row_position(t)),
                             lambda res, k=key: self._on_global_kv_edit(k, res))
        else:
            self.push_screen(Prompt(f"Edit {key}", value=f"{key}={value}"),
                             lambda res, k=key: self._on_global_kv_edit(k, res))

    def _global_row_position(self, table) -> tuple[int, int] | None:
        """Screen position of the cursor row in the Global table, so the
        choice dropdown can open in place."""
        try:
            row_index = table.cursor_coordinate[0]
            region = table._get_row_region(row_index)
            x, y = table.region.x, table.region.y
            node = table.parent
            while node is not None and not isinstance(node, Screen):
                x += node.region.x
                y += node.region.y
                node = node.parent
            y += region.y - int(table.scroll_y)
            # land over the value column (key column is 16 wide + row label)
            return (x + 18, y)
        except Exception:
            return None

    def _on_global_kv_edit(self, old_key, kv) -> None:
        if not kv:
            return
        if "=" in kv:
            key, value = kv.split("=", 1)
            key, value = key.strip(), value.strip()
        else:
            # from SelectPrompt: just the value, keep the key
            key, value = old_key, kv.strip()
        if value == "(unset)":
            return  # keep the manifest default (no explicit setting)
        for l in self.lines:
            if l.kind == "global" and l.key == old_key:
                if l.key == key and l.value == value:
                    return  # no change (e.g. re-picked the current option)
                self._snapshot()
                l.key = key
                l.value = value
                l.raw = l.render()
                break
        else:
            # key not in the file yet (was showing its default): add it
            if value == self._global_default(key):
                return  # same as the default: no need to write it
            self._snapshot()
            self._insert_global(key, value)
        self.dirty = True
        self._populate_global()
        self._populate_rules()

    def _delete_global(self) -> None:
        t = self.query_one("#global-table", DataTable)
        if not t.row_count:
            return
        rk, _ = t.coordinate_to_cell_key(t.cursor_coordinate)
        key, _, state = t.get_row(rk)
        if state == "(default)":
            self.notify(f"'{key}' is not set in this file (using the default); "
                        "nothing to delete", severity="warning")
            return
        self._snapshot()
        self.lines = [l for l in self.lines
                      if not (l.kind == "global" and l.key == key)]
        self.dirty = True
        self._populate_global()
        self._populate_rules()

    # -- db tab -------------------------------------------------------------
    def _add_db_entry_direct(self, section: str, key: str, value: str) -> None:
        """Add a db entry (used from the rule editor)."""
        self._snapshot()
        for i, l in enumerate(self.dblines):
            if l.kind == "section" and l.section == section:
                j = i
                while j + 1 < len(self.dblines) \
                        and self.dblines[j + 1].kind == "entry":
                    j += 1
                self.dblines.insert(j + 1, parser.DbLine(
                    raw=f"{key}={value}", kind="entry",
                    section=section, key=key, value=value))
                break
        self.dirty = True
        self._rebuild_db()
        self._populate_db()

    def _add_db_entry(self) -> None:
        rk, info = self._selected_row()
        section = None
        if info and info[0] == "dbsection":
            section = info[1]
        elif info and info[0] == "dbentry":
            section = info[3]
        if section is None:
            sections = parser.db_sections(self.dblines)
            section = sections[0] if sections else None
        if section is None:
            self.notify("db file has no sections", severity="warning")
            return
        self.current_dbsection = section
        self.push_screen(Prompt(f"New {section} entry (key=value)",
                                placeholder="name=value"),
                         self._on_db_entry)

    def _on_db_entry(self, kv) -> None:
        if not kv or "=" not in kv:
            return
        self._snapshot()
        key, value = kv.split("=", 1)
        key, value = key.strip(), value.strip()
        for i, l in enumerate(self.dblines):
            if l.kind == "section" and l.section == self.current_dbsection:
                j = i
                while j + 1 < len(self.dblines) and self.dblines[j + 1].kind == "entry":
                    j += 1
                self.dblines.insert(j + 1, parser.DbLine(
                    raw=f"{key}={value}", kind="entry",
                    section=self.current_dbsection, key=key, value=value))
                break
        self.dirty = True
        self._rebuild_db()
        self._populate_db()

    def _edit_db_entry(self) -> None:
        rk, info = self._selected_row()
        if not info:
            return
        if info[0] == "dbsection":
            # expand the section and select its first entry
            self.db_view.expand_section(info[1])
            for i, row in enumerate(self.db_view.rows):
                if row[0] == "dbentry" and row[3] == info[1]:
                    self.db_view.selected = i
                    self.db_view._ensure_visible()
                    self.db_view.refresh()
                    info = self.db_view.rows[i]
                    break
        if not info or info[0] != "dbentry":
            self.notify("Select a db entry to edit", severity="warning")
            return
        e = self.dblines[info[4]]
        self.push_screen(Prompt(f"Edit {e.key}", value=f"{e.key}={e.value}"),
                         lambda res, old=e: self._on_db_entry_edit(old, res))

    def _on_db_entry_edit(self, old, kv) -> None:
        if not kv or "=" not in kv:
            return
        self._snapshot()
        key, value = kv.split("=", 1)
        old.key = key.strip()
        old.value = value.strip()
        old.raw = old.render()
        self.dirty = True
        self._rebuild_db()
        self._populate_db()

    def _delete_db_entry(self) -> None:
        rk, info = self._selected_row()
        if not info or info[0] != "dbentry":
            self.notify("Select a db entry to delete", severity="warning")
            return
        self._snapshot()
        e = self.dblines[info[4]]
        if e in self.dblines:
            self.dblines.remove(e)
        self.dirty = True
        self._rebuild_db()
        self._populate_db()

    # -- validate / save ----------------------------------------------------
    def action_validate(self) -> None:
        if not self.current_host:
            self.notify("Select a host ruleset to validate", severity="warning")
            return
        issues = expand.validate_rules(self.lines, self.db)
        gerrs = expand.validate_globals(self.lines)
        if gerrs:
            from .expand import RuleIssue
            issues.append(RuleIssue("global", "", "", "", gerrs, []))
        dupes = expand.validate_duplicate_sections(self.lines)
        if dupes:
            from .expand import RuleIssue
            issues.append(RuleIssue("(sections)", "", "", "", dupes, []))
        prowarns = expand.validate_proto_coverage(self.lines)
        if prowarns:
            from .expand import RuleIssue
            issues.append(RuleIssue("global", "", "", "", [], prowarns))
        self.push_screen(ValidationReport(issues), self._on_validation_result)

    def _on_validation_result(self, issue) -> None:
        """After closing validation: jump to the rule an issue refers to."""
        self.screen.refresh()  # defensive: modal pop can leave ghost content
        if issue is None or not issue.text:
            return
        for l in self.lines:
            if (l.kind == "rule" and l.value == issue.text
                    and l.table == issue.table and l.proto == issue.proto):
                self._jump_to_rule(l, issue.section)
                break

    def _jump_to_rule(self, line, section) -> None:
        """Switch to the tab of the rule's table and select the given rule."""
        tab = {"nat": "tab-nat", "mangle": "tab-mangle"}.get(
            line.table, "tab-rules")
        self._set_db_mode(False)
        self.query_one("#tabs", TabbedContent).active = tab
        view = self._active_rules_view()
        if view:
            view.set_filter("")  # clear any active filter
            view.expand_section(section)
            view.select_line(line)
        self._focus_content()

    def action_preview(self) -> None:
        """Show exactly what the __firewall type would generate for this
        host, by running its manifest in generate-only mode (FWTUI_GENERATE)."""
        if not self.current_host:
            self.notify("Select a host ruleset to preview", severity="warning")
            return
        host = self.current_host
        modal = DeployModal(f"Preview {host}")
        self.push_screen(modal)
        self.run_worker(self._preview_worker(host, modal), exclusive=True)

    async def _preview_worker(self, host: str, modal: DeployModal) -> None:
        """Run the type's manifest in generate-only mode (with a stubbed
        cdist object/global layout) and show the generated restore files."""
        import asyncio
        import shutil
        import tempfile
        # wait until the modal is mounted so early output is not lost
        while not modal.is_mounted:
            await asyncio.sleep(0.01)
        manifest = os.path.join(self.firewall_type, "manifest")
        if not os.path.isfile(manifest):
            modal.append(f"firewall type manifest not found: {manifest}\n")
            return
        objdir = tempfile.mkdtemp(prefix="fwtui-object-")
        globaldir = tempfile.mkdtemp(prefix="fwtui-global-")
        outdir = tempfile.mkdtemp(prefix="fwtui-preview-")
        try:
            # stub the cdist object/global layout the manifest reads
            paramdir = os.path.join(objdir, "parameter")
            os.makedirs(paramdir)
            with open(os.path.join(paramdir, "rules"), "w") as fh:
                fh.write(os.path.join(self.fwdir, host))
            if os.path.exists(self.db_path):
                with open(os.path.join(paramdir, "db"), "w") as fh:
                    fh.write(self.db_path)
            if self.includedir:
                with open(os.path.join(paramdir, "includedir"), "w") as fh:
                    fh.write(self.includedir)
            open(os.path.join(paramdir, "state"), "w").close()
            os.makedirs(os.path.join(globaldir, "explorer"))
            osfile = os.path.join(self.explore_dir, host, "os")
            if os.path.exists(osfile):
                shutil.copy(osfile, os.path.join(globaldir, "explorer", "os"))
            else:
                open(os.path.join(globaldir, "explorer", "os"), "w").close()
            env = os.environ.copy()
            env.update({
                "__target_host": host,
                "__type": self.firewall_type,
                "__object": objdir,
                "__global": globaldir,
                "FWTUI_GENERATE": outdir,
            })
            modal.append(f"$ {manifest} (generate-only for {host})\n")
            proc = await asyncio.create_subprocess_exec(
                "bash", manifest, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=env)
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                modal.append(line.decode(errors="replace"))
            rc = await proc.wait()
            if rc != 0:
                modal.append(f"\n[generation failed, exit code {rc}]\n")
            files = sorted(f for f in os.listdir(outdir)
                           if not f.startswith("."))
            if files:
                for f in files:
                    with open(os.path.join(outdir, f)) as fh:
                        modal.append(f"\n=== {f} ===\n")
                        modal.append(fh.read())
            else:
                modal.append("\n(no rules generated)\n")
        finally:
            shutil.rmtree(objdir, ignore_errors=True)
            shutil.rmtree(globaldir, ignore_errors=True)
            shutil.rmtree(outdir, ignore_errors=True)

    # -- deploy and git ----------------------------------------------------
    def action_deploy(self) -> None:
        """Run the configured deploy command for the current host, showing
        the live output in a modal (the command may be a real deploy or a
        dry run, depending on the config)."""
        if not self.current_host:
            self.notify("Select a host first", severity="warning")
            return
        host = self.current_host
        modal = DeployModal(f"Deploy {host}")
        self.push_screen(modal)
        self.run_worker(self._deploy_worker(host, modal), exclusive=True)

    async def _deploy_worker(self, host: str, modal: DeployModal) -> None:
        """Run the deploy command, streaming its output to the modal."""
        import asyncio
        import shlex
        # wait until the modal is mounted so early output is not lost
        while not modal.is_mounted:
            await asyncio.sleep(0.01)
        env = os.environ.copy()
        env.update(self.deploy_env)
        cmd = shlex.split(self.deploy_command.format(host=host))
        modal.append(f"$ {' '.join(cmd)}\n")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=env)

            async def read_output() -> int:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    modal.append(line.decode(errors="replace"))
                return await proc.wait()

            try:
                returncode = await asyncio.wait_for(read_output(), timeout=180)
                modal.append(f"\n[exit code {returncode}]")
            except asyncio.TimeoutError:
                proc.kill()
                modal.append("\n[timed out after 180s]")
        except Exception as e:
            modal.append(f"\nError running deploy command: {e}")

    def action_git_diff(self) -> None:
        """Show the git history for the current host's ruleset: pick a
        commit, view its diff, load that version."""
        if not self.current_host:
            self.notify("Select a host first", severity="warning")
            return
        self.push_screen(GitHistory(self.current_host, self.fwdir),
                         self._on_git_history_load)

    def _on_git_history_load(self, result) -> None:
        """Load a git version of the host file into the editor."""
        if not result:
            return
        self._snapshot()
        host = os.path.join(self.fwdir, self.current_host)
        self.lines = []
        self._load_content_with_includes(result["content"], host, self.lines)
        # dirty only if the loaded state differs from what is on disk
        # (loading the working tree back should not leave unsaved changes)
        try:
            with open(host) as fh:
                disk = fh.read()
            self.dirty = (parser.serialize_rules(self.lines).rstrip("\n")
                          != disk.rstrip("\n"))
        except OSError:
            self.dirty = True
        self._populate_rules()
        self._populate_global()
        self._update_status()
        label = (result["commit"] if result["commit"] == "working tree"
                 else result["commit"][:8])
        self.notify(f"Loaded {label} - review and save (ctrl+s)")

    def _load_content_with_includes(self, content: str, path: str,
                                    out: list) -> None:
        """Like _load_with_includes but from in-memory content (for loading
        a git version of the host file; include files stay current)."""
        for l in parser.parse_rules(content):
            l.source = path
            if l.kind == "include":
                out.append(l)
                inc_path = os.path.join(self.includedir, l.name)
                if os.path.isfile(inc_path):
                    self._load_with_includes(inc_path, out)
            else:
                out.append(l)

    def action_save(self) -> None:
        if self.db_mode or self.current_host is None:
            with open(self.db_path, "w") as fh:
                fh.write(parser.serialize_db(self.dblines))
            self.dirty = False
            self._update_status()
            self.notify(f"Saved {os.path.basename(self.db_path)}")
            return
        # group the spliced lines by their source file (host + includes)
        by_file: dict[str, list] = {}
        for l in self.lines:
            by_file.setdefault(l.source, []).append(l)
        for path, flines in by_file.items():
            with open(path, "w") as fh:
                fh.write(parser.serialize_rules(flines))
        self.dirty = False
        self._update_status()
        saved = ", ".join(os.path.basename(p) for p in by_file)
        self.notify(f"Saved {saved}")

    def _update_status(self) -> None:
        sb = self.query_one("#statusbar", Static)
        filt = ""
        view = self._active_rules_view()
        if view and view.filter_text:
            filt = f"  [filter: {view.filter_text}]"
        if self.db_view and self.db_view.filter_text:
            filt += f"  [db filter: {self.db_view.filter_text}]"
        empty_hint = "O=show empty"
        if view is not None and not view.hide_empty:
            empty_hint = "O=hide empty"
        sb.update(
            f"a=add e=edit d=delete n=new section space=collapse o=toggle all "
            f"{empty_hint} enter=edit v=validate g=preview p=deploy i=git "
            f"history /=filter ctrl+z=undo ctrl+s=save q=quit   esc=menu{filt}")

    def on_rules_view_selection_changed(self, event) -> None:
        """Show the raw rule text of the selected rule in the status bar."""
        if self._active_tab() not in ("rules", "nat", "mangle"):
            return
        view = self._active_rules_view()
        if not view:
            return
        rows = view.rows
        if event.row_index < len(rows):
            info = rows[event.row_index]
            if info[0] == "rule":
                line = info[1]
                self.query_one("#statusbar", Static).update(
                    f"{line.table}{line.proto}={line.value}")
                return
        self._update_status()

    def on_rules_view_widths_changed(self, event) -> None:
        """Column widths changed: keep the header line of that view in sync."""
        wid = {"#rules-view": "#rules-header", "#nat-view": "#nat-header",
               "#mangle-view": "#mangle-header"}.get(event.view.id)
        if wid:
            self.query_one(wid, Static).update(header_text(event.widths))


def main() -> None:
    # optional args: [config-file] [fwdir] [includedir]
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    fwdir = sys.argv[2] if len(sys.argv) > 2 else None
    includedir = sys.argv[3] if len(sys.argv) > 3 else None
    FirewallApp(fwdir, includedir, config_path).run()


if __name__ == "__main__":
    main()
