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

import asyncio
import copy
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from rich.markup import escape
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
from textual.widgets._footer import FooterKey

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
    type_to_search is on so typing in an open dropdown filters the options
    (fast for long db-backed lists); while the dropdown is closed, printable
    keys still bubble, so the modal shortcuts (a, s) and vi j/k field
    navigation keep working.
    """

    BINDINGS = [
        Binding("enter,space", "show_overlay", "Show menu", show=False),
    ]

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("type_to_search", True)
        super().__init__(*args, **kwargs)


class HostSelect(NavSelect):
    """Host selector: type to search. Typing opens the dropdown and feeds
    the key to its search, so printable keys search instead of triggering
    app actions (a/e/d/v/...)."""

    class Focused(Message):
        pass

    def __init__(self, *args, **kwargs) -> None:
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
    Activate on enter (so enter works like 'e'). Also accepts vi-style
    navigation (j/k/G/ctrl+d/u/f/b)."""

    class NavigateUp(Message):
        pass

    class Activate(Message):
        pass

    BINDINGS = [
        Binding("enter", "activate", "Edit", show=False),
        # vi-style navigation (arrow keys still work)
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("G", "go_bottom", "Bottom", show=False),
        Binding("ctrl+d", "page_down", "Page down", show=False),
        Binding("ctrl+u", "page_up", "Page up", show=False),
        Binding("ctrl+f", "page_down", "Page down", show=False),
        Binding("ctrl+b", "page_up", "Page up", show=False),
    ]

    def action_activate(self) -> None:
        self.post_message(self.Activate())

    def action_go_bottom(self) -> None:
        """G: move the cursor to the last row."""
        if self.row_count:
            self.move_cursor(row=self.row_count - 1)

    def action_cursor_up(self) -> None:
        if self.cursor_row == 0:
            self.post_message(self.NavigateUp())
        else:
            super().action_cursor_up()


class HelpFooter(Footer):
    """Footer that always pins a '?' Help key on the right edge, so the way
    to open the key-binding help is never scrolled out of view even when the
    other keys overflow a narrow terminal."""

    def __init__(self, *args, **kwargs) -> None:
        # hide Textual's built-in command-palette key (we show '?' instead)
        kwargs.setdefault("show_command_palette", False)
        super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        yield from super().compose()
        yield FooterKey("?", "?", "Help", "help", classes="-command-palette")


# ---------------------------------------------------------------------------
# rule editor modal (builder form + raw text)
# ---------------------------------------------------------------------------

# Sentinel for the "(custom dscp ...)" option in the mangle Action dropdown
CUSTOM_DSCP = "__custom_dscp__"

# Per-table option sets for the rule editor: each tab only offers the
# chains / targets that are valid in the table it edits, so a mistake like
# a filter rule with -A PREROUTING or -j DNAT is impossible from the form.
# (The raw text field still accepts anything, e.g. custom chains or MARK.)
CHAINS_BY_TABLE = {
    "filter": ["INPUT", "OUTPUT", "FORWARD"],
    "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
    "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT",
               "POSTROUTING"],
}

ACTIONS_BY_TABLE = {
    "filter": ["ACCEPT", "DROP", "reject(reset)", "reject(unreachable)",
               "reject(prohibited)", "log"],
    "nat": ["ACCEPT", "DROP", "reject(reset)", "reject(unreachable)",
            "reject(prohibited)", "log", "DNAT", "SNAT", "MASQUERADE"],
    "mangle": ["ACCEPT", "DROP", "reject(reset)", "reject(unreachable)",
               "reject(prohibited)", "log", "dscp(0x2e)", "dscp(0x10)",
               "dscp(0x04)", "dscp(0x08)", "dscp(0x0c)", "dscp(0x2a)",
               CUSTOM_DSCP],
}

# Source/Destination type selector: pick the kind first, then the value.
SRC_TYPES = [
    ("(any)", "any"),
    ("host", "host"),
    ("hostgroup", "hostgroup"),
    ("dns", "dns"),
    ("network", "network"),
    ("networkgroup", "networkgroup"),
    ("custom", "custom"),
]

# Source/Destination kinds that expand to an ipset match. These must NOT be
# prefixed with -s/-d; instead the set-match direction (src/dst) is appended:
#   hostgroup(lan) src / dns(example.org) dst / networkgroup(x) src
SET_MATCH_KINDS = ("hostgroup", "networkgroup", "dns")
SET_MATCH_RE = re.compile(
    r"(?:hostgroup|networkgroup|dns)\([^)]*\)\s+(?:src|dst)$")

PROTOS = [("both (46)", "46"), ("IPv4", "4"), ("IPv6", "6")]

# Sentinel value for the "(custom ...)" option in the Source/Dest dropdowns
CUSTOM = "__custom__"


def build_rule(chain: str, iface: str, src: str, dst: str, svc: str,
               action: str, to: str, extra: str,
               logprefix: str = "",
               limit: str = "", state: str = "",
               time: str = "", recent: str = "",
               mac: str = "", rpfilter: str = "",
               lograte: str = "",
               string: str = "", owner: str = "", frag: str = "") -> str:
    parts = [f"-A {chain}"]
    if iface:
        parts.append(f"-i {iface}")
    for val, flag in ((src, "-s"), (dst, "-d")):
        if not val:
            continue
        if SET_MATCH_RE.match(val):
            # ipset match already carries its src/dst direction: put it in
            # the body without a -s/-d prefix (the manifest rejects that)
            parts.append(val)
        else:
            parts.append(f"{flag} {val}")
    if svc:
        if svc.startswith("dservices("):
            parts.append(svc)  # multiport form, keep as-is
        else:
            parts.append(f"dservice({svc})")
    # match clauses (limit/state/time/recent/mac/rpfilter/string/owner/frag)
    # go in the body before -j
    for clause in (limit, state, time, recent, mac, rpfilter,
                   string, owner, frag):
        if clause:
            parts.append(clause)
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
        rate = f",{lograte}" if lograte else ""
        parts.append(f"log({logprefix or 'firewall'}{rate})")
    elif action.startswith("reject("):
        parts.append(action)  # e.g. reject(unreachable)
    elif action.startswith("dscp("):
        # dscp(0x2e) -> -j DSCP --set-dscp 0x2e
        val = action[action.index("(") + 1: -1]
        parts.append(f"-j DSCP --set-dscp {val}")
    else:
        parts.append(f"-j {action}")
    if extra:
        parts.append(extra)
    return " ".join(parts)


class RuleEditor(ModalScreen):
    """Modal to add/edit a rule. Builder fields feed a live raw preview;
    the raw text is authoritative on save."""

    CSS = """
    /* Let dropdowns size to their content instead of wrapping long options
       to the narrow width of the Select field (source/dest/service names
       wrap into several lines otherwise). Capped at 60% of the screen so a
       single very long option cannot overflow the terminal. */
    Select > SelectOverlay {
        width: auto;
        max-width: 60vw;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("s", "save", "Save", show=False),
        Binding("a", "add_db_entry", "Add db entry", show=False),
        Binding("w", "where_used", "Where used", show=False),
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
        self._baseline_text = ""  # raw text snapshot on mount (for edits)
        self._pending_jump = None
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

    def _service_options(self) -> list:
        """Service dropdown: show each service's port/proto next to its name
        (e.g. 'ssh (22/tcp)') so the value is clear and type-to-search
        matches on it too."""
        opts = [("(none)", "")]
        for s in self.services:
            val = self.db.services.get(s, "")
            opts.append((f"{s} ({val})" if val else s, s))
        opts.append(("(custom ...)", CUSTOM))
        return opts

    def _to_svc_options(self) -> list:
        """To-svc dropdown (DNAT/SNAT target): same name (port/proto)
        display; the value keeps the service() wrapper used in
        --to-destination."""
        opts = [("(none)", "")]
        for s in self.services:
            val = self.db.services.get(s, "")
            opts.append((f"{s} ({val})" if val else s, f"service({s})"))
        return opts

    def _src_type_options(self, kind: str) -> list:
        """Value options for a Source/Destination type: the db entries of
        that kind, wrapped in the manifest's function form (host(x),
        network(y), ...)."""
        if kind == "host":
            return [("(none)", "")] + [(h, f"host({h})")
                                         for h in self.hosts]
        if kind == "hostgroup":
            return [("(none)", "")] + [(g, f"hostgroup({g})")
                                         for g in self.hostgroups]
        if kind == "network":
            return [("(none)", "")] + [(n, f"network({n})")
                                         for n in self.networks]
        if kind == "networkgroup":
            opts = [("(none)", "")] + [(g, f"networkgroup({g})")
                                         for g in self.networkgroups]
            opts += self._country_options()
            return opts
        return [("(any)", "")]

    def _country_options(self) -> list:
        """Predefined G_<CC> country networkgroups from the GeoLite2 MMDB,
        read once per app session (via the app's cache) and cached. Returns
        [] if geoip isn't configured or the helper/MMDB isn't available, so
        the editor still works for db-defined groups."""
        countries = self.app._country_list(self.db)
        return [(cc, f"networkgroup(G_{cc})") for cc in countries]

    def _src_field(self, wid: str) -> Horizontal:
        """Two-step Source/Destination field: a type dropdown (any / host /
        hostgroup / network / networkgroup / custom) plus, next to it, the
        value dropdown for that type or a raw-value input for custom."""
        return Horizontal(
            NavSelect(SRC_TYPES, value="any", id=f"{wid}-type",
                      classes="fselect src-type", allow_blank=False),
            NavSelect([("(any)", "")], value="", id=f"{wid}-val",
                      classes="fselect src-val", allow_blank=False),
            Input(placeholder="raw value (IP, host(x), ...)",
                  id=f"{wid}-custom", classes="finput src-custom"),
            id=f"{wid}-box", classes="fbox")

    def _apply_src_type(self, wid: str) -> None:
        """Populate the value dropdown and show/hide the value dropdown vs
        the custom input for the field's current type. Does not touch the
        raw text. A value that is still valid for the new type is kept
        (so deferred Select.Changed messages from a sync don't wipe it)."""
        kind = self.query_one(f"#{wid}-type", Select).value
        val_sel = self.query_one(f"#{wid}-val", Select)
        custom_in = self.query_one(f"#{wid}-custom", Input)
        cur = val_sel.value
        val_sel.set_options(self._src_type_options(kind))
        if cur in [v for _, v in val_sel._options]:
            val_sel.value = cur
        else:
            val_sel.value = ""
        val_sel.display = kind not in ("any", "custom", "dns")
        custom_in.display = kind in ("custom", "dns")
        custom_in.placeholder = ("domain name (resolved on the firewall host)"
                                 if kind == "dns" else
                                 "raw value (IP, host(x), ...)")

    def _on_src_type_changed(self, wid: str) -> None:
        """Type dropdown changed: repopulate the value dropdown, toggle the
        custom input, and rebuild the raw text."""
        self._apply_src_type(wid)
        self._rebuild_raw()

    def _set_src_value(self, wid: str, raw_value: str) -> None:
        """Set the type + value widgets from a raw -s/-d value (e.g.
        'host(proxy)' -> type host, value proxy; '192.168.1.77' -> custom)."""
        wid = wid.lstrip("#")
        m = re.match(r"(host|hostgroup|network|networkgroup|dns)\(([^)]+)\)",
                     raw_value)
        kind, name = (m.group(1), m.group(2)) if m else ("custom", raw_value)
        self.query_one(f"#{wid}-type", Select).value = kind
        self._apply_src_type(wid)
        if kind in ("custom", "dns"):
            self.query_one(f"#{wid}-custom", Input).value = name
        else:
            self._set_select_value(self.query_one(f"#{wid}-val", Select),
                                   raw_value)

    def _src_raw_value(self, wid: str) -> str:
        """The raw -s/-d value the field currently represents ("" for any).
        Set-match kinds (hostgroup/networkgroup/dns) are emitted as
        'func(x) src|dst' (direction by field) so build_rule puts them in
        the body without a -s/-d prefix."""
        kind = self.query_one(f"#{wid}-type", Select).value
        if kind in ("", "any"):
            return ""
        direction = "src" if wid.endswith("src") else "dst"
        if kind in SET_MATCH_KINDS:
            if kind == "dns":
                value = self.query_one(f"#{wid}-custom", Input).value.strip()
                if not value:
                    return ""
                return f"dns({value}) {direction}"
            value = self.query_one(f"#{wid}-val", Select).value or ""
            return f"{value} {direction}" if value else ""
        if kind == "custom":
            return self.query_one(f"#{wid}-custom", Input).value.strip()
        return self.query_one(f"#{wid}-val", Select).value or ""

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

    def _chains(self) -> list[tuple[str, str]]:
        """Chains valid in this editor's table (see CHAINS_BY_TABLE)."""
        return [(c, c) for c in CHAINS_BY_TABLE.get(self.table,
                                                    CHAINS_BY_TABLE["filter"])]

    def _actions(self) -> list[tuple[str, str]]:
        """Targets valid in this editor's table (see ACTIONS_BY_TABLE). The
        mangle '(custom dscp ...)' sentinel is shown as a labeled option."""
        acts = ACTIONS_BY_TABLE.get(self.table, ACTIONS_BY_TABLE["filter"])
        out = [(a, a) for a in acts if a != CUSTOM_DSCP]
        if CUSTOM_DSCP in acts:
            out.append(("(custom dscp ...)", CUSTOM_DSCP))
        return out

    def compose(self) -> ComposeResult:
        yield Static("Rule editor", classes="modal-title")
        with Horizontal():
            with Vertical(id="builder"):
                yield self._row("Proto", NavSelect(
                    PROTOS, value=self.proto, id="f-proto",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Chain", NavSelect(
                    self._chains(), id="f-chain",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Iface",
                    NavSelect(self._iface_options(), value="", id="f-iface",
                              classes="fselect -textual-compact",
                              allow_blank=False)
                    if self.ifaces else Input(
                        placeholder="e.g. eth0, vlan10", id="f-iface",
                        classes="finput -textual-compact"))
                yield self._row("Source", self._src_field("f-src"))
                yield self._row("Destination", self._src_field("f-dst"))
                yield self._row("Service", NavSelect(
                    self._service_options(), value="", id="f-svc",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("Action", NavSelect(
                    self._actions(), value="ACCEPT", id="f-action",
                    classes="fselect -textual-compact", allow_blank=False))
                yield self._row("To host", NavSelect(
                    [("(none)", "")] + [(f"host({h})", f"host({h})")
                                          for h in self.hosts],
                    value="", id="f-to-host",
                    classes="fselect -textual-compact", allow_blank=False),
                    classes="natrow")
                yield self._row("To svc", NavSelect(
                    self._to_svc_options(), value="", id="f-to-svc",
                    classes="fselect -textual-compact", allow_blank=False),
                    classes="natrow")
                yield self._row("Log prefix", Input(
                    placeholder="e.g. apache dropped", id="f-logprefix",
                    classes="finput -textual-compact"), classes="logrow")
                yield self._row("Log rate", Input(
                    placeholder="e.g. 10/min (optional)", id="f-lograte",
                    classes="finput -textual-compact"), classes="logrow")
                yield self._row("Rate limit", Input(
                    placeholder="e.g. 10/min,5", id="f-limit",
                    classes="finput -textual-compact"))
                yield self._row("State", Input(
                    placeholder="e.g. NEW,ESTABLISHED", id="f-state",
                    classes="finput -textual-compact"))
                yield self._row("Schedule", Input(
                    placeholder="e.g. 08:00-18:00,Mon-Fri", id="f-time",
                    classes="finput -textual-compact"))
                yield self._row("Recent", Input(
                    placeholder="set | check,60,5", id="f-recent",
                    classes="finput -textual-compact"))
                yield self._row("MAC", Input(
                    placeholder="e.g. 00:11:22:33:44:55", id="f-mac",
                    classes="finput -textual-compact"))
                yield self._row("rpfilter", Input(
                    placeholder="loose | strict | validmark", id="f-rpfilter",
                    classes="finput -textual-compact"))
                yield self._row("String", Input(
                    placeholder="e.g. GET /admin", id="f-string",
                    classes="finput -textual-compact"))
                yield self._row("Owner", Input(
                    placeholder="e.g. root or 0", id="f-owner",
                    classes="finput -textual-compact"))
                yield self._row("Frag", Input(
                    placeholder="more | first", id="f-frag",
                    classes="finput -textual-compact"))
                yield self._row("Extra", Input(
                    placeholder="e.g. -m limit --limit 10/min", id="f-extra",
                    classes="finput -textual-compact"))
                yield Label(
                    "Source/Destination: pick a type, then a value "
                    "(custom = raw IP/address). Service: pick a db entry or "
                    "'(custom ...)'", classes="fhint")
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
        for wid in ("f-src", "f-dst"):
            self._apply_src_type(wid)
        self._sync_from_raw()
        self._update_conditional_rows()
        # snapshot the normalized raw text once the editor settles (a few
        # frames later) so later edits can be detected for the jump warning
        self.set_timer(0.2, self._snapshot_baseline)

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
        self._syncing = True
        try:
            raw = self.query_one("#f-raw", TextArea).text
            self.text = raw
            m = re.search(r"-A\s+(\S+)", raw)
            if m:
                # keep custom chains (user-defined, SECMARK, ...) as options
                self._set_select_value(self.query_one("#f-chain", Select),
                                       m.group(1))
            for flag, wid in (("-i", "#f-iface"), ("-s", "#f-src"),
                              ("-d", "#f-dst")):
                m = re.search(rf"{flag}\s+(\S+)", raw)
                if m:
                    if wid in ("#f-src", "#f-dst"):
                        self._set_src_value(wid, m.group(1))
                    else:
                        w = self.query_one(wid)
                        if isinstance(w, Input):
                            w.value = m.group(1)
                        else:
                            self._set_select_value(w, m.group(1))
            # ipset set-match sources/destinations appear in the rule body
            # as 'func(x) src' / 'func(x) dst' (no -s/-d prefix)
            for func, direction, wid in (
                    ("hostgroup", "src", "#f-src"),
                    ("hostgroup", "dst", "#f-dst"),
                    ("networkgroup", "src", "#f-src"),
                    ("networkgroup", "dst", "#f-dst"),
                    ("dns", "src", "#f-src"),
                    ("dns", "dst", "#f-dst")):
                m = re.search(rf"{func}\(([^)]+)\)\s+{direction}\b", raw)
                if m:
                    self._set_src_value(wid, f"{func}({m.group(1)})")
            # DNAT/SNAT rules use the long form --destination; capture it too
            m = re.search(r"--destination\s+(\S+)", raw)
            if m:
                self._set_src_value("#f-dst", m.group(1))
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
            # match clauses: limit/state/time/recent/mac/rpfilter/string/owner/frag
            for func, wid in (("limit", "#f-limit"), ("state", "#f-state"),
                              ("time", "#f-time"), ("recent", "#f-recent"),
                              ("mac", "#f-mac"), ("rpfilter", "#f-rpfilter"),
                              ("string", "#f-string"), ("owner", "#f-owner"),
                              ("frag", "#f-frag")):
                m = re.search(rf"{func}\(([^)]+)\)", raw)
                if m:
                    self.query_one(wid, Input).value = m.group(1)
            m = re.search(r"-j\s+(\S+)", raw)
            if m:
                # keep custom targets (MARK, custom chains, ...) as options
                self._set_select_value(self.query_one("#f-action", Select),
                                       m.group(1))
            # function actions: reject(...), log(prefix[,rate]) and dscp(...)
            m = re.search(r"reject\((reset|unreachable|prohibited)\)", raw)
            if m:
                self.query_one("#f-action", Select).value = f"reject({m.group(1)})"
            m = re.search(r"log\(([^)]*)\)", raw)
            if m:
                self.query_one("#f-action", Select).value = "log"
                logargs = m.group(1).split(",")
                self.query_one("#f-logprefix", Input).value = logargs[0].strip()
                self.query_one("#f-lograte", Input).value = (
                    logargs[1].strip() if len(logargs) > 1 else "")
            m = re.search(r"-j DSCP --set-dscp\s+(\S+)", raw)
            if m:
                self._set_select_value(self.query_one("#f-action", Select),
                                       f"dscp({m.group(1)})")
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

    def _rebuild_raw(self) -> None:
        chain = self.query_one("#f-chain", Select).value or "INPUT"
        iface = self.query_one("#f-iface").value  # Input or Select
        src = self._src_raw_value("f-src")
        dst = self._src_raw_value("f-dst")
        svc = self.query_one("#f-svc", Select).value or ""
        action = self.query_one("#f-action", Select).value or "ACCEPT"
        to_host = self.query_one("#f-to-host", Select).value or ""
        to_svc = self.query_one("#f-to-svc", Select).value or ""
        to = to_host + (f":{to_svc}" if to_svc else "")
        extra = self.query_one("#f-extra", Input).value
        logprefix = self.query_one("#f-logprefix", Input).value
        lograte = self.query_one("#f-lograte", Input).value
        limit = self._match_clause("f-limit", "limit")
        state = self._match_clause("f-state", "state")
        time = self._match_clause("f-time", "time")
        recent = self._match_clause("f-recent", "recent")
        mac = self._match_clause("f-mac", "mac")
        rpfilter = self._match_clause("f-rpfilter", "rpfilter")
        string = self._match_clause("f-string", "string")
        owner = self._match_clause("f-owner", "owner")
        frag = self._match_clause("f-frag", "frag")
        self.query_one("#f-raw", TextArea).text = build_rule(
            chain, iface, src, dst, svc, action, to, extra, logprefix,
            limit, state, time, recent, mac, rpfilter, lograte,
            string, owner, frag)

    def _match_clause(self, wid: str, func: str) -> str:
        """Wrap a match-clause field's value in its function form, or '' if
        empty. e.g. '10/min,5' -> 'limit(10/min,5)'."""
        val = self.query_one(f"#{wid}", Input).value.strip()
        return f"{func}({val})" if val else ""

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._syncing:
            return
        if event.input.id in ("f-iface", "f-extra", "f-logprefix",
                              "f-lograte", "f-limit", "f-state", "f-time",
                              "f-recent", "f-mac", "f-rpfilter",
                              "f-string", "f-owner", "f-frag",
                              "f-src-custom", "f-dst-custom"):
            self._rebuild_raw()

    def on_select_changed(self, event: Select.Changed) -> None:
        if self._syncing:
            return
        wid = event.select.id
        if event.value == CUSTOM and wid in ("f-iface", "f-svc"):
            # "(custom ...)": ask for a raw value; do NOT rebuild the raw
            # text with the sentinel (it still holds the previous value)
            self._open_custom_value(wid)
            return
        if event.value == CUSTOM_DSCP and wid == "f-action":
            self._open_custom_value("f-action")
            return
        if wid in ("f-src-type", "f-dst-type"):
            self._on_src_type_changed(wid[:-5])  # strip the "-type" suffix
            return
        if wid in ("f-chain", "f-action", "f-svc", "f-to-host",
                   "f-to-svc", "f-src-val", "f-dst-val", "f-iface"):
            self._rebuild_raw()
        if wid == "f-action":
            self._update_conditional_rows()

    def _open_custom_value(self, wid: str) -> None:
        """'(custom ...)' picked in Iface/Service/Action: prompt for a value."""
        if wid == "f-iface":
            title, placeholder = "Interface value", "e.g. eth0, vlan10"
        elif wid == "f-svc":
            title, placeholder = ("Service value (db entry or raw name)",
                                  "e.g. ssh, https, or dservices(a,b)")
        else:  # f-action (dscp)
            title, placeholder = "DSCP value", "e.g. 0x2e"
        self.app.push_screen(
            Prompt(title, value=self._current_field_value(wid),
                   placeholder=placeholder),
            lambda res, w=wid: self._on_custom_value(w, res))

    def _current_field_value(self, wid: str) -> str:
        """The value the field had before '(custom ...)' was picked: the raw
        text is untouched at this point, so parse it."""
        raw = self.query_one("#f-raw", TextArea).text
        if wid == "f-svc":
            m = (re.search(r"dservices\(([^)]+)\)", raw)
                 or re.search(r"dservice\(([^)]+)\)", raw))
        elif wid == "f-action":
            m = re.search(r"dscp\(([^)]+)\)", raw)
            return m.group(1) if m else ""
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
        if wid == "f-action":
            value = f"dscp({value})"
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
                           "networkgroups", "servicegroups", "geoip"):
            self.notify(f"Unknown db section '{section}'", severity="error")
            return
        if not self.app._add_db_entry_direct(section, key, value):
            return  # validation failed (notification already shown)
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
            ("#f-svc", self._service_options()),
            ("#f-to-host", [("(none)", "")]
             + [(f"host({h})", f"host({h})") for h in self.hosts]),
            ("#f-to-svc", self._to_svc_options()),
        ):
            sel = self.query_one(wid, Select)
            cur = sel.value
            sel.set_options(opts)
            self._set_select_value(sel, cur)
        for wid in ("f-src", "f-dst"):
            kind = self.query_one(f"#{wid}-type", Select).value
            val_sel = self.query_one(f"#{wid}-val", Select)
            cur = val_sel.value
            val_sel.set_options(self._src_type_options(kind))
            self._set_select_value(val_sel, cur)

    # -- where-used (w) on the highlighted db item ------------------------
    def action_where_used(self) -> None:
        """w: show where the db item in the highlighted field is used. Only
        does something when the focused field holds a db reference (service,
        source/destination host/network/group, NAT to-host/to-svc)."""
        ref = self._focused_db_ref()
        if not ref:
            self.notify("No db item selected in the highlighted field",
                        severity="warning")
            return
        section, key = ref
        rule_refs, db_refs = self.app._collect_db_refs(section, key)
        self.app.push_screen(
            DbReferencesReport(
                section, key, rule_refs, db_refs,
                title=f"Where used: '{key}' ({section}) — "
                      f"{len(rule_refs) + len(db_refs)} reference(s)"),
            self._on_where_used_done)

    def _on_where_used_done(self, payload) -> None:
        """A rule reference was picked in the where-used report: leave the
        editor and jump to it, warning first if the rule has unsaved edits."""
        if not payload or payload[0] == "db":
            return
        host, section, line = payload
        if self._has_unsaved_changes():
            self._pending_jump = (host, section, line)
            self.app.push_screen(ConfirmDiscardJump(), self._on_discard_jump)
        else:
            self._discard_and_jump(host, section, line)

    def _on_discard_jump(self, confirmed) -> None:
        if not confirmed or not self._pending_jump:
            self._pending_jump = None
            return
        host, section, line = self._pending_jump
        self._pending_jump = None
        self._discard_and_jump(host, section, line)

    def _discard_and_jump(self, host, section, line) -> None:
        """Leave the editor without saving and tell the app to jump."""
        self.dismiss({"_jump": (host, section, line)})

    def _has_unsaved_changes(self) -> bool:
        """True if the rule text was edited since the editor opened (the
        raw text is normalized on mount, so the baseline is captured once it
        settles; for a new rule, any typed content counts as a change)."""
        if not self._baseline_text:
            self._snapshot_baseline()
        return self.query_one("#f-raw", TextArea).text != self._baseline_text

    def _snapshot_baseline(self) -> None:
        """Record the editor's normalized raw text as the no-change state."""
        self._baseline_text = self.query_one("#f-raw", TextArea).text

    def _focused_db_ref(self):
        """The (section, key) db object the currently-focused field holds,
        or None if it is not a db reference."""
        f = self.focused
        if f is None or f.id is None:
            return None
        fid = f.id
        if fid in ("f-src-type", "f-src-val", "f-src-custom"):
            return self._src_field_db_ref("f-src")
        if fid in ("f-dst-type", "f-dst-val", "f-dst-custom"):
            return self._src_field_db_ref("f-dst")
        if fid == "f-svc":
            return self._service_db_ref()
        if fid == "f-to-host":
            val = self.query_one("#f-to-host", Select).value or ""
            m = re.match(r"host\(([^)]+)\)", val)
            return ("hosts", m.group(1)) if m else None
        if fid == "f-to-svc":
            val = self.query_one("#f-to-svc", Select).value or ""
            m = re.match(r"service\(([^)]+)\)", val)
            return ("services", m.group(1)) if m else None
        return None

    def _src_field_db_ref(self, wid: str):
        """The db object the Source/Destination field holds (by its type)."""
        kind = self.query_one(f"#{wid}-type", Select).value
        section = {"host": "hosts", "hostgroup": "hostgroups",
                   "network": "networks",
                   "networkgroup": "networkgroups"}.get(kind)
        if not section:
            return None
        val = self.query_one(f"#{wid}-val", Select).value or ""
        m = re.match(rf"{re.escape(kind)}\(([^)]+)\)", val)
        return (section, m.group(1)) if m else None

    def _service_db_ref(self):
        """The db object the Service field holds (a service, a dservice, or
        a dservices group; a comma list of services is not one object)."""
        svc = self.query_one("#f-svc", Select).value or ""
        if not svc or svc == CUSTOM:
            return None
        m = re.match(r"dservices\(([^)]+)\)", svc)
        if m:
            group = m.group(1)
            if group in self.db.servicegroups:
                return ("servicegroups", group)
            return None
        m = re.match(r"dservice\(([^)]+)\)", svc)
        if m:
            return ("services", m.group(1))
        return ("services", svc)

    # -- form navigation ----------------------------------------------------
    FIELD_IDS = ("f-proto", "f-chain", "f-iface", "f-src-type",
                 "f-src-val", "f-src-custom", "f-dst-type", "f-dst-val",
                 "f-dst-custom", "f-svc", "f-action", "f-to-host",
                 "f-to-svc", "f-logprefix", "f-lograte", "f-limit",
                 "f-state", "f-time", "f-recent", "f-mac", "f-rpfilter",
                 "f-string", "f-owner", "f-frag", "f-extra", "f-raw")

    def _fields(self) -> list:
        return [self.query_one(f"#{wid}") for wid in self.FIELD_IDS
                if self.query_one(f"#{wid}").display]

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
        elif event.key in ("j", "k") and isinstance(self.focused, Select):
            # vi-style: j/k move between fields while a dropdown is focused
            # (text fields keep j/k for typing; an open dropdown's overlay
            # takes focus, so option navigation is unaffected)
            if event.key == "j":
                self.action_next_field()
            else:
                self.action_prev_field()
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


class DbEntryEditor(ModalScreen):
    """Add/edit a db entry with separate name and value fields.

    Values are validated per section (services, IPs, networks, groups)
    before saving; errors are shown inline and the modal stays open. Enter
    in the name field moves to the value field, enter in the value field
    saves."""

    CSS = """
    DbEntryEditor #db-error { color: $error; }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("s", "save", "Save", show=False),
    ]

    def __init__(self, section: str, key: str = "", value: str = "",
                 orig: "parser.DbLine | None" = None) -> None:
        super().__init__()
        self.section = section
        self.key = key
        self.value = value
        self.orig = orig  # the DbLine being edited (None when adding)

    def compose(self) -> ComposeResult:
        verb = "Edit" if self.orig else "New"
        yield Static(f"{verb} [{self.section}] entry", classes="modal-title")
        yield Horizontal(Label("Name", classes="flabel"),
                         Input(self.key, id="db-key",
                               classes="finput -textual-compact"),
                         classes="frow")
        yield Horizontal(Label("Value", classes="flabel"),
                         Input(self.value, id="db-value",
                               placeholder="e.g. 192.168.0.0/24, 22/tcp, ...",
                               classes="finput -textual-compact"),
                         classes="frow")
        yield Static("", id="db-error", classes="dberror")
        with Horizontal(id="modal-buttons"):
            yield Button("Save", variant="primary", id="btn-save")
            yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        for w in self.query(".finput"):
            w.add_class("-textual-compact")
        self.query_one("#db-key").focus()

    def _validate(self, key: str, value: str) -> list[str]:
        return self.app._validate_db_entry(self.section, key, value,
                                           orig=self.orig)

    def action_save(self) -> None:
        key = self.query_one("#db-key", Input).value.strip()
        value = self.query_one("#db-value", Input).value.strip()
        errs = self._validate(key, value)
        if errs:
            # escape: section names like [networks] are rich markup
            self.query_one("#db-error", Static).update(
                escape("\n".join(errs)))
            return
        self.dismiss({"key": key, "value": value})

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter: name field moves to the value field, value field saves."""
        if event.input.id == "db-key":
            self.query_one("#db-value", Input).focus()
        else:
            self.action_save()


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


class ConfirmDiscardJump(ModalScreen):
    """Confirm leaving the rule editor (discarding unsaved rule edits) to
    jump to a where-used reference."""

    BINDINGS = [
        Binding("escape", "no", "Cancel"),
        Binding("y", "yes", "Discard & jump"),
        Binding("n", "no", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("Discard changes to this rule and jump?\n"
                     "The current rule edit will be lost.",
                     classes="modal-title")
        with Horizontal(id="modal-buttons"):
            yield Button("Discard & jump", variant="error", id="btn-jump")
            yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-jump":
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

class HelpPopup(ModalScreen):
    """Lists the key bindings that are currently available (the '?' help)."""

    CSS = """
    HelpPopup #help-list { height: 24; }
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close", show=False),
        Binding("?", "close", "Close", show=False),
    ]

    def __init__(self, bindings: list[tuple[str, str]]) -> None:
        super().__init__()
        self.bindings = bindings

    def compose(self) -> ComposeResult:
        yield Static(f"Available key bindings ({len(self.bindings)})",
                     classes="modal-title")
        items = [ListItem(Label(f"  {key:<14}{desc}"))
                 for key, desc in self.bindings]
        yield ListView(*items, id="help-list")
        with Horizontal(id="modal-buttons"):
            yield Button("Close", id="btn-close")

    def action_close(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-close":
            self.dismiss(None)


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


class DbReferencesReport(ModalScreen):
    """Shown for a db entry's references (where-used, or delete-blocked).
    Lists the referencing rules (host + section + rule) and nested db group
    references. Enter on a rule line dismisses with a (host, section, line)
    payload so the app can switch to that host and highlight the rule; db
    references cannot be jumped to."""

    CSS = """
    DbReferencesReport #report-list { height: 20; }
    """

    BINDINGS = [Binding("escape", "close", "Close"),
                Binding("q", "close", "Close")]

    def __init__(self, section, key, rule_refs, db_refs, title=None) -> None:
        super().__init__()
        self.section = section
        self.key = key
        # rule_refs: list of (host, section, Line); db_refs: list of DbLine
        self.rule_refs = rule_refs
        self.db_refs = db_refs
        self.entries = self._entries()
        self.title = title

    def _entries(self):
        """Parallel (payload, label) list; payload is None for db refs."""
        out = []
        for host, sec, l in self.rule_refs:
            out.append(((host, sec, l),
                        f"rule  {host} [{l.table}{l.proto}] {l.value}"))
        for l in self.db_refs:
            out.append((None, f"db    [{l.section}] {l.key}={l.value}"))
        return out

    def compose(self) -> ComposeResult:
        n = len(self.entries)
        yield Static(
            self.title or (f"'{self.key}' ({self.section}) is used by "
                           f"{n} reference(s)."),
            classes="modal-title")
        items = [ListItem(Label(label)) for _, label in self.entries]
        if not items:
            items = [ListItem(Label("No references."))]
        yield ListView(*items, id="report-list")
        with Horizontal(id="modal-buttons"):
            yield Button("Close", id="btn-close")

    def on_list_view_selected(self, event) -> None:
        """Enter on a reference: dismiss with its jump payload."""
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


class CommitModal(ModalScreen):
    """Optional git commit after saving: enter a message and commit the
    changed files (or skip)."""

    BINDINGS = [
        Binding("escape", "skip", "Skip"),
        Binding("ctrl+s", "commit", "Commit", show=False),
    ]

    def __init__(self, files: list[str], fwdir: str) -> None:
        super().__init__()
        self.files = files
        self.fwdir = fwdir

    def compose(self) -> ComposeResult:
        yield Static("Commit changes to git?", classes="modal-title")
        yield Static("\n".join(f"  {escape(f)}" for f in self.files))
        yield Input(placeholder="Commit message", id="commit-msg")
        with Horizontal(id="modal-buttons"):
            yield Button("Commit", variant="primary", id="btn-commit")
            yield Button("Skip", id="btn-skip")
        yield Static("enter: commit   esc: skip", id="commit-hint")

    def on_mount(self) -> None:
        self.query_one("#commit-msg", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "commit-msg":
            self.action_commit()

    def action_commit(self) -> None:
        msg = self.query_one("#commit-msg", Input).value.strip()
        if not msg:
            self.notify("Enter a commit message", severity="warning")
            return
        self.query_one("#btn-commit", Button).disabled = True
        self.query_one("#btn-skip", Button).disabled = True
        self.run_worker(self._commit_worker(msg), exclusive=True)

    async def _commit_worker(self, msg: str) -> None:
        try:
            add = await asyncio.create_subprocess_exec(
                "git", "-C", self.fwdir, "add", "--", *self.files,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            out, _ = await add.communicate()
            if add.returncode != 0:
                self.notify("git add failed: "
                            + out.decode(errors="replace").strip(),
                            severity="error")
                self.dismiss(None)
                return
            commit = await asyncio.create_subprocess_exec(
                "git", "-C", self.fwdir, "commit", "-m", msg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            out, _ = await commit.communicate()
            text = out.decode(errors="replace").strip()
            if commit.returncode == 0:
                last = text.splitlines()[-1] if text else "committed"
                self.notify(f"Committed: {last}")
            elif "nothing to commit" in text:
                self.notify("Nothing to commit (no changes)")
            else:
                self.notify(f"git commit failed: {text}", severity="error")
        except Exception as e:
            self.notify(f"git error: {e}", severity="error")
        self.dismiss(None)

    def action_skip(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-commit":
            self.action_commit()
        elif event.button.id == "btn-skip":
            self.action_skip()


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
    /* slim line buttons everywhere (borderless text buttons, 1 line tall) */
    Button {
        border: none;
        min-height: 1;
        height: 1;
        padding: 0 2;
        background: transparent;
        color: $text;
        text-style: bold;
    }
    Button:hover, Button:focus {
        background: $panel;
    }
    Button.-primary { color: $primary; }
    Button.-success { color: $success; }
    Button.-warning { color: $warning; }
    Button.-error { color: $error; }
    Button:disabled {
        background: transparent;
        text-opacity: 0.4;
    }
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
    .fbox { width: 1fr; }
    .src-type { width: 13; }
    .src-val, .src-custom { width: 1fr; }
    #rawcol TextArea { height: 12; }
    #modal-buttons { height: 2; align-horizontal: left; align-vertical: middle; padding: 0 1; }
    #modal-buttons Button { margin: 0 1 0 0; }
    .modal-title { padding: 1; text-style: bold; }
    #report { height: 20; }
    """

    BINDINGS = [
        Binding("a", "add", "Add"),
        Binding("e", "edit", "Edit"),
        Binding("d", "delete", "Delete"),
        Binding("w", "where_used", "Where used"),
        Binding("n", "new_section", "New section"),
        Binding("v", "validate", "Validate"),
        Binding("p", "preview", "Preview"),
        Binding("D", "deploy", "Deploy"),
        Binding("g", "git", "Git"),
        Binding("ctrl+z", "undo", "Undo"),
        Binding("ctrl+s", "save", "Save"),
        Binding("?", "help", "Help"),
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
        # G_<CC> country list from the GeoLite2 MMDB, loaded once per session
        self._country_cache: list[str] | None = None
        self.rules_view: RulesView | None = None
        self.nat_view: RulesView | None = None
        self.mangle_view: RulesView | None = None
        self.db_view: DbView | None = None
        self.dbrowmap: dict = {}    # db table: row_key -> kind info
        self.dirty = False
        self.undo_stack: list = []
        self.db_mode = False
        self._pending_host: str | None = None
        self._pending_jump: tuple | None = None
        # git state (cached: the repo status does not change mid-session)
        self._git_info_cache: tuple[bool, str] | None = None

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
        yield HelpFooter()

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
        self.refresh_bindings()
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

    def _load_with_includes(self, path: str, out: list,
                            content: str | None = None) -> None:
        """Parse a rules file (or in-memory content), splicing [#include]
        content inline. Every line is tagged with the file it came from, so
        edits can be written back to the right file."""
        if content is None:
            with open(path) as fh:
                content = fh.read()
        for l in parser.parse_rules(content):
            l.source = path
            if l.kind == "include":
                out.append(l)
                inc_path = os.path.join(self.includedir, l.name)
                if os.path.isfile(inc_path):
                    self._load_with_includes(inc_path, out)
            else:
                out.append(l)

    def _country_list(self, db) -> list[str]:
        """ISO country codes available for geo blocking, read from the
        pre-generated per-country files under <maxminddir>/countries (IPv4).
        Loaded once per session and cached; returns [] when geoip isn't
        configured or no country data has been generated."""
        if self._country_cache is not None:
            return self._country_cache
        maxminddir = db.geoip.get("maxminddir", "")
        cdir = os.path.join(maxminddir, "countries") if maxminddir else ""
        if not cdir or not os.path.isdir(cdir):
            self._country_cache = []
            return []
        # v4 files are named <CC> (2 letters); IPv6 counterparts are <CC>6
        self._country_cache = sorted(
            f for f in os.listdir(cdir)
            if not f.endswith("6") and os.path.isfile(os.path.join(cdir, f)))
        return self._country_cache

    def _load_ruleset(self, host: str) -> None:
        path = os.path.join(self.fwdir, host)
        self.lines = []
        self._load_with_includes(path, self.lines)
        self.current_host = host
        self.dirty = False
        self._populate_rules(reset_collapsed=True)
        self._populate_global()
        self.refresh_bindings()

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
        globals_ = parser.global_dict(self.lines)
        host = os.path.join(self.fwdir, self.current_host or "")
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
                # sections from an include file are shown with an
                # 'include: ' label (row[3] marks them)
                rows.append(("section", l.name, l.source,
                             l.source != host))
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
        present = parser.global_dict(self.lines)
        for key in GLOBAL_ORDER:
            if key in present:
                t.add_row(key, present[key], "")
            else:
                t.add_row(key, self._global_default(key), "(default)")

    def _global_default(self, key: str) -> str:
        """Effective default for a global key (policy_* inherits policy,
        log_* inherits log)."""
        present = parser.global_dict(self.lines)
        if key.startswith("policy_"):
            return present.get("policy", GLOBAL_DEFAULTS["policy"])
        if key.startswith("log_"):
            return present.get("log", "")
        return GLOBAL_DEFAULTS[key]

    def _insert_after_section(self, lines: list, section_name: str,
                              new_line, kind: str,
                              source: str | None = None) -> bool:
        """Insert new_line after the last line of `kind` in the section
        named section_name (optionally matching source). Returns True when
        the section was found and the line inserted."""
        for i, l in enumerate(lines):
            if (l.kind == "section" and l.name == section_name
                    and (source is None or l.source == source)):
                j = i
                while j + 1 < len(lines) and lines[j + 1].kind == kind:
                    j += 1
                lines.insert(j + 1, new_line)
                return True
        return False

    def _insert_global(self, key: str, value: str) -> None:
        """Insert a global key=value line after the [global] header (creating
        the section at the top if the file has none)."""
        host = os.path.join(self.fwdir, self.current_host)
        line = parser.Line(raw=f"{key}={value}", kind="global", key=key,
                           value=value)
        line.source = host
        if self._insert_after_section(self.lines, "global", line, "global"):
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
        self.refresh_bindings()

    def on_tabbed_content_tab_activated(self, event) -> None:
        """Refresh the Footer keys when the active tab changes."""
        self.refresh_bindings()

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
        self.refresh_bindings()

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
        """Vertical navigation: host-select <-> tabs <-> content. View keys
        (o, O, space, /, ctrl+up/down) pressed while the tab strip is
        focused act on the active tab's view, so they work right after
        switching tabs."""
        focused = self.focused
        if isinstance(focused, ContentTabs):
            # vi-style navigation on the tab strip
            if event.key == "h":
                focused.action_previous_tab()
                event.stop()
                return
            if event.key == "l":
                focused.action_next_tab()
                event.stop()
                return
            if event.key == "j":
                self._focus_content()
                event.stop()
                return
            if event.key == "k":
                self.host_select.focus()
                event.stop()
                return
            view = self._active_rules_view()
            if view is not None:
                if event.key == "o":
                    view.action_toggle_all()
                    event.stop()
                    return
                if event.key == "O":
                    view.action_toggle_empty()
                    event.stop()
                    return
                if event.key == "space":
                    view.action_toggle_collapse()
                    event.stop()
                    return
                if event.key == "slash":
                    self._show_filter()
                    event.stop()
                    return
                if event.key == "ctrl+up":
                    view.action_move_up()
                    event.stop()
                    return
                if event.key == "ctrl+down":
                    view.action_move_down()
                    event.stop()
                    return
        if event.key == "down":
            if focused is self.host_select:
                self._focus_tabs()
                event.stop()
            elif isinstance(focused, ContentTabs):
                self._focus_content()
                event.stop()
            elif focused is self.query_one("#db-button", Button):
                # down from the db button: enter the db view (mirror of
                # up returning from the db view to the db button)
                self._set_db_mode(True)
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

    def action_help(self) -> None:
        """? : pop up the list of currently-available key bindings."""
        shown: set[tuple[str, str]] = set()
        for _key, (_ns, binding, enabled, _tooltip) in self.active_bindings.items():
            if binding.show and binding.description and enabled:
                shown.add((self.get_key_display(binding), binding.description))
        self.push_screen(HelpPopup(sorted(shown)))

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
            # no new global settings: the Global tab always shows every
            # option (with its default) and only supports editing ('e')
            self.notify("'a' isn't available here; the Global tab shows every "
                        "setting, edit one with 'e'", severity="warning")

    def _add_rule(self) -> None:
        rk, info = self._selected_row()
        if info and info[0] == "include":
            # an include is a container of sections: 'a' adds a section to
            # the include file itself
            self._add_include_section(info[1])
            return
        section = None
        section_source = None
        if info and info[0] == "rule":
            section = info[2]
            section_source = info[1].source
        elif info and info[0] == "section":
            section = info[1]
            section_source = info[2]
        if section is None:
            # default to the first real section visible in this tab. Only
            # sections the user can actually see are fair game: silently
            # picking an invisible one (hidden because it holds no rules for
            # this table) is confusing. Press 'O' to show empty sections.
            view = self._active_rules_view()
            if view:
                for row in view.rows:
                    if row[0] == "section":
                        section = row[1]
                        section_source = row[2]
                        break
        if section is None:
            self.notify("No visible section to add a rule to; press 'n' to "
                        "create one, or 'O' to show empty sections",
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
        if "_jump" in result:
            # the editor's where-used jumped instead of adding a rule
            self._jump_to_reference(*result["_jump"])
            return
        self._snapshot()
        # find the section line (in the file it came from)
        key = result["table"] + result["proto"]
        new_line = parser.Line(
            raw=f"{key}={result['text']}", kind="rule", key=key,
            value=result["text"], table=result["table"],
            proto=result["proto"])
        new_line.source = section_source
        self._insert_after_section(self.lines, section, new_line, "rule",
                                   source=section_source)
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
        if kind == "include":
            self.push_screen(
                Prompt("Rename include", value=info[1],
                       placeholder="include filename"),
                lambda res, old=info[1]:
                self._rename_include(old, res))
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
        if "_jump" in result:
            # the editor's where-used jumped instead of editing the rule
            self._jump_to_reference(*result["_jump"])
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
            self.notify("'d' isn't available on the Global tab; edit a value "
                        "with 'e' (or use '(unset)' to fall back to default)",
                        severity="warning")

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
        if kind == "include":
            self._delete_include(info[1])
            return
        if kind == "rule":
            line = info[1]
            if line in self.lines:
                self.lines.remove(line)
            self.dirty = True
            self._populate_rules()

    # -- include bars ------------------------------------------------------
    # [#name] bars behave like sections: rename (e), delete (d), reorder
    # (ctrl+up/down), and 'a' adds a section into the include file. The
    # include content is shared across hosts, so deleting/renaming only
    # changes the host's reference (and what this host includes) — the
    # shared include file is left untouched (not rewritten on save).

    @staticmethod
    def _include_span(lines, idx: int) -> list:
        """The lines belonging to include lines[idx] (transitively): every
        following line until the next sibling line from the same source file
        (which ends this include's content, whether it is a section or
        another include in the same file)."""
        inc = lines[idx]
        out: list = []
        j = idx + 1
        while j < len(lines) and lines[j].source != inc.source:
            out.append(lines[j])
            j += 1
        return out

    def _find_include(self, name: str):
        for l in self.lines:
            if l.kind == "include" and l.name == name:
                return l
        return None

    def _delete_include(self, name: str) -> None:
        inc = self._find_include(name)
        if inc is None:
            return
        self._snapshot()
        idx = self.lines.index(inc)
        span = self._include_span(self.lines, idx)
        del self.lines[idx:idx + len(span) + 1]
        self.dirty = True
        self._populate_rules()

    def _rename_include(self, old: str, new: str) -> None:
        if not new or new == old:
            return
        self._snapshot()
        inc = self._find_include(old)
        if inc is None:
            return
        idx = self.lines.index(inc)
        span = self._include_span(self.lines, idx)
        before = self.lines[:idx]
        after = self.lines[idx + len(span) + 1:]
        new_inc = parser.Line(raw=f"[#{new}]", kind="include", name=new)
        new_inc.source = inc.source
        new_content: list = []
        new_path = os.path.join(self.includedir, new)
        if os.path.isfile(new_path):
            self._load_with_includes(new_path, new_content)
        self.lines = before + [new_inc] + new_content + after
        self.dirty = True
        self._populate_rules()

    def _move_include(self, name: str, direction: str):
        """Swap an include block with the adjacent include in the same file.
        Does not cross into sibling sections/rules. Returns the include line
        if moved."""
        inc = self._find_include(name)
        if inc is None:
            return None
        self._snapshot()
        idx = self.lines.index(inc)
        span = self._include_span(self.lines, idx)
        block_len = len(span) + 1
        step = 1 if direction == "down" else -1
        j = idx + block_len if direction == "down" else idx - 1
        target = None
        while 0 <= j < len(self.lines):
            l = self.lines[j]
            if l.source != inc.source:
                j += step  # skip nested include content
                continue
            if l.kind == "include":
                target = j
                break
            break  # a sibling section/rule in the same file: don't cross
        if target is None:
            return None
        t_span = self._include_span(self.lines, target)
        t_block_len = len(t_span) + 1
        block = self.lines[idx:idx + block_len]
        del self.lines[idx:idx + block_len]
        if target > idx:
            target -= block_len
        if direction == "down":
            self.lines[target + t_block_len: target + t_block_len] = block
        else:
            self.lines[target: target] = block
        self.dirty = True
        self._populate_rules()
        return inc

    def _add_include_section(self, name: str) -> None:
        inc = self._find_include(name)
        if inc is None:
            return
        self.push_screen(
            Prompt("New section name", placeholder="e.g. allow web from admin"),
            lambda res, i=inc: self._on_add_include_section(i, res))

    def _on_add_include_section(self, inc, name) -> None:
        if not name:
            return
        self._snapshot()
        idx = self.lines.index(inc)
        span = self._include_span(self.lines, idx)
        insert_at = idx + len(span) + 1
        inc_path = os.path.join(self.includedir, inc.name)
        if insert_at > 0 and self.lines[insert_at - 1].kind != "blank":
            blank = parser.Line(raw="", kind="blank")
            blank.source = inc_path
            self.lines.insert(insert_at, blank)
            insert_at += 1
        new_line = parser.Line(raw=f"[{name}]", kind="section", name=name)
        new_line.source = inc_path
        self.lines.insert(insert_at, new_line)
        self.dirty = True
        self._populate_rules()
        view = self._active_rules_view()
        if view:
            view.expand_section(name)

    # -- reordering ---------------------------------------------------------
    def _snapshot(self) -> None:
        """Push the current lines/dblines onto the undo stack."""
        self.undo_stack.append((copy.deepcopy(self.lines),
                                copy.deepcopy(self.dblines)))
        if len(self.undo_stack) > 50:
            self.undo_stack.pop(0)
        self.refresh_bindings()

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
        self.refresh_bindings()

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
        elif kind == "include":
            moved = self._move_include(info[1], event.direction)
            if moved and view:
                view.select_include(moved.name)
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
        choice dropdown can open in place. table.region is already relative
        to the screen; _get_row_region is relative to the table."""
        try:
            row_index = table.cursor_coordinate[0]
            region = table._get_row_region(row_index)
            x = table.region.x + 18  # over the value column (key col + label)
            y = table.region.y + region.y - int(table.scroll_y)
            return (x, y)
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

    # -- db tab -------------------------------------------------------------
    def _validate_db_entry(self, section: str, key: str, value: str,
                           orig=None) -> list[str]:
        """Validate a db entry (name non-empty, no duplicate, value valid).
        `orig` is the DbLine being edited (skipped in the duplicate check)."""
        errs = []
        if not key:
            errs.append("name is empty")
        for l in self.dblines:
            if (l.kind == "entry" and l.section == section
                    and l.key == key and l is not orig):
                errs.append(f"'{key}' already exists in [{section}]")
                break
        errs.extend(expand.validate_db_value(section, value, self.db))
        return errs

    def _add_db_entry_direct(self, section: str, key: str, value: str) -> bool:
        """Add a db entry (used from the rule editor). Validates first;
        returns True when the entry was added."""
        errs = self._validate_db_entry(section, key, value)
        if errs:
            self.notify("; ".join(errs), severity="error")
            return False
        self._snapshot()
        self._insert_after_section(self.dblines, section, parser.DbLine(
            raw=f"{key}={value}", kind="entry", section=section,
            key=key, value=value), "entry")
        self.dirty = True
        self._rebuild_db()
        self._populate_db()
        return True

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
        self.push_screen(DbEntryEditor(section), self._on_db_entry)

    def _on_db_entry(self, result) -> None:
        if not result:
            return
        self._snapshot()
        key, value = result["key"], result["value"]
        self._insert_after_section(self.dblines, self.current_dbsection,
                                   parser.DbLine(
            raw=f"{key}={value}", kind="entry",
            section=self.current_dbsection, key=key, value=value), "entry")
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
        self.push_screen(
            DbEntryEditor(e.section, key=e.key, value=e.value, orig=e),
            lambda res, old=e: self._on_db_entry_edit(old, res))

    def _on_db_entry_edit(self, old, result) -> None:
        if not result:
            return
        self._snapshot()
        old.key = result["key"]
        old.value = result["value"]
        old.raw = old.render()
        self.dirty = True
        self._rebuild_db()
        self._populate_db()

    def _collect_db_refs(self, section: str, key: str):
        """All references to a db entry (section, key): the rules that use
        it across every host ruleset (each as (host, section, Line)) and any
        nested db entries (groups) that list it."""
        rule_refs: list[tuple[str, str, parser.Line]] = []
        for host, lines in self._all_ruleset_lines():
            current_section = "(no section)"
            for l in lines:
                if l.kind == "section":
                    current_section = l.name
                    continue
                if l.kind == "rule" and expand.rule_references(
                        l.value, section, key):
                    rule_refs.append((host, current_section, l))
        db_refs = expand.db_group_refs(self.dblines, section, key)
        return rule_refs, db_refs

    def action_where_used(self) -> None:
        """w: show where the selection is used. On a db entry, show every
        reference to it; on a rule, show where the db objects it references
        are used across all hosts. Enter on a rule line jumps to it."""
        if self.db_mode:
            rk, info = self._selected_row()
            if not info or info[0] != "dbentry":
                self.notify("Select a db entry to inspect", severity="warning")
                return
            e = self.dblines[info[4]]
            section, key = e.section, e.key
            rule_refs, db_refs = self._collect_db_refs(section, key)
            n = len(rule_refs) + len(db_refs)
            self.push_screen(DbReferencesReport(
                section, key, rule_refs, db_refs,
                title=f"Where used: '{key}' ({section}) — {n} reference(s)"),
                self._on_db_ref_jump)
            return
        # rule mode: which db objects does this rule use, and where are they
        # used across all firewalls?
        rk, info = self._selected_row()
        if not info or info[0] != "rule":
            self.notify("Where-used works on a rule or a db entry",
                        severity="warning")
            return
        line = info[1]
        refs = expand.rule_db_refs(line.value, self.db)
        if not refs:
            self.notify("This rule references no db objects",
                        severity="warning")
            return
        rule_refs: list[tuple[str, str, parser.Line]] = []
        for host, lines in self._all_ruleset_lines():
            current = "(no section)"
            for l in lines:
                if l.kind == "section":
                    current = l.name
                    continue
                if l.kind != "rule":
                    continue
                if not any(expand.rule_references(l.value, s, k)
                           for s, k in refs):
                    continue
                # skip the rule being inspected (same host + text)
                if host == self.current_host and l.value == line.value \
                        and l.table == line.table and l.proto == line.proto:
                    continue
                rule_refs.append((host, current, l))
        db_refs: list = []
        seen: set[tuple[str, str]] = set()
        for section, key in refs:
            for l in expand.db_group_refs(self.dblines, section, key):
                if (l.section, l.key) not in seen:
                    seen.add((l.section, l.key))
                    db_refs.append(l)
        obj_label = ", ".join(f"{s}:{k}" for s, k in sorted(refs))
        n = len(rule_refs) + len(db_refs)
        self.push_screen(DbReferencesReport(
            "", "", rule_refs, db_refs,
            title=f"Where used: this rule's db objects ({obj_label}) — "
                  f"{n} reference(s)"),
            self._on_db_ref_jump)

    def _delete_db_entry(self) -> None:
        rk, info = self._selected_row()
        if not info or info[0] != "dbentry":
            self.notify("Select a db entry to delete", severity="warning")
            return
        e = self.dblines[info[4]]
        section, key = e.section, e.key
        # cross-check that nothing still references this entry before deleting:
        # (1) rules in any host ruleset, (2) other db entries (groups).
        rule_refs, db_refs = self._collect_db_refs(section, key)
        if rule_refs or db_refs:
            self.push_screen(DbReferencesReport(
                section, key, rule_refs, db_refs,
                title=f"'{key}' ({section}) is used by "
                      f"{len(rule_refs) + len(db_refs)} reference(s) "
                      f"and can't be deleted."),
                self._on_db_ref_jump)
            return
        self._snapshot()
        if e in self.dblines:
            self.dblines.remove(e)
        self.dirty = True
        self._rebuild_db()
        self._populate_db()

    def _on_db_ref_jump(self, payload) -> None:
        """After a DbReferencesReport closes: jump to the chosen rule."""
        self.screen.refresh()  # defensive: modal pop can leave ghost content
        if not payload:
            return
        if payload[0] == "db":
            self.notify("That is a db reference; select a rule line to jump "
                        "to its host", severity="warning")
            return
        host, section, line = payload
        self._jump_to_reference(host, section, line)

    def _jump_to_reference(self, host: str, section: str, line) -> None:
        """Switch to the host that uses a db entry and highlight the rule.
        Confirms before discarding unsaved edits, like a manual host switch."""
        if host not in self.hosts:
            self.notify(f"Host '{host}' not found", severity="warning")
            return
        if host != self.current_host and self.dirty:
            self._pending_host = host
            self._pending_jump = (section, line)
            self.push_screen(ConfirmSwitch(), self._on_jump_confirm)
            return
        self._perform_jump(host, section, line)

    def _on_jump_confirm(self, result) -> None:
        if result and self._pending_host and self._pending_jump:
            host = self._pending_host
            section, line = self._pending_jump
            self._pending_host = None
            self._pending_jump = None
            self._perform_jump(host, section, line)
        else:
            self._pending_host = None
            self._pending_jump = None

    def _perform_jump(self, host: str, section: str, line) -> None:
        """Ensure the host's ruleset is current, then highlight the rule.
        The reference line came from a separate scan, so it is re-found in
        the in-memory ruleset by (section, value, table, proto) before the
        view selects it (RulesView matches rule rows by object identity)."""
        self._set_db_mode(False)
        if host != self.current_host:
            self._load_ruleset(host)
            # keep the host pulldown in sync with the loaded ruleset
            self.host_select.value = host
        current = "(no section)"
        for l in self.lines:
            if l.kind == "section":
                current = l.name
                continue
            if (l.kind == "rule" and current == section
                    and l.value == line.value
                    and l.table == line.table and l.proto == line.proto):
                line = l
                break
        self._jump_to_rule(line, section)

    def _all_ruleset_lines(self) -> list[tuple[str, list]]:
        """Return (host, lines) for every host ruleset, includes spliced."""
        out: list[tuple[str, list]] = []
        for host in self.hosts:
            lines: list = []
            path = os.path.join(self.fwdir, host)
            if os.path.isfile(path):
                self._load_with_includes(path, lines)
            out.append((host, lines))
        return out

    # -- validate / save ----------------------------------------------------
    def action_validate(self) -> None:
        if not self.current_host:
            self.notify("Select a host ruleset to validate", severity="warning")
            return
        issues = expand.validate_rules(self.lines, self.db)
        issues.extend(expand.validate_chains(self.lines))
        gerrs = expand.validate_globals(self.lines)
        if gerrs:
            issues.append(expand.RuleIssue("global", "", "", "", gerrs, []))
        dupes = expand.validate_duplicate_sections(self.lines)
        if dupes:
            issues.append(expand.RuleIssue("(sections)", "", "", "", dupes, []))
        prowarns = expand.validate_proto_coverage(self.lines)
        if prowarns:
            issues.append(expand.RuleIssue("global", "", "", "", [], prowarns))
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

    def action_git(self) -> None:
        """Show the git history for the current host's ruleset: pick a
        commit, view its diff, load that version. Only available when the
        firewall dir is inside a git repo (see check_action)."""
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
        self._load_with_includes(host, self.lines, content=result["content"])
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
        self.refresh_bindings()
        label = (result["commit"] if result["commit"] == "working tree"
                 else result["commit"][:8])
        self.notify(f"Loaded {label} - review and save (ctrl+s)")

    # -- git ---------------------------------------------------------------
    def _git_info(self) -> tuple[bool, str]:
        """(is_inside_work_tree, repo toplevel) for the firewall dir.
        Cached: the repo status does not change mid-session."""
        if self._git_info_cache is None:
            try:
                proc = subprocess.run(
                    ["git", "-C", self.fwdir, "rev-parse",
                     "--is-inside-work-tree", "--show-toplevel"],
                    capture_output=True, text=True, timeout=10)
                lines = proc.stdout.splitlines()
                ok = (proc.returncode == 0 and len(lines) >= 1
                      and lines[0].strip() == "true")
                root = lines[1].strip() if ok and len(lines) > 1 else ""
                self._git_info_cache = (ok, root)
            except Exception:
                self._git_info_cache = (False, "")
        return self._git_info_cache

    def _git_available(self) -> bool:
        """True when the firewall dir is inside a git work tree."""
        return self._git_info()[0]

    def _git_root(self) -> str:
        """The git repo toplevel for the firewall dir ("" if none)."""
        return self._git_info()[1]

    def check_action(self, action: str,
                     parameters: tuple[object, ...]) -> bool | None:
        """Dynamic key availability: returning True shows a key in the Footer
        (and lets it run), False hides it entirely and makes it a no-op, and
        None shows it dimmed. Availability depends on the active tab, whether
        the shared db view is open, whether a host is selected, and git state."""
        if action == "quit":
            return True
        if action == "help":
            return True  # '?' is always available
        if action == "undo":
            return bool(self.undo_stack)
        if action == "save":
            return self.db_mode or self.current_host is not None
        if action in ("validate", "preview", "deploy"):
            return self.current_host is not None
        if action == "git":
            return self._git_available() and self.current_host is not None
        if self.db_mode:
            # shared db view: add/edit/delete/where-used operate on db entries
            rk, info = self._selected_row()
            kind = info[0] if info else None
            if action == "add":
                return True
            if action == "edit":
                return kind in ("dbsection", "dbentry")
            if action in ("delete", "where_used"):
                return kind == "dbentry"
            return False  # rules-tab actions (n, add-rule) don't apply here
        if self._active_tab() == "global":
            # global settings: only 'e' (edit) applies; a/d/w/n do nothing
            return action == "edit"
        # rules / nat / mangle tabs
        rk, info = self._selected_row()
        kind = info[0] if info else None
        if action == "edit":
            return kind in ("section", "rule", "include")
        if action == "delete":
            return kind in ("section", "rule", "include")
        if action == "where_used":
            return kind == "rule"
        if action == "new_section":
            return True
        if action == "add":
            return self._can_add_rule()
        if action == "focus_tabs":
            return True
        return super().check_action(action, parameters)

    def _can_add_rule(self) -> bool:
        """True when 'a' has a real section to add to: a rule/section/include
        is selected, or a real section is visible in the active tab."""
        rk, info = self._selected_row()
        if info and info[0] in ("rule", "section", "include"):
            return True
        view = self._active_rules_view()
        if view:
            for row in view.rows:
                if row[0] == "section":
                    return True
        return False

    def on_rules_view_selection_changed(self, event) -> None:
        """Selection changed in a rules view: refresh which Footer keys are
        available (add/edit/delete/where-used depend on the selected row)."""
        self.refresh_bindings()

    def on_db_view_selection_changed(self, event) -> None:
        """Selection changed in the db view: refresh the Footer keys."""
        self.refresh_bindings()

    def _offer_commit(self, paths: list[str]) -> None:
        """After a save, offer an optional git commit for the changed files
        (only when they live in a git repo)."""
        if not self._git_available():
            return
        root = os.path.abspath(self._git_root())
        files = [p for p in paths
                 if os.path.abspath(p).startswith(root + os.sep)]
        if not files:
            return
        self.push_screen(CommitModal(files, self.fwdir))

    def action_save(self) -> None:
        if self.db_mode or self.current_host is None:
            with open(self.db_path, "w") as fh:
                fh.write(parser.serialize_db(self.dblines))
            self.dirty = False
            self.notify(f"Saved {os.path.basename(self.db_path)}")
            self._offer_commit([self.db_path])
            return
        # group the spliced lines by their source file (host + includes)
        by_file: dict[str, list] = {}
        for l in self.lines:
            by_file.setdefault(l.source, []).append(l)
        for path, flines in by_file.items():
            with open(path, "w") as fh:
                fh.write(parser.serialize_rules(flines))
        self.dirty = False
        saved = ", ".join(os.path.basename(p) for p in by_file)
        self.notify(f"Saved {saved}")
        self._offer_commit(list(by_file))

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
