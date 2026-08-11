# Firewall TUI — design & history

Original investigation: 2026-08-08 (feasibility of a TUI to manage
`__firewall` rules), followed by a prototype and iterative development.
This document is the design record; the format reference lives in
[format.md](format.md).

## Verdict

**A TUI is very feasible.** The rules and db files are simple, well-documented
INI-style formats with a small, well-defined function vocabulary. The main
design decision is how to handle the free-form iptables rule content:
form-based editing for common patterns + a raw-editor fallback. Textual was
chosen (see "Technology choice") and the working implementation is in this
repo.

## What a TUI could manage

- **db file** (easy — highly structured): services, hosts, networks, groups
  are pure key-value pairs; add/edit/delete/rename, pick from lists in rule
  forms.
- **global section** (easy): 7+ well-defined keys with small value sets
  (accept/drop, true/false, 4/6/4,6) — form-based.
- **Sections** (easy): add/rename/delete/reorder; the section name becomes
  the rule comment.
- **Table tabs** (easy): filter / nat / mangle — the format maps directly
  onto tabs.
- **Common rule patterns** (medium): captured in a builder form (chain,
  source, destination, service, interface, action, NAT target) with a live
  preview; the raw line is always visible and authoritative.
- **Arbitrary iptables lines** (hard — needs raw editor): mangle marks,
  custom chains, raw matches (`-m limit`, `--icmpv6-type`, multiport, ...).
  Every rule row has an "edit raw" mode.

## Challenges (and how they were solved)

1. **Free-form rule content** — solved with the builder-form + raw-text
   hybrid in the rule editor (two-way sync).
2. **INI parsing quirks** — duplicate keys in a section, `[#include]`
   pseudo-sections, `@command` db values, table keys with proto suffixes
   (`filter46`). Python's `configparser` cannot handle this; a line-based
   parser with perfect round-trip fidelity was written (`parser.py`),
   verified byte-identical on all 22 production rulesets.
3. **Validation** — the type's manifest expands functions at deploy time.
   The expansion logic was mirrored in Python (`expand.py`: host, hosts,
   hostgroup, network, networkgroup, service, dservice, dservices, reject,
   log, with DNS fallback). Validation reports per-rule errors/warnings
   instead of aborting. (The type still has an open ToDo: "add option to
   generate rules but not install them", which would make validation
   authoritative.)
4. **No TUI library installed** — Python 3.13 with pip available, but the
   environment is PEP 668 externally-managed; a venv is used.

## Technology choice

| framework | notes |
|---|---|
| **textual** (chosen, 8.2.8) | modern, rich widgets, mouse+keyboard, CSS; best fit for tabs/panels/forms |
| urwid | classic curses, lower-level |
| prompt_toolkit | form/dialog style, less "app" feel |
| npyscreen | older, less maintained |

## Suggested design (original)

Three-column split (hosts | sections | rules with filter/nat/mangle/db
tabs). This was built and then **redesigned** after user feedback — see
"Redesign" below.

## Implementation (current state)

Working features (all in `fwtui/`):

- Browse all rulesets + shared db; host selector + `db` button in the top
  bar (the db is global, not per-ruleset).
- Rules tab: full-width view with sections as spanning header bars and
  rules as 9-column rows (`table | chain | from | sport | to | proto |
  port | action | target`); function args shown as-is, not resolved IPs;
  manual scrolling; mouse support; the status bar shows the raw rule text
  of the selected row.
- **Table tabs**: Rules (filter) / NAT / Mangle each show only their own
  table's rules in the full-width view (the design doc's original "table
  tabs" idea, realized per user request); a section with rules of several
  tables appears in each relevant tab. Sections empty for the current tab
  are hidden by default; `O` reveals them so a rule can be added to an
  existing (for this table empty) section. `o` toggles all headers
  open/closed.
- Implicit rules from `[global]` are shown as dimmed, non-editable groups
  in the Rules tab in the position they occupy in the real deployed ruleset
  (verified against a manifest run): loopback / related-and-established /
  icmp-drop at the top, icmp-allow / log / policy at the bottom.
- Global tab: key/value table, dropdowns for fixed-value keys, add/edit/
  delete.
- db view: collapsible sections (default collapsed), enter edits an entry,
  `e` on a section bar expands and selects its first entry.
- Rule editor: builder form + raw text, two-way sync (debounced so partial
  typing doesn't pollute the dropdowns); DNAT/SNAT rows only shown for NAT
  actions; `a` adds a db entry without leaving the editor; `tab` cycles the
  main components, up/down move between fields.
- Sections & rules: add, edit, rename, delete, reorder (ctrl+up/down;
  sections stay within their file, rules within their section); blank-line
  spacing normalized on section moves; selection preserved after edits.
- `[#include]` support: spliced inline, amber bars, nested includes,
  missing-include markers, edits written back to the source file, save
  writes host file + include files separately.
- Validation (`v`): rule expansion, global values, duplicate sections,
  proto coverage ("no IPv6 rules" warning), `@command` db expansion.
- Preview (`g`): generated iptables rules per proto, mirroring the
  manifest's generation order.
- Deploy (`p`): configurable command in a background worker.
- Git diff (`i`), undo (ctrl+z, 50 deep), filter (`/`), save (ctrl+s) with
  unsaved-changes confirmation on quit.
- Keyboard navigation: host-select <-> tabs <-> content, `esc` returns to
  the menu, compact one-line Selects (NavSelect subclass, `-textual-compact`).

## Redesign (2026-08-08, per user feedback)

The original 3-column split (hosts | sections | rules) was replaced with a
full-width column overview:

- **Top bar**: host selector + current-host / modified indicator + `db` button
- **Tabs**: Rules (filter) | NAT | Mangle | Global | db
- **Rules tab**: custom full-width view (`rulesview.py`); sections as
  full-width header bars (DataTable cannot span cells); rules as 9 columns;
  manual scroll offset; collapsible sections with `▸`/`▾`; the raw rule
  text of the highlighted row in the status bar.
- **NAT / Mangle tabs**: the same full-width view populated with only the
  rules of that table (three `RulesView` instances, one per table tab);
  sections are shared across tabs and shown where they have rules;
  `O` toggles the display of sections empty for the active tab.
- **Implicit rules**: not a section — the `[global]` settings are a separate
  Global tab, and the Rules tab shows what they generate as dimmed groups in
  their real chain position.
- **Global tab**: key/value table of the `[global]` settings.
- **db tab**: full-width key/value table with db sections as group headers.

New modules from the redesign: `columns.py` (rule -> column parser),
`implicit.py` (global settings -> generated rules), `rulesview.py`,
`dbview.py`.

## Current limitations

- No horizontal scrolling in the Rules view (columns clip on narrow
  terminals).
- Long hostnames clip in the from/to columns; the full raw text is shown
  in the status bar for the selected row.
- Validation does DNS lookups (`dig`) which can be slow for many hosts.
- No "generate but don't install" mode in the type yet (would make
  validation authoritative).
- No automated test suite; verified headless via textual's `run_test()`
  and by validating all production rulesets against `expand.py`.
- Save writes the files; committing to git is left to the user (the git
  diff view is there to help).

## History

- 2026-08-08 — investigation, type review (see cdist workspace docs), first
  prototype at `/home/cdist/firewall-tui/` with venv + textual 8.2.8.
- 2026-08-08/09 — iterative development (full-width redesign, includes,
  undo, reorder, validation, preview, deploy, git diff; all verified
  headless on the server).
- 2026-08-09 — commits `ff971e2`, `d0e2f07`, `ff4d8ba`: the full-width
  overview, deploy env vars moved to the config file, and the
  `~/.firewall-tui.conf` override support.
- 2026-08-10 — per-table tabs (Rules/filter, NAT, Mangle): each tab shows
  only its own table's rules; sections with rules of several tables appear
  in each relevant tab; `o` toggles all headers open/closed and `O` toggles
  the display of sections empty for the active tab (so rules can be added
  to an existing section that has no rules in the current view).
- Deployment on the cdist server: `/home/cdist/firewall-tui` (git repo,
  same remote as this repository), per-user config
  `/home/cdist/.firewall-tui.conf` overriding `deploy_command` to
  `runcdist -o firewall {host}`.
