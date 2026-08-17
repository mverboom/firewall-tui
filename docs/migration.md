# Migrating from fwbuilder to the __firewall type

`fwbuilder2cdist` converts a fwbuilder project (`.fwb`, XML) into the
`__firewall` ruleset + db format that this TUI manages. It was written to
migrate the fwbuilder-managed firewalls (gan, knowing, ferrari, sheppard,
jack) to the cdist `__firewall` type.

The generated files open directly in this TUI: they parse and validate
cleanly and deploy through the `__firewall` manifest.

## Usage

```
fwbuilder2cdist --fwb firewall.fwb --firewall Sheppard \
                [--outdir out/] [--output-name sheppard.cnw.verboom.net] \
                [--existing-db path/db [--apply-db] [--batch]]
```

- `--fwb`      the fwbuilder project file (XML).
- `--firewall` the firewall name as it appears in the project.
- `--output-name` base name for the output files (defaults to the firewall
  name). `--outdir` defaults to the current directory.
- `--existing-db` reconcile the generated entries against the shared cdist
  db instead of writing a standalone `<name>.db` (see below).
- `--apply-db` append the genuinely new entries into `--existing-db`
  (a `.bak` copy is written first).
- `--batch`    non-interactive: auto-accept the safe default for any
  ambiguous entry (used automatically when stdin is not a terminal).

Without `--existing-db` it writes `<name>.rules` + `<name>.db`. With
`--existing-db` it writes `<name>.rules` (names rewritten to the shared db)
and `<name>.new.db` (the entries to merge), plus a reconciliation report.

## Interactive reconciliation against the shared db

Production uses one shared `…/firewall/db`, so migrated entries have to be
matched to what's already there. With `--existing-db`, every generated
service/host/network/group is classified against the shared db:

- **exact match** (same name + same value) — reused, no action;
- **same value, different name** — auto-mapped to the existing name (rules
  are rewritten to use it), keeping the shared db canonical;
- **same name, different value** — genuine conflict: prompts whether to keep
  the existing value, add the generated one under a new name, or skip;
- **several value matches** — prompts which existing entry to map to;
- **new** — kept and written to `<name>.new.db` to merge.

Group members are matched after their referenced leaves are mapped, so e.g.
`hostgroup(lanclients)` whose members are re-merged onto existing hosts maps
onto an existing `[hostgroups]` entry by value. Rules (and group definitions)
are rewritten to the final names via `host()`/`dservice()`/`hostgroup()`/etc.

`--batch` (or a non-terminal stdin) applies the safe defaults — keep existing
on a same-name conflict, map on an unambiguous value match, add genuinely new
entries — without prompting.

## What it maps

- **Objects**: Hosts (all interface IPs, v4+v6) → `[hosts]`; Networks →
  `[networks]`; TCP/UDP services → `[services]` (tcp/udp name collisions get
  a `_tcp` suffix, matching the existing db convention); ICMP services →
  `icmp[/<type>]`; ObjectGroups → host/network/servicegroups.
- **PolicyRule → rule**: group → section; direction + src/dst topology →
  `INPUT`/`OUTPUT`/`FORWARD`; src/dst → `host()`/`network()`/literals;
  services → `dservice()`/`dservices()` (mixed protos split into separate
  lines); action → `ACCEPT`/`DROP`/`reject()`; `log` → `log()`.
- **Globals**: the final "deny all, log" rule → `policy=drop` +
  `log=Unmatched traffic`; the loopback rule → the `loopback` global;
  `established=true`.
- **NAT rules → nat table**: DNAT (to the first public firewall IP, with port
  translation when the translated service differs) and SNAT (to the public or
  LAN address depending on the destination). Hairpin SNAT is emitted when the
  DNAT source is restricted.
- fwbuilder's user chains/jumps are gone by construction (rules are read
  from the logical Policy/NAT rules, not the generated iptables).

## Caveats to review after conversion

1. **Always emits `proto=4,6`.** A project with only IPv4 rules produces a
   strict empty IPv6 drop-all firewall (the manifest warns "no IPv6 rules
   defined"). Check the generated `[global]` `proto` line; if the firewall
   has no IPv6 policy, set `proto=4`.

2. **The db is standalone (unless `--existing-db`).** Without it, the
   converter writes a self-contained `<name>.db`, but production uses the
   shared `…/firewall/db`. Pass `--existing-db` to reconcile against and
   optionally `--apply-db` to merge the new entries directly (see
   "Interactive reconciliation" above). Several names may already exist in
   the shared db.

3. **Interface objects warn.** A rule whose src/dst references a firewall
   `Interface` object directly is dropped with "unhandled address object
   Interface …". Interface restrictions are otherwise kept only when the rule
   group name matches a firewall interface name (e.g. `Openvpn` → `-i openvpn`).
   Review the warnings per rule.

4. **DNAT destination IP.** DNAT rules all use the first public firewall IP;
   fwbuilder may have used a different address for specific rules. Adjust per
   rule if needed.

5. **`dservices()` > 15 ports** is rejected by the manifest at deploy time
   (rare — multiport limit).

## Validation

The output is validated the same way the TUI validates any ruleset: it must
parse with `fwtui.parser` and pass `fwtui.expand.validate_rules`, and it must
generate cleanly through the `__firewall` manifest (the TUI's `p` preview
does the latter via `FWTUI_GENERATE`).
