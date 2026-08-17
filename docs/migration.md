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
                [--existing-db path/db [--apply-db] [--batch]] \
                [--policy accept|drop] [--proto 4|6|4,6] \
                [--established true|false] [--icmp true|false]
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
- `--policy`   default policy for the generated ruleset (`drop` default).
- `--proto`    IP versions to generate rules for: `4`, `6` or `4,6`
  (default `4,6`).
- `--established` allow related/established traffic (`true` default).
- `--icmp`     allow icmp at the bottom of the ruleset (default: rely on
  the explicit rules).

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
- **Globals**: `policy`/`proto`/`established` come from the CLI options
  (defaults `drop`/`4,6`/`true`); the final "deny all, log" rule adds
  `log=Unmatched traffic`; loopback rules are converted as normal rules and
  the implicit `loopback` global is disabled (`loopback=false`); `--icmp`
  sets the `icmp` global.
- **NAT rules → nat table**: DNAT uses the rule's own public destination IP
  when present (else the first public firewall IP), with port translation
  when the translated service differs; SNAT uses the fwbuilder translate-to
  (TSrc) address when present (else a LAN/public heuristic). Hairpin SNAT is
  emitted when the DNAT source is restricted.
- **Port ranges** are preserved as `start:end/proto` (e.g. `1000:2000/tcp`).
- **`reject()`** uses `reject(reset)` only for all-TCP rules, otherwise
  `reject(unreachable)` (tcp-reset is invalid for UDP/icmp).
- **`dservices()`** is chunked into ≤15 ports per line (the manifest's
  multiport limit).
- fwbuilder's user chains/jumps are gone by construction (rules are read
  from the logical Policy/NAT rules, not the generated iptables).

## Caveats to review after conversion

1. **`proto=4,6` by default.** A project with only IPv4 rules produces a
   strict empty IPv6 drop-all firewall (the manifest warns "no IPv6 rules
   defined"). Pass `--proto 4` if the firewall has no IPv6 policy.

2. **The db is standalone (unless `--existing-db`).** Without it, the
   converter writes a self-contained `<name>.db`, but production uses the
   shared `…/firewall/db`. Pass `--existing-db` to reconcile against and
   optionally `--apply-db` to merge the new entries directly (see
   "Interactive reconciliation" above). Several names may already exist in
   the shared db.

3. **Interface references are resolved to their networks.** A rule whose
   Src/Dst references a firewall `Interface` object is mapped to the
   network(s) that interface serves (e.g. `eth1` → `-d network(eth1)`), and
   LAN-interface destinations are placed on `FORWARD`. Interface
   restrictions via a rule group name are still only applied when the group
   name matches an interface name; a near-miss (e.g. `eth` vs `eth0`) emits a
   warning instead of being silently dropped.

4. **mangle rules are not converted.** If the project has a Mangle ruleset,
   a warning is emitted; those rules must be ported manually.

5. **`--policy` default is `drop`.** If the source firewall uses a
   default-accept policy with explicit denies, pass `--policy accept`.

6. **DNAT/SNAT heuristics.** DNAT uses the rule's own public destination IP
   when present, else the first public IP; SNAT uses the fwbuilder
   translate-to when present, else a LAN/public guess. Review the generated
   NAT rules and any warnings.

7. **`Both`-direction rules** are emitted in INPUT, OUTPUT and FORWARD (a
   warning is emitted); review whether each chain is intended.

## Validation

The output is validated the same way the TUI validates any ruleset: it must
parse with `fwtui.parser` and pass `fwtui.expand.validate_rules`, and it must
generate cleanly through the `__firewall` manifest (the TUI's `p` preview
does the latter via `FWTUI_GENERATE`).
