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
                [--outdir out/] [--output-name sheppard.cnw.verboom.net]
```

- `--fwb`      the fwbuilder project file (XML).
- `--firewall` the firewall name as it appears in the project.
- `--output-name` base name for the output files (defaults to the firewall
  name). `--outdir` defaults to the current directory.
- Writes `<name>.rules` and `<name>.db`, prints warnings to stderr.

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

2. **The db is standalone.** The converter writes a self-contained
   `<name>.db`, but production uses the shared `…/firewall/db`. Merge the
   generated `[services]/[hosts]/[networks]/…` entries into the shared db
   before deploying. Several names may already exist there.

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
