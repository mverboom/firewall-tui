# __firewall ruleset & db format

This is the file format managed by the TUI — the same format read by the
cdist `__firewall` type (`/home/cdist/files.external/cdist-types.git/__firewall`).
The TUI's `parser.py` implements a line-based parser with round-trip
fidelity (untouched lines keep their exact raw text), because Python's
`configparser` cannot handle this format (duplicate keys, `[#include]`
pseudo-sections, `@command` values).

Production layout on the cdist server:

- Rulesets: `/home/cdist/config/files/firewall/<fqdn>` (one file per host)
- Shared db: `/home/cdist/config/files/firewall/db`
- Invocation (manifest/autorun/firewall):
  `__firewall --rules "$BASE/$e_fqdn" --db "$BASE/db"`

## Rules file (per host)

```
[global]                    # policy, established, icmp, proto, log,
                            # loopback, packageinstall, policy_* , log_*
policy=accept|drop
established=true
icmp=true
proto=4|6|4,6
log=prefix

[section description]       # groups rules; used as the rule comment
filter=-A INPUT -s host(proxy) dservice(https) -j ACCEPT
filter6=-A INPUT ...
nat=-A PREROUTING dservice(ssh) --destination host(x) -j DNAT \
     --to-destination host(y):service(ssh)
mangle=-A PREROUTING -j CONNMARK --restore-mark
```

- **Tables**: `filter`, `nat`, `mangle`, optionally suffixed `4`, `6` or
  `46` for the IP version(s) the rule applies to (`filter46` runs for both).
  A rule with no suffix (e.g. `filter=`) applies to IPv4 only.
- **Global keys**: `policy`, `policy_input`, `policy_output`,
  `policy_forward`, `established`, `icmp`, `proto`, `log`, `log_input`,
  `log_forward`, `log_output`, `loopback`, `packageinstall`.
- `[#filename]` is a **pseudo-section**: include the file of that name from
  the includedir (defaults to the firewall dir). Includes are read
  recursively. Defined but unused by the current rulesets.
- Lines starting with `#` are comments (ignored by the parser, preserved on
  write).
- A section defined more than once is an error in the manifest ("Section ...
  redefined"); the TUI flags it too.

## Shared db file

```
[services]        name=port/proto        or  icmp[/type]
[servicegroups]   name=comma,list,of,services
[hosts]           name=IP [IP...]        (space separated for v4+v6)
[hostgroups]      name=comma,list,of,hosts
[networks]        name=network/mask [network...]
[networkgroups]   name=comma,list,of,networks
```

- Values may start with `@` to execute a command and use its output
  (e.g. `test2=@echo "shell,proxy"`).
- `[hosts]` entries can hold several IPs (v4 and v6); the expansion picks
  the one matching the rule's proto.
- ICMP services: `name=icmp` (all types) or `name=icmp/<type>`; the type
  manifest maps the common icmpv4 type numbers to their icmpv6 counterparts
  for IPv6 rules.

## Functions

Embedded in rule text, expanded by the manifest at deploy time (and mirrored
by the TUI's `expand.py` for validation):

| function | expansion | notes |
|---|---|---|
| `host(name)` | the host's IP for this proto | db `[hosts]`, then DNS fallback |
| `hosts(a,b)` | comma-separated IPs | |
| `hostgroup(name)` | `-m set --match-set <proto>-ip-<name>` | must be followed by `src`/`dst`; do **not** put `-s`/`-d` before it |
| `network(name)` | `network/mask` | db `[networks]`, per proto |
| `networkgroup(name)` | `-m set --match-set <proto>-net-<name>` | same `src`/`dst` rule as hostgroup |
| `service(name)` | the port number | proto taken from the db |
| `dservice(name)` | `-p <proto> --dport <port>` | icmp: `-p icmp` / `-p ipv6-icmp`, `--icmp-type` / `--icmpv6-type` |
| `dservices(list\|group)` | `-p <proto> -m multiport --dports a,b,c` | single proto, max 15 ports |
| `reject(reset\|unreachable\|prohibited)` | `-j REJECT --reject-with ...` | v6 rules use the `icmp6-*` variants |
| `log(prefix)` | `-j NFLOG --nflog-prefix "<prefix> "` | |

## Common patterns seen in production

- Allow a service from a host:
  `filter=-A INPUT -s host(x) dservice(y) -j ACCEPT`
- Allow + drop/reject the rest:
  `filter=-A INPUT dservice(x) reject(unreachable)` / `filter=-A INPUT -j DROP`
- NAT port forward:
  `nat=-A PREROUTING dservice(x) --destination host(y) -j DNAT --to-destination host(z):service(x)`
- SNAT / MASQUERADE:
  `nat=-A POSTROUTING -o eth0 -s network(x) -j SNAT --to-source host(y)`
- Mangle marks / custom chains:
  `mangle=:chain - [0:0]` (chain definition),
  `mangle=-A PREROUTING -j MARK --set-mark N`
- ipset groups:
  `filter=-A INPUT hostgroup(sipclients) src -d host(...) dservice(sip) -j ACCEPT`

## Generation order (what the manifest emits)

For each configured proto (from `global[proto]`):

1. `loopback` — `-I INPUT -i lo -j ACCEPT` / `-I OUTPUT -o lo -j ACCEPT`
   (only when policy is drop), inserted at the **top** of the chain
2. `related and established` — `-A <chain> -m conntrack --ctstate
   RELATED,ESTABLISHED -j ACCEPT` for INPUT/OUTPUT/FORWARD
3. `icmp=false` — `-A INPUT -p icmp|ipv6-icmp -j DROP` (before the rules)
4. the section rules, grouped filter / nat / mangle, in file order
5. `icmp=true` — `-A INPUT -p icmp|ipv6-icmp -j ACCEPT` (after the rules)
6. `log` — `-A <chain> -j NFLOG --nflog-prefix "<log> "` appended to each chain
7. policy — `-P <chain> <POLICY>` (per-chain overrides `policy_input`,
   `policy_output`, `policy_forward`)

The TUI's Rules tab renders these implicit rules in this same position, so
the overview matches the deployed ruleset.
