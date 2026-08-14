"""Function expansion and validation for __firewall rules.

Mirrors the expansion logic in the type's manifest (doexpand) so rules can be
validated before writing. Returns errors/warnings per rule rather than
aborting, so the TUI can show them inline.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field

from .parser import global_lines, rules_in_section

# ---------------------------------------------------------------------------
# db access
# ---------------------------------------------------------------------------

class Db:
    """Lookup container mirroring the manifest's associative arrays."""

    def __init__(self, lines=None):
        self.services: dict[str, str] = {}
        self.servicegroups: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.hostgroups: dict[str, str] = {}
        self.networks: dict[str, str] = {}
        self.networkgroups: dict[str, str] = {}
        if lines:
            self.load(lines)

    def load(self, lines) -> None:
        section = None
        for l in lines:
            if l.kind == "section":
                section = l.section
            elif l.kind == "entry" and section:
                table = getattr(self, section, None)
                if isinstance(table, dict):
                    val = l.value
                    if val.startswith("@"):
                        val = _run_command(val[1:])
                    table[l.key] = val


def _run_command(cmd: str) -> str:
    """Run a db @command value, mirroring the manifest's bash -c expansion."""
    try:
        out = subprocess.run(["bash", "-c", cmd], capture_output=True,
                             text=True, timeout=5)
        return out.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


# ---------------------------------------------------------------------------
# helpers mirroring the manifest
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r"^(([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?)$")
IPV6_RE = re.compile(r"^([a-fA-F0-9]{0,4}:){1,8}[a-fA-F0-9]{0,4}$")

# icmpv4 type -> icmpv6 type mapping from the manifest
ICMPV6_MAP = {
    "8": "128", "0": "129", "3": "1", "4": "2", "5": "137",
    "11": "3", "12": "4", "13": "130", "14": "131", "17": "134",
    "18": "135", "9": "138", "10": "139",
}


def chkproto(ip: str) -> int | None:
    if IPV4_RE.match(ip):
        return 4
    if IPV6_RE.match(ip):
        return 6
    return None


def _dig(name: str, proto: int) -> str | None:
    """DNS lookup, mirroring the manifest's dig fallback."""
    t = "A" if proto == 4 else "AAAA"
    try:
        out = subprocess.run(
            ["dig", "+short", "+search", name, t],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip().splitlines()
        return out[-1] if out else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# expansion
# ---------------------------------------------------------------------------

@dataclass
class Result:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    expanded: str = ""


def expand_rule(text: str, db: Db, proto: int, log_prefix: str = "firewall") -> Result:
    """Expand all functions in one rule line for a given IP proto (4 or 6).

    Mirrors the manifest's line parser: repeatedly finds the first
    func(args) token, expands it, and stitches the result back together.
    """
    res = Result()
    rule = text
    guard = 0
    while len(rule) > 0 and guard < 100:
        guard += 1
        m = re.search(r"(^|[^(]*[ .:-;])([^( .:-;]+\([^)]+\))", rule)
        if not m:
            res.expanded = rule
            return res
        expansion = m.group(2)
        pos = m.start(2)
        rest = rule[m.end(2):]
        funcname = expansion[: expansion.index("(")]
        args = expansion[expansion.index("(") + 1: -1]

        # hostgroup/networkgroup/dns: check for -s/-d before the function
        if funcname in ("hostgroup", "networkgroup", "dns"):
            prefix = rule[:pos].rstrip()
            if re.search(r"(^|\s)-[sd](\s|$)", prefix):
                res.errors.append(
                    f"Do not use -s/-d before {funcname}(); append the set "
                    f"match flag instead, e.g. '{funcname}({args}) src'"
                )

        expanded, errs, warns = _expand_one(funcname, args, db, proto, log_prefix)
        res.errors.extend(errs)
        res.warnings.extend(warns)
        rule = rule[:pos] + expanded + rest
    res.expanded = rule
    return res


def _expand_one(funcname: str, args: str, db: Db, proto: int,
                log_prefix: str) -> tuple[str, list[str], list[str]]:
    errs: list[str] = []
    warns: list[str] = []

    if funcname == "reject":
        if args == "reset":
            return "-j REJECT --reject-with tcp-reset", errs, warns
        if args == "unreachable":
            if proto == 6:
                return "-j REJECT --reject-with icmp6-port-unreachable", errs, warns
            return "-j REJECT --reject-with icmp-port-unreachable", errs, warns
        if args == "prohibited":
            if proto == 6:
                return "-j REJECT --reject-with icmp6-adm-prohibited", errs, warns
            return "-j REJECT --reject-with icmp-admin-prohibited", errs, warns
        errs.append(f"Unknown reject type '{args}' (reset|unreachable|prohibited)")
        return args, errs, warns

    if funcname == "log":
        return f'-j NFLOG --nflog-prefix "{args.replace("%", " ")} "', errs, warns

    if funcname == "service":
        svc = db.services.get(args)
        if svc is None:
            errs.append(f"Service '{args}' not found in db")
            return args, errs, warns
        return svc.split("/")[0], errs, warns

    if funcname == "dservice":
        svc = db.services.get(args)
        if svc is None:
            errs.append(f"Service '{args}' not found in db")
            return args, errs, warns
        if svc == "icmp":
            return ("-p ipv6-icmp" if proto == 6 else "-p icmp"), errs, warns
        if svc.startswith("icmp/"):
            t = svc.split("/", 1)[1]
            if proto == 6:
                if t == "-1":
                    return "-p ipv6-icmp", errs, warns
                return f"-p ipv6-icmp --icmpv6-type {ICMPV6_MAP.get(t, t)}", errs, warns
            if t == "-1":
                return "-p icmp", errs, warns
            return f"-p icmp --icmp-type {t}", errs, warns
        port, pr = svc.split("/", 1)
        return f"-p {pr} --dport {port}", errs, warns

    if funcname == "dservices":
        if args in db.servicegroups:
            svcs = db.servicegroups[args].split(",")
        else:
            svcs = args.split(",")
        ports: list[str] = []
        sproto: str | None = None
        for s in svcs:
            svc = db.services.get(s.strip())
            if svc is None:
                errs.append(f"Service '{s}' not found in db")
                continue
            port, pr = svc.split("/", 1)
            if sproto is not None and sproto != pr:
                errs.append(
                    f"Service group '{args}' mixes protocols ({sproto} and {pr}); "
                    f"split the rule"
                )
            sproto = pr
            ports.append(port)
        if len(ports) > 15:
            errs.append(f"Service group '{args}' has more than 15 ports; split the rule")
        if sproto is None:
            return args, errs, warns
        return f"-p {sproto} -m multiport --dports {','.join(ports)}", errs, warns

    if funcname == "host":
        ip = _hostlookup(args, db, proto, errs, warns)
        return ip, errs, warns

    if funcname == "hosts":
        ips = []
        for h in args.split(","):
            ips.append(_hostlookup(h.strip(), db, proto, errs, warns))
        return ",".join(ips), errs, warns

    if funcname == "hostgroup":
        if args not in db.hostgroups:
            errs.append(f"Hostgroup '{args}' not found in db")
            return args, errs, warns
        return f"-m set --match-set {proto}-ip-{args}", errs, warns

    if funcname == "dns":
        # DNS-resolved host: ipset match, contents managed by the periodic
        # firewall-dns resolver. No db lookup; the name is a domain.
        return f"-m set --match-set {proto}-dns-{args}", errs, warns

    if funcname == "network":
        net = _netlookup(args, db, proto, errs, warns)
        return net, errs, warns

    if funcname == "networkgroup":
        if args not in db.networkgroups:
            errs.append(f"Networkgroup '{args}' not found in db")
            return args, errs, warns
        return f"-m set --match-set {proto}-net-{args}", errs, warns

    errs.append(f"Unknown function '{funcname}()'")
    return args, errs, warns


def _hostlookup(name: str, db: Db, proto: int, errs: list[str],
                warns: list[str]) -> str:
    p = chkproto(name)
    if p == proto:
        return name
    parts = db.hosts.get(name, "").split()
    for val in parts:
        if chkproto(val) == proto:
            return val
    # DNS fallback (mirrors manifest)
    ip = _dig(name, proto)
    if ip:
        warns.append(f"Host '{name}' resolved via DNS (not in db)")
        return ip
    # the manifest aborts on this; report it as an error
    errs.append(f"Host '{name}' not in db and DNS lookup failed")
    return name


def _netlookup(name: str, db: Db, proto: int, errs: list[str],
               warns: list[str]) -> str:
    p = chkproto(name.split("/", 1)[0])
    if p == proto:
        return name
    parts = db.networks.get(name, "").split()
    for val in parts:
        if chkproto(val.split("/", 1)[0]) == proto:
            return val
    # the manifest aborts on this; report it as an error
    errs.append(f"Network '{name}' not found in db for IPv{proto}")
    return name


# ---------------------------------------------------------------------------
# db entry validation
# ---------------------------------------------------------------------------

def validate_db_value(section: str, value: str, db: Db | None = None) -> list[str]:
    """Validate a db entry value for its section. Returns error messages
    (empty = valid). @command values are not validated (their output is only
    known at runtime); group lists are checked against the db when given."""
    if not value:
        return ["value is empty"]
    if value.startswith("@"):
        return []
    if section == "services":
        return _validate_service_value(value)
    if section == "hosts":
        return _validate_ip_list(value)
    if section == "networks":
        return _validate_network_list(value)
    if section in ("servicegroups", "hostgroups", "networkgroups"):
        table = {"servicegroups": "services", "hostgroups": "hosts",
                 "networkgroups": "networks"}[section]
        return _validate_group_list(value, db, table)
    return []


def _validate_service_value(value: str) -> list[str]:
    """services: name=port/proto, or icmp[/type]."""
    if value == "icmp":
        return []
    if value.startswith("icmp/"):
        if not value.split("/", 1)[1]:
            return ["icmp type is missing (use icmp or icmp/<type>)"]
        return []
    if "/" not in value:
        return ["expected '<port>/<proto>' (e.g. 22/tcp) or icmp[/<type>]"]
    port, proto = value.split("/", 1)
    errs = []
    if not (re.fullmatch(r"\d+", port) or re.fullmatch(r"\d+:\d+", port)):
        errs.append(f"invalid port '{port}' (use e.g. 22 or 1000:2000)")
    if not proto or any(c.isspace() for c in proto):
        errs.append(f"invalid protocol '{proto}'")
    return errs


def _validate_ip_list(value: str) -> list[str]:
    """hosts: name=IP [IP...] (v4 and/or v6)."""
    errs = []
    for tok in value.split():
        if not _is_ip_or_cidr(tok):
            errs.append(f"'{tok}' is not a valid IP address")
    return errs


def _validate_network_list(value: str) -> list[str]:
    """networks: name=network/mask [network...]."""
    errs = []
    for tok in value.split():
        if "/" not in tok:
            errs.append(f"'{tok}' is missing a mask (use e.g. 192.168.0.0/24)")
            continue
        try:
            ipaddress.ip_network(tok, strict=False)
        except ValueError:
            errs.append(f"'{tok}' is not a valid network/mask "
                        "(e.g. 192.168.0.0/24)")
    return errs


def _is_ip_or_cidr(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _validate_group_list(value: str, db: Db | None, table: str) -> list[str]:
    """servicegroups/hostgroups/networkgroups: comma-separated member names."""
    errs = []
    toks = [t.strip() for t in value.split(",")]
    if any(not t for t in toks):
        errs.append("empty name in comma-separated list")
    if db is not None:
        known = getattr(db, table, {})
        for t in toks:
            if t and t not in known:
                errs.append(f"unknown {table.rstrip('s')} '{t}'")
    return errs


# ---------------------------------------------------------------------------
# whole-file validation
# ---------------------------------------------------------------------------

@dataclass
class RuleIssue:
    section: str
    table: str
    proto: str
    text: str
    errors: list[str]
    warnings: list[str]


def validate_rules(lines, db: Db) -> list[RuleIssue]:
    """Validate every rule in a parsed rules file. Returns issues (no raise)."""
    issues: list[RuleIssue] = []
    current_section = "(no section)"
    for l in lines:
        if l.kind in ("section", "include"):
            current_section = l.name
            continue
        if l.kind == "rule":
            protos = ("4", "6") if l.proto == "46" else (l.proto or "4",)
            for p in protos:
                res = expand_rule(l.value, db, int(p))
                if res.errors or res.warnings:
                    issues.append(RuleIssue(
                        section=current_section, table=l.table, proto=l.proto,
                        text=l.value, errors=res.errors, warnings=res.warnings,
                    ))
    return issues


def validate_globals(lines) -> list[str]:
    """Check global section values (policy, proto, etc.)."""
    errs: list[str] = []
    globals_ = {l.key: l.value for l in lines if l.kind == "global"}
    policy = globals_.get("policy", "accept")
    for chain in ("", "_input", "_output", "_forward"):
        p = globals_.get(f"policy{chain}", policy)
        if p.lower() not in ("accept", "drop"):
            errs.append(f"policy{chain}: '{p}' must be accept or drop")
    proto = globals_.get("proto", "4")
    if proto not in ("4", "6", "4,6"):
        errs.append(f"proto: '{proto}' must be 4, 6 or 4,6")
    for k in ("established", "icmp", "loopback", "packageinstall"):
        if k in globals_ and globals_[k] not in ("true", "false"):
            errs.append(f"{k}: '{globals_[k]}' must be true or false")
    return errs


def validate_duplicate_sections(lines) -> list[str]:
    """Flag section names defined more than once (the manifest errors on
    these with 'Section X redefined')."""
    seen: dict[str, str] = {}
    errs: list[str] = []
    for l in lines:
        if l.kind == "section" and l.name != "global":
            if l.name in seen:
                errs.append(
                    f"Section '{l.name}' redefined (first in "
                    f"{seen[l.name]}, again in {l.source})")
            else:
                seen[l.name] = l.source
    return errs


def validate_proto_coverage(lines) -> list[str]:
    """Warn when a configured proto has no rules at all (the manifest emits
    this warning; the chain policy then applies to all that proto's traffic)."""
    globals_ = {l.key: l.value for l in lines if l.kind == "global"}
    proto = globals_.get("proto", "4")
    protos = [p for p in (4, 6) if str(p) in proto.split(",")]
    counts = {4: 0, 6: 0}
    for l in lines:
        if l.kind == "rule":
            if l.proto in ("", "4"):
                counts[4] += 1
            elif l.proto == "6":
                counts[6] += 1
            elif l.proto == "46":
                counts[4] += 1
                counts[6] += 1
    warns: list[str] = []
    for p in protos:
        if counts[p] == 0:
            warns.append(
                f"No IPv{p} rules defined; "
                f"{globals_.get('policy', 'accept')} policy applies to "
                f"all IPv{p} traffic")
    return warns


def generate_preview(lines, db) -> dict[int, list[str]]:
    """Generate the effective iptables rules per proto, mirroring the
    manifest's generation order (established, icmp drop, section rules
    grouped filter/nat/mangle, icmp allow, policy, loopback, log).
    Returns {4: [lines], 6: [lines]}."""
    globals_ = {l.key: l.value for l in global_lines(lines)}
    proto = globals_.get("proto", "4")
    protos = [p for p in (4, 6) if str(p) in proto.split(",")]
    out: dict[int, list[str]] = {p: [] for p in protos}
    for p in protos:
        if globals_.get("established") == "true":
            for chain in ("INPUT", "OUTPUT", "FORWARD"):
                out[p].append(
                    f"-A {chain} -m conntrack --ctstate RELATED,ESTABLISHED "
                    f"-j ACCEPT")
        if globals_.get("icmp") == "false":
            icmp = "ipv6-icmp" if p == 6 else "icmp"
            out[p].append(f"-A INPUT -p {icmp} -j DROP")
        last_section = None
        for l in lines:
            if l.kind == "section" and l.name != "global":
                rules = rules_in_section(lines, l)
                for table in ("filter", "nat", "mangle"):
                    for r in rules:
                        if r.table != table:
                            continue
                        if p == 4 and r.proto not in ("", "4", "46"):
                            continue
                        if p == 6 and r.proto not in ("6", "46"):
                            continue
                        if l.name != last_section:
                            out[p].append(f"# {l.name}")
                            last_section = l.name
                        res = expand_rule(r.value, db, p)
                        if res.errors:
                            out[p].append(
                                f"# ERROR: {'; '.join(res.errors)}")
                        out[p].append(res.expanded)
        if globals_.get("icmp") == "true":
            icmp = "ipv6-icmp" if p == 6 else "icmp"
            out[p].append(f"-A INPUT -p {icmp} -j ACCEPT")
        policy = globals_.get("policy", "accept")
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            cp = globals_.get(f"policy_{chain.lower()}", policy)
            out[p].append(f"-P {chain} {cp.upper()}")
        if policy == "drop" and globals_.get("loopback") != "false":
            out[p].append("-I INPUT -i lo -j ACCEPT")
            out[p].append("-I OUTPUT -o lo -j ACCEPT")
        log = globals_.get("log")
        if log:
            for chain in ("INPUT", "OUTPUT", "FORWARD"):
                out[p].append(
                    f'-A {chain} -j NFLOG --nflog-prefix "{log} "')
    return out
