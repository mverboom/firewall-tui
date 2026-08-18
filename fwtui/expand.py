"""Function expansion and validation for __firewall rules.

Mirrors the expansion logic in the type's manifest (doexpand) so rules can be
validated before writing. Returns errors/warnings per rule rather than
aborting, so the TUI can show them inline.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field

from .parser import global_dict, rules_in_section

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
        self.geoip: dict[str, str] = {}  # [geoip] maxminddir=...
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
        # log(prefix[,rate]) -> -j NFLOG --nflog-prefix "<prefix> " [-m limit --limit <rate>]
        parts = args.split(",", 1)
        prefix = parts[0]
        rate = parts[1].strip() if len(parts) > 1 else ""
        out = f'-j NFLOG --nflog-prefix "{prefix.replace("%", " ")} "'
        if rate:
            if not re.fullmatch(r"\d+/(sec|min|hour|day)", rate):
                errs.append(f"log: rate '{rate}' must be like 10/min "
                            f"(N/sec|min|hour|day)")
                return args, errs, warns
            out += f" -m limit --limit {rate}"
        return out, errs, warns

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
        if args in db.networkgroups:
            _resolve_networkgroup(db, args, (), errs)
        elif args.startswith("G_"):
            _resolve_country(db, args, errs)
        else:
            errs.append(f"Networkgroup '{args}' not found in db")
        return f"-m set --match-set {proto}-net-{args}", errs, warns

    if funcname == "limit":
        # limit(rate[,burst]) -> -m limit --limit <rate> [--limit-burst <burst>]
        parts = args.split(",", 1)
        rate = parts[0].strip()
        burst = parts[1].strip() if len(parts) > 1 else ""
        if not re.fullmatch(r"\d+/(sec|min|hour|day)", rate):
            errs.append(f"limit: rate '{rate}' must be like 10/min "
                        f"(N/sec|min|hour|day)")
            return args, errs, warns
        out = f"-m limit --limit {rate}"
        if burst:
            if not re.fullmatch(r"\d+", burst):
                errs.append(f"limit: burst '{burst}' must be a positive integer")
                return args, errs, warns
            out += f" --limit-burst {burst}"
        return out, errs, warns

    if funcname == "state":
        # state(NEW,ESTABLISHED) -> -m conntrack --ctstate NEW,ESTABLISHED
        states = [s.strip() for s in args.split(",")]
        valid = {"NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"}
        for s in states:
            if s not in valid:
                errs.append(f"state: unknown ctstate '{s}' "
                            f"(NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED)")
        if errs:
            return args, errs, warns
        return f"-m conntrack --ctstate {','.join(states)}", errs, warns

    if funcname == "time":
        # time(start-stop[,weekdays]) -> -m time --timestart <start> --timestop <stop> [--weekdays <days>]
        parts = args.split(",", 1)
        times = parts[0].strip()
        weekdays = parts[1].strip() if len(parts) > 1 else ""
        if "-" not in times:
            errs.append(f"time: '{times}' must be like 08:00-18:00")
            return args, errs, warns
        start, stop = times.split("-", 1)
        if not re.fullmatch(r"\d{2}:\d{2}", start):
            errs.append(f"time: start '{start}' must be HH:MM")
        if not re.fullmatch(r"\d{2}:\d{2}", stop):
            errs.append(f"time: stop '{stop}' must be HH:MM")
        out = f"-m time --timestart {start} --timestop {stop}"
        if weekdays:
            days = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
            for d in weekdays.split(","):
                d = d.strip()
                # single day (Mon) or a range (Mon-Fri)
                if d not in days and not (
                        "-" in d and d.split("-", 1)[0] in days
                        and d.split("-", 1)[1] in days):
                    errs.append(f"time: unknown weekday '{d}' (Mon..Sun)")
            out += f" --weekdays {weekdays}"
        if errs:
            return args, errs, warns
        return out, errs, warns

    if funcname == "recent":
        # recent(set) -> -m recent --set
        # recent(check[,seconds[,hitcount]]) -> -m recent --update [--seconds N] [--hitcount N]
        parts = args.split(",", 1)
        mode = parts[0].strip()
        rest = parts[1].strip() if len(parts) > 1 else ""
        if mode == "set":
            return "-m recent --set", errs, warns
        if mode == "check":
            sub = rest.split(",", 1)
            seconds = sub[0].strip()
            hitcount = sub[1].strip() if len(sub) > 1 else ""
            out = "-m recent --update"
            if seconds:
                if not re.fullmatch(r"\d+", seconds):
                    errs.append(f"recent: seconds '{seconds}' must be a positive integer")
                else:
                    out += f" --seconds {seconds}"
            if hitcount:
                if not re.fullmatch(r"\d+", hitcount):
                    errs.append(f"recent: hitcount '{hitcount}' must be a positive integer")
                else:
                    out += f" --hitcount {hitcount}"
            if errs:
                return args, errs, warns
            return out, errs, warns
        errs.append(f"recent: unknown mode '{mode}' (set|check)")
        return args, errs, warns

    if funcname == "mac":
        # mac(00:11:22:33:44:55) -> -m mac --mac-source <mac>
        if not re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", args):
            errs.append(f"mac: '{args}' must be a MAC address like "
                        f"00:11:22:33:44:55")
            return args, errs, warns
        return f"-m mac --mac-source {args}", errs, warns

    if funcname == "rpfilter":
        # rpfilter(loose|strict|validmark) -> -m rpfilter --<mode>
        if args in ("loose", "strict", "validmark"):
            return f"-m rpfilter --{args}", errs, warns
        errs.append(f"rpfilter: unknown mode '{args}' (loose|strict|validmark)")
        return args, errs, warns

    if funcname == "dscp":
        # dscp(0x2e) -> -j DSCP --set-dscp 0x2e
        if not re.fullmatch(r"0x[0-9a-fA-F]{2}", args):
            errs.append(f"dscp: '{args}' must be a hex value like 0x2e")
            return args, errs, warns
        return f"-j DSCP --set-dscp {args}", errs, warns

    if funcname == "string":
        # string(pattern) -> -m string --string "pattern" --algo bm
        return f'-m string --string "{args}" --algo bm', errs, warns

    if funcname == "owner":
        # owner(uid) -> -m owner --uid-owner <uid>
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", args):
            errs.append(f"owner: '{args}' must be a user name or numeric uid")
            return args, errs, warns
        return f"-m owner --uid-owner {args}", errs, warns

    if funcname == "frag":
        # frag(more|first) -> -m frag --fragmore|--fragfirst
        if args == "more":
            return "-m frag --fragmore", errs, warns
        if args == "first":
            return "-m frag --fragfirst", errs, warns
        errs.append(f"frag: unknown mode '{args}' (more|first)")
        return args, errs, warns

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


def _resolve_country(db: Db, name: str, errs: list[str]) -> bool:
    """Validate a predefined country group G_<CC> (resolved from the
    pre-generated per-country files under <maxminddir>/countries, written by
    the geoip2.sh download script). Requires [geoip] maxminddir in the db and
    that the country's data file exists."""
    if not name.startswith("G_"):
        errs.append(f"Networkgroup member '{name}' is not a network, group or country")
        return False
    cc = name[2:]
    if not re.fullmatch(r"[A-Z]{2}", cc):
        errs.append(f"geoip: '{cc}' is not a 2-letter country code")
        return False
    maxminddir = db.geoip.get("maxminddir", "")
    if not maxminddir:
        errs.append(f"geoip: country '{cc}' used but [geoip] maxminddir is not set in the db")
        return False
    cdir = os.path.join(maxminddir, "countries")
    if not os.path.isfile(os.path.join(cdir, cc)):
        errs.append(f"geoip: country '{cc}' data not found at "
                    f"'{os.path.join(cdir, cc)}' (run geoip2.sh to generate it)")
        return False
    return True


def _resolve_networkgroup(db: Db, name: str, chain: tuple, errs: list[str]) -> bool:
    """Recursively validate a networkgroup resolves: members may be a leaf
    network, a nested networkgroup, or a predefined G_<CC> country group.
    Detects circular references. Mirrors the manifest's netgroup_resolve."""
    if name in chain:
        errs.append(f"Networkgroup '{name}': circular reference "
                    f"({' -> '.join(chain + (name,))})")
        return False
    members = db.networkgroups.get(name)
    if members is None:
        errs.append(f"Networkgroup '{name}' not found in db")
        return False
    ok = True
    for m in (x.strip() for x in members.split(",") if x.strip()):
        if m in db.networkgroups:
            ok = _resolve_networkgroup(db, m, chain + (name,), errs) and ok
        elif m in db.networks:
            continue
        else:
            ok = _resolve_country(db, m, errs) and ok
    return ok


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
        leaf = {"servicegroups": "services", "hostgroups": "hosts",
                "networkgroups": "networks"}[section]
        return _validate_group_list(value, db, leaf, section)
    if section == "geoip":
        # [geoip] maxminddir=/path/to/maxminddbs
        if not value.startswith("/"):
            return ["expected an absolute path (e.g. /home/cdist/files.external/geoip2)"]
        return []
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


def _validate_group_list(value: str, db: Db | None, leaf: str,
                         group_section: str) -> list[str]:
    """servicegroups/hostgroups/networkgroups: comma-separated member names.
    networkgroups may also reference nested networkgroups and predefined
    G_<CC> country groups (resolved from the GeoLite2 MMDB at deploy)."""
    errs = []
    toks = [t.strip() for t in value.split(",")]
    if any(not t for t in toks):
        errs.append("empty name in comma-separated list")
    if db is not None:
        known = getattr(db, leaf, {})
        for t in toks:
            if not t:
                continue
            if group_section == "networkgroups":
                if t in db.networks or t in db.networkgroups or t.startswith("G_"):
                    continue
                errs.append(f"unknown network '{t}' (add it to [networks], "
                            f"a [networkgroups] group, or use G_<CC> for a country)")
            elif t not in known:
                errs.append(f"unknown {leaf.rstrip('s')} '{t}'")
    return errs


# ---------------------------------------------------------------------------
# reference detection (used before deleting a db entry)
# ---------------------------------------------------------------------------

# rule function -> db section it references
_FUNC_TO_SECTION = {
    "service": "services",
    "dservice": "services",
    "host": "hosts",
    "hosts": "hosts",
    "network": "networks",
    "hostgroup": "hostgroups",
    "networkgroup": "networkgroups",
    "dservices": "servicegroups",
}

# which db group section lists members of a given leaf section
_LEAF_GROUP = {
    "services": "servicegroups",
    "hosts": "hostgroups",
    "networks": "networkgroups",
}


def _rule_funcs(value: str) -> list[tuple[str, str]]:
    """Yield (funcname, args) for every func(args) token in a rule value,
    using the same tokenizer as expand_rule so reference detection matches
    what the manifest actually expands."""
    out: list[tuple[str, str]] = []
    guard = 0
    while value and guard < 100:
        guard += 1
        m = re.search(r"(^|[^(]*[ .:-;])([^( .:-;]+\([^)]+\))", value)
        if not m:
            break
        tok = m.group(2)
        value = value[m.end(2):]
        out.append((tok[: tok.index("(")], tok[tok.index("(") + 1: -1]))
    return out


def _func_refers(funcname: str, args: str, section: str, key: str) -> bool:
    """Does one function call reference the db entry (section, key)?"""
    if funcname == "dservices":
        # a service group name, or a comma list of individual services
        if section == "servicegroups":
            return args == key
        if section == "services":
            return key in {t.strip() for t in args.split(",")}
        return False
    if funcname == "hosts":
        if section != "hosts":
            return False
        return key in {t.strip() for t in args.split(",")}
    return _FUNC_TO_SECTION.get(funcname) == section and args == key


def rule_references(value: str, section: str, key: str) -> bool:
    """True if the rule text references the db entry (section, key)."""
    return any(_func_refers(f, a, section, key) for f, a in _rule_funcs(value))


def rule_db_refs(value: str, db: Db | None = None) -> set[tuple[str, str]]:
    """The db (section, key) objects a rule text references. dns() is a
    domain (no db entry) and is omitted; dservices()/hosts() split their
    comma lists into the individual leaf objects."""
    refs: set[tuple[str, str]] = set()
    groups = getattr(db, "servicegroups", {}) if db is not None else {}
    for funcname, args in _rule_funcs(value):
        if funcname == "dservices":
            if args in groups:
                refs.add(("servicegroups", args))
            else:
                for s in args.split(","):
                    s = s.strip()
                    if s:
                        refs.add(("services", s))
        elif funcname == "hosts":
            for h in args.split(","):
                h = h.strip()
                if h:
                    refs.add(("hosts", h))
        else:
            section = _FUNC_TO_SECTION.get(funcname)
            if section:
                # a predefined G_<CC> country group has no db entry
                if funcname == "networkgroup" and args.startswith("G_"):
                    continue
                refs.add((section, args))
    return refs


def db_group_refs(lines, section: str, key: str):
    """Db entries (groups) that reference a leaf entry (section, key).
    Groups list members of leaf sections only (no group-in-group nesting).
    @command group values are unknown at edit time and are not flagged."""
    group_sec = _LEAF_GROUP.get(section)
    if group_sec is None:
        return []
    refs = []
    for l in lines:
        if l.kind == "entry" and l.section == group_sec \
                and not l.value.startswith("@"):
            if key in {t.strip() for t in l.value.split(",")}:
                refs.append(l)
    return refs


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
    globals_ = global_dict(lines)
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


BUILTIN_CHAINS = {
    "filter": {"INPUT", "OUTPUT", "FORWARD"},
    "nat": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
    "mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
}

# -j targets that are iptables built-ins, not user chains
_TARGET_KEYWORDS = {
    "ACCEPT", "DROP", "REJECT", "LOG", "NFLOG", "DNAT", "SNAT",
    "MASQUERADE", "MARK", "CONNMARK", "RETURN", "QUEUE", "REDIRECT",
}


def validate_chains(lines) -> list[RuleIssue]:
    """Validate custom chain definitions (:name - [0:0]) and that -A/-j
    reference a defined chain in the rule's table. Returns issues (no raise)."""
    defined = {t: set(c) for t, c in BUILTIN_CHAINS.items()}
    for l in lines:
        if l.kind == "rule":
            m = re.match(r":(\S+)", l.value)
            if m:
                defined.setdefault(l.table, set()).add(m.group(1))
    issues: list[RuleIssue] = []
    current_section = "(no section)"
    for l in lines:
        if l.kind in ("section", "include"):
            current_section = l.name
            continue
        if l.kind != "rule":
            continue
        errs: list[str] = []
        m = re.search(r"-[AI]\s+(\S+)", l.value)
        if m and m.group(1) not in defined.get(l.table, set()):
            errs.append(f"Unknown chain '{m.group(1)}' in {l.table} table")
        for m in re.finditer(r"-j\s+(\S+)", l.value):
            tgt = m.group(1)
            if tgt.upper() in _TARGET_KEYWORDS:
                continue
            if tgt not in defined.get(l.table, set()):
                errs.append(f"Unknown target chain '{tgt}' in {l.table} table")
        if errs:
            issues.append(RuleIssue(
                section=current_section, table=l.table, proto=l.proto,
                text=l.value, errors=errs, warnings=[],
            ))
    return issues


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
    globals_ = global_dict(lines)
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
    globals_ = global_dict(lines)
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
