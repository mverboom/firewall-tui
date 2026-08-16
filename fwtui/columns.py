"""Parse a rule line into overview columns for the TUI.

Turns raw rule text like
    filter=-A INPUT -s host(proxy) dservice(node-red) -j ACCEPT
into
    chain=input  from=proxy  sport=any  to=any
    proto=tcp  port=node-red  action=accept  target=-

Function args are shown as-is (proxy, node-red), not resolved to IPs, so the
overview stays readable and matches what the user wrote.
"""

from __future__ import annotations

import re

from .expand import Db

COLUMNS = ("chain", "from", "sport", "to", "proto", "port",
           "action", "target")


def _shorten(v: str) -> str:
    """Strip a function wrapper: host(proxy) -> proxy, network(lnw) -> lnw."""
    m = re.match(r"([a-z]+)\(([^)]+)\)", v)
    return m.group(2) if m else v


def rule_columns(text: str, db: Db) -> dict:
    """Parse one rule line into a dict of overview columns."""
    cols = {c: "any" for c in COLUMNS}
    cols["action"] = ""
    cols["target"] = ""

    # custom chain definition: ":name - [0:0]"
    m = re.match(r":(\S+)", text)
    if m:
        cols["chain"] = m.group(1)
        cols["action"] = "create"
        return cols

    # chain
    m = re.search(r"-[AI]\s+(\S+)", text)
    if m:
        cols["chain"] = m.group(1).lower()

    # source/destination via ipset set matches
    m = re.search(r"(?:hostgroup|networkgroup|dns)\(([^)]+)\)\s+src", text)
    if m:
        cols["from"] = m.group(1)
    m = re.search(r"(?:hostgroup|networkgroup|dns)\(([^)]+)\)\s+dst", text)
    if m:
        cols["to"] = m.group(1)

    # source / source port
    m = re.search(r"-s\s+(\S+)", text)
    if m:
        cols["from"] = _shorten(m.group(1))
    m = re.search(r"--sport\s+(\S+)", text)
    if m:
        cols["sport"] = m.group(1)

    # destination
    m = re.search(r"-d\s+(\S+)", text)
    if m:
        cols["to"] = _shorten(m.group(1))
    m = re.search(r"--destination\s+(\S+)", text)
    if m:
        cols["to"] = _shorten(m.group(1))

    # protocol
    m = re.search(r"-p\s+(\S+)", text)
    if m:
        cols["proto"] = m.group(1)

    # dservice -> proto from db; port column shows the service name
    m = re.search(r"dservice\(([^)]+)\)", text)
    if m:
        svc = m.group(1)
        cols["port"] = svc
        val = db.services.get(svc)
        if val:
            if val.startswith("icmp"):
                cols["proto"] = "icmp"
            elif "/" in val:
                cols["proto"] = val.split("/", 1)[1]

    # dservices (multiport)
    m = re.search(r"dservices\(([^)]+)\)", text)
    if m:
        cols["port"] = m.group(1)

    # explicit --dport
    m = re.search(r"--dport\s+(\S+)", text)
    if m:
        cols["port"] = m.group(1)

    # action
    m = re.search(r"-j\s+(\S+)", text)
    if m:
        cols["action"] = m.group(1).lower()
    m = re.search(r"reject\(([^)]+)\)", text)
    if m:
        cols["action"] = f"reject:{m.group(1)}"
    m = re.search(r"log\(([^)]*)\)", text)
    if m:
        cols["action"] = "log"

    # NAT target
    m = re.search(r"--to-destination\s+(\S+)", text)
    if m:
        cols["target"] = _shorten(m.group(1))
    m = re.search(r"--to-source\s+(\S+)", text)
    if m:
        cols["target"] = _shorten(m.group(1))

    return cols
