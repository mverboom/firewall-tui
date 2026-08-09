"""Parse and serialize __firewall rules files and db files.

The format is INI-like but has quirks that rule out configparser:
  * duplicate keys in a section (multiple filter= lines)
  * [ #filename ] include pseudo-sections
  * @command values in the db
  * table keys with proto suffix (filter4, filter6, filter46, ...)

Model is line-based so round-trip fidelity is perfect: untouched lines keep
their exact raw text (comments, blank lines, commented-out rules, spacing).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Keys allowed in the [global] section of a rules file
GLOBAL_KEYS = (
    "policy", "policy_input", "policy_output", "policy_forward",
    "established", "icmp", "proto", "log",
    "log_input", "log_forward", "log_output",
    "loopback", "packageinstall",
)

# Tables recognized in rules files
TABLE_KEYS = ("filter", "nat", "mangle")
PROTO_SUFFIXES = ("", "4", "6", "46")

# Sections recognized in the db file
DB_SECTIONS = (
    "services", "servicegroups", "hosts", "hostgroups",
    "networks", "networkgroups",
)


@dataclass
class Line:
    """One logical line of a rules file."""

    raw: str
    kind: str = "blank"  # blank|comment|section|include|global|rule|unknown
    key: str = ""        # global key or rule key (filter, nat, ...)
    value: str = ""      # global value or rule text
    table: str = ""      # filter|nat|mangle (for rules)
    proto: str = ""      # ""|"4"|"6"|"46" (for rules)
    name: str = ""       # section name or include filename
    source: str = ""     # file this line was parsed from (for includes)

    def render(self) -> str:
        """Regenerate the raw line from the parsed fields."""
        if self.kind in ("blank", "comment", "unknown"):
            return self.raw
        if self.kind == "section":
            return f"[{self.name}]"
        if self.kind == "include":
            return f"[#{self.name}]"
        if self.kind in ("global", "rule"):
            return f"{self.key}={self.value}"
        return self.raw


def _classify_rule_key(key: str) -> tuple[str, str] | None:
    """Split a rule key into (table, proto). None if not a table key."""
    for table in TABLE_KEYS:
        if key == table:
            return table, ""
        for p in PROTO_SUFFIXES[1:]:
            if key == table + p:
                return table, p
    return None


def parse_rules(text: str) -> list[Line]:
    """Parse a rules file into a list of Line objects."""
    lines: list[Line] = []
    for raw in text.splitlines():
        line = Line(raw=raw)
        stripped = raw.strip()
        if not stripped:
            line.kind = "blank"
        elif stripped.startswith("#"):
            line.kind = "comment"
        elif stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip()
            if name.startswith("#"):
                line.kind = "include"
                line.name = name[1:].strip()
            else:
                line.kind = "section"
                line.name = name
        elif "=" in stripped:
            key, value = stripped.split("=", 1)
            line.key = key.strip()
            line.value = value.strip()
            if line.key in GLOBAL_KEYS:
                line.kind = "global"
            else:
                t = _classify_rule_key(line.key)
                if t:
                    line.kind = "rule"
                    line.table, line.proto = t
                else:
                    line.kind = "unknown"
        else:
            line.kind = "unknown"
        lines.append(line)
    return lines


def serialize_rules(lines: list[Line]) -> str:
    """Serialize a list of Line objects back to file text."""
    return "\n".join(l.render() for l in lines) + "\n"


# ---------------------------------------------------------------------------
# db file
# ---------------------------------------------------------------------------

@dataclass
class DbLine:
    """One logical line of a db file."""

    raw: str
    kind: str = "blank"    # blank|comment|section|entry|unknown
    section: str = ""
    key: str = ""
    value: str = ""

    def render(self) -> str:
        if self.kind in ("blank", "comment", "unknown"):
            return self.raw
        if self.kind == "section":
            return f"[{self.section}]"
        if self.kind == "entry":
            return f"{self.key}={self.value}"
        return self.raw


def parse_db(text: str) -> list[DbLine]:
    """Parse a db file into a list of DbLine objects."""
    lines: list[DbLine] = []
    for raw in text.splitlines():
        line = DbLine(raw=raw)
        stripped = raw.strip()
        if not stripped:
            line.kind = "blank"
        elif stripped.startswith("#"):
            line.kind = "comment"
        elif stripped.startswith("[") and stripped.endswith("]"):
            line.kind = "section"
            line.section = stripped[1:-1].strip()
        elif "=" in stripped:
            key, value = stripped.split("=", 1)
            line.kind = "entry"
            line.key = key.strip()
            line.value = value.strip()
        else:
            line.kind = "unknown"
        lines.append(line)
    return lines


def serialize_db(lines: list[DbLine]) -> str:
    return "\n".join(l.render() for l in lines) + "\n"


# ---------------------------------------------------------------------------
# Convenience: structured views over the line lists
# ---------------------------------------------------------------------------

def rules_sections(lines: list[Line]) -> list[Line]:
    """Return the section/include lines in order."""
    return [l for l in lines if l.kind in ("section", "include")]


def rules_in_section(lines: list[Line], section: Line) -> list[Line]:
    """Return the rule lines belonging to a section (until next section)."""
    if section.kind not in ("section", "include"):
        return []
    out: list[Line] = []
    seen = False
    for l in lines:
        if l is section:
            seen = True
            continue
        if seen and l.kind in ("section", "include"):
            break
        if seen and l.kind == "rule":
            out.append(l)
    return out


def global_lines(lines: list[Line]) -> list[Line]:
    """Return the global option lines (inside the [global] section)."""
    out: list[Line] = []
    for l in lines:
        if l.kind == "section":
            if l.name == "global":
                continue  # the [global] header itself
            break
        if l.kind == "include":
            break
        if l.kind == "global":
            out.append(l)
    return out


def db_entries(lines: list[DbLine], section: str) -> list[DbLine]:
    """Return entry lines belonging to a db section."""
    out: list[DbLine] = []
    seen = False
    for l in lines:
        if l.kind == "section":
            seen = (l.section == section)
            continue
        if seen and l.kind == "entry":
            out.append(l)
    return out


def db_sections(lines: list[DbLine]) -> list[str]:
    """Return db section names in order."""
    return [l.section for l in lines if l.kind == "section"]
