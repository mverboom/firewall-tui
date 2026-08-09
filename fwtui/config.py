"""Configuration for the firewall TUI.

Reads a simple INI file (default: firewall-tui.conf next to the project).
Settings:
    [firewall]
    dir            base directory containing the per-host rulesets
    includedir     directory for [#include] files (defaults to dir)
    db             path to the shared db file (defaults to dir/db)
    deploy_command command template to install a firewall; {host} is
                   replaced with the target hostname
"""

from __future__ import annotations

import configparser
import os

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              "firewall-tui.conf")

DEFAULTS = {
    "dir": "/home/cdist/config/files/firewall",
    "includedir": "",
    "db": "",
    "deploy_command": "/home/cdist/cdist/bin/cdist config -n "
                      "-c /home/cdist/config {host}",
}


def load_config(path: str | None = None) -> dict:
    """Load the config file, falling back to defaults for missing keys."""
    cfg = configparser.ConfigParser()
    cfg.read(path or DEFAULT_CONFIG)
    out = dict(DEFAULTS)
    if cfg.has_section("firewall"):
        for k in DEFAULTS:
            if cfg.has_option("firewall", k):
                out[k] = cfg.get("firewall", k).strip()
    if not out["includedir"]:
        out["includedir"] = out["dir"]
    if not out["db"]:
        out["db"] = os.path.join(out["dir"], "db")
    return out
