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
HOME_CONFIG = os.path.expanduser("~/.firewall-tui.conf")

DEFAULTS = {
    "dir": "/home/cdist/config/files/firewall",
    "includedir": "",
    "db": "",
    "deploy_command": "/home/cdist/cdist/bin/cdist config -n "
                      "-c /home/cdist/config {host}",
    # directory with the last explorer data per host (enables the interface
    # dropdown in the rule editor); empty = feature off
    "explore_dir": "",
    # __firewall type directory; the 'g' preview runs its manifest in
    # generate-only mode (FWTUI_GENERATE) for authoritative output
    "firewall_type": "/home/cdist/files.external/cdist-types.git/__firewall",
}

DEFAULT_ENV = {
    "CDIST_BETA": "1",
    "CDIST_INSTALL": "/home/cdist/cdist",
    "CDIST_EXPLORE": "/home/cdist/explore",
    "CDIST_INVENTORY": "/home/cdist/.cdist/inventory",
    "CDIST_CONFIG_DIR": "/home/cdist/config",
}


def _config_path(path: str | None) -> str:
    """Resolve the config file: explicit path, else ~/.firewall-tui.conf if it
    exists, else the project's firewall-tui.conf."""
    if path:
        return path
    if os.path.exists(HOME_CONFIG):
        return HOME_CONFIG
    return DEFAULT_CONFIG


def load_config(path: str | None = None) -> dict:
    """Load the config file, falling back to defaults for missing keys.
    Returns {"firewall": {...}, "env": {...}}."""
    cfg = configparser.ConfigParser()
    cfg.optionxform = str  # preserve env var case
    cfg.read(_config_path(path))
    out = dict(DEFAULTS)
    if cfg.has_section("firewall"):
        for k in DEFAULTS:
            if cfg.has_option("firewall", k):
                out[k] = cfg.get("firewall", k).strip()
    if not out["includedir"]:
        out["includedir"] = out["dir"]
    if not out["db"]:
        out["db"] = os.path.join(out["dir"], "db")
    env = dict(DEFAULT_ENV)
    if cfg.has_section("environment"):
        for k in cfg.options("environment"):
            env[k] = cfg.get("environment", k).strip()
    return {"firewall": out, "env": env}
