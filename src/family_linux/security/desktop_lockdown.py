"""GNOME desktop lockdown for child sessions.

AppArmor confines only programs a child launches through the approved wrapper. A terminal
started from a keyboard shortcut or the Alt+F2 run dialog runs outside that profile, so those
entry points are locked in the desktop settings instead.

The locks are system-wide dconf settings, so they apply to every user on the machine,
including the parent. A user can change an unlocked setting but not a locked one.
"""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Dict, List

from family_linux.security.adapter import SystemAdapter

DCONF_DB_DIR = Path("/etc/dconf/db/local.d")
SETTINGS_PATH = DCONF_DB_DIR / "00-family-linux"
LOCKS_PATH = DCONF_DB_DIR / "locks" / "00-family-linux"

# group path -> keys to set and lock
LOCKED_SETTINGS: Dict[str, List[str]] = {
    "org/gnome/settings-daemon/plugins/media-keys": ["terminal"],  # Ctrl+Alt+T
    "org/gnome/desktop/lockdown": ["disable-command-line"],  # Alt+F2 run dialog
}


def render_settings() -> str:
    """Returns the dconf keyfile that sets the locked values."""
    return (
        "# Managed by Family Linux. Do not edit.\n"
        "[org/gnome/settings-daemon/plugins/media-keys]\n"
        "terminal=@as []\n"
        "\n"
        "[org/gnome/desktop/lockdown]\n"
        "disable-command-line=true\n"
    )


def render_locks() -> str:
    """Returns the dconf lock list that stops users changing the settings above."""
    lines = ["# Managed by Family Linux. Do not edit."]
    for group, keys in LOCKED_SETTINGS.items():
        lines.extend(f"/{group}/{key}" for key in keys)
    return "\n".join(lines) + "\n"


class DesktopLockdown:
    """Writes the dconf policy and rebuilds the dconf database."""

    def __init__(self, adapter: SystemAdapter):
        self.adapter = adapter

    def apply(self) -> List[str]:
        """Writes the settings and locks, then runs dconf update. Returns warnings."""
        self.adapter.write_system_file(SETTINGS_PATH, render_settings(), mode=0o644)
        self.adapter.write_system_file(LOCKS_PATH, render_locks(), mode=0o644)
        result = self.adapter.run_command(["dconf", "update"])
        if result.returncode != 0:
            return ["dconf not available; terminal shortcut and Alt+F2 command line are not locked"]
        return []
