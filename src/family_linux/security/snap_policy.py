"""Snap installs for child accounts: each attempt needs the parent's password.

Ubuntu's app store is the snap store, and snapd checks PolicyKit before it installs, updates or
removes a snap. The stock policy for an active session is auth_admin_keep, which remembers the
authorisation for several minutes. The rule written here asks for admin authentication on every
attempt by a child account (AUTH_ADMIN). The only administrator is the parent, so the prompt
takes the parent's password. The check runs in snapd's own process, so it covers the software
center, the snap command and any other client.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Sequence

from family_linux.security.adapter import SystemAdapter

POLKIT_RULE_PATH = Path("/etc/polkit-1/rules.d/50-family-linux-snap.rules")
SNAP_ACTIONS = ("io.snapcraft.snapd.manage", "io.snapcraft.snapd.manage-interfaces")
SNAPD_PACKAGE = "snapd"
USERNAME_PATTERN = r"[a-z_][a-z0-9_-]{2,31}"


def render_polkit_rule(child_usernames: Sequence[str]) -> str:
    """JavaScript polkit rule. Rules are read by polkitd from /etc/polkit-1/rules.d."""
    for name in child_usernames:
        if not re.fullmatch(USERNAME_PATTERN, name):
            raise ValueError(f"Unsafe username for polkit rule: {name!r}")
    children = ", ".join(f'"{name}"' for name in child_usernames)
    actions = ", ".join(f'"{action}"' for action in SNAP_ACTIONS)
    return (
        "// Family Linux (managed; do not edit).\n"
        "// Snap installs, updates and removals by a child account need the parent's password on\n"
        "// every attempt. AUTH_ADMIN, unlike the default auth_admin_keep for an active session,\n"
        "// does not remember the authorisation.\n"
        "polkit.addRule(function (action, subject) {\n"
        f"    var actions = [{actions}];\n"
        f"    var children = [{children}];\n"
        "    if (actions.indexOf(action.id) >= 0 && children.indexOf(subject.user) >= 0) {\n"
        "        return polkit.Result.AUTH_ADMIN;\n"
        "    }\n"
        "});\n"
    )


def rule_in_place(content: str, child_usernames: Sequence[str]) -> bool:
    """True when the rule file names every child and the snap actions it gates."""
    if "polkit.Result.AUTH_ADMIN" not in content:
        return False
    return all(f'"{name}"' in content for name in child_usernames) and all(
        f'"{action}"' in content for action in SNAP_ACTIONS
    )


class SnapInstallGate:
    """Makes snap installs for child accounts require the parent's password, and keeps snapd present."""

    def __init__(self, adapter: Optional[SystemAdapter] = None, rule_path: Path = POLKIT_RULE_PATH):
        self.adapter = adapter or SystemAdapter()
        self.rule_path = rule_path

    def apply(self, child_usernames: Sequence[str]) -> List[str]:
        """Installs snapd if missing and writes the polkit rule. Returns warnings."""
        warnings: List[str] = []
        if self.adapter.run_command(["dpkg", "-s", SNAPD_PACKAGE]).returncode != 0:
            install = self.adapter.run_command(["apt-get", "install", "-y", "-q", SNAPD_PACKAGE])
            if install.returncode != 0:
                warnings.append("snapd could not be installed; the snap store is not available")
        self.adapter.write_system_file(self.rule_path, render_polkit_rule(child_usernames), mode=0o644)
        return warnings

    def is_in_place(self, child_usernames: Sequence[str]) -> bool:
        return self.rule_path.exists() and rule_in_place(self.rule_path.read_text(encoding="utf-8"), child_usernames)

