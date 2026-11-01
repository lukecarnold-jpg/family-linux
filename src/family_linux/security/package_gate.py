"""Software installs for child accounts: each attempt needs the parent's password.

Debian's app store (Discover) installs packages through PackageKit, and PackageKit asks polkit for
permission first. A child is not an administrator, so the only way through is an administrator's
password, which is the parent's. The rule written here asks for administrator authentication on
every attempt by a child account (AUTH_ADMIN). The stock policy for an active session,
auth_admin_keep, remembers the authorisation for several minutes, so a child could install a
second app without the parent. The rule covers every PackageKit action (install, remove, refresh
and upgrade) rather than a list of names, so no path skips it.

Flatpak and Snap would be a way around the rule: Flatpak installs per user without PackageKit or an
administrator, and Discover offers it once its Flatpak backend is installed (the KDE task can pull it
in). They are removed if present and pinned at priority -1, so apt never installs them again.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Sequence

from family_linux.security.adapter import SystemAdapter

POLKIT_RULE_PATH = Path("/etc/polkit-1/rules.d/50-family-linux-packages.rules")
PACKAGEKIT_ACTION_PREFIX = "org.freedesktop.packagekit."
PACKAGEKIT_PACKAGE = "packagekit"
# Ways to install software that do not go through PackageKit's polkit check.
BLOCKED_PACKAGES = ("flatpak", "plasma-discover-backend-flatpak", "plasma-discover-backend-snap", "snapd")
APT_PIN_PATH = Path("/etc/apt/preferences.d/family-linux-no-flatpak-snap")
USERNAME_PATTERN = r"[a-z_][a-z0-9_-]{2,31}"


def render_polkit_rule(child_usernames: Sequence[str]) -> str:
    """JavaScript polkit rule. Rules are read by polkitd from /etc/polkit-1/rules.d."""
    for name in child_usernames:
        if not re.fullmatch(USERNAME_PATTERN, name):
            raise ValueError(f"Unsafe username for polkit rule: {name!r}")
    children = ", ".join(f'"{name}"' for name in child_usernames)
    return (
        "// Family Linux (managed; do not edit).\n"
        "// Software installs, removals and updates by a child account need the parent's password on\n"
        "// every attempt. AUTH_ADMIN, unlike the default auth_admin_keep for an active session,\n"
        "// does not remember the authorisation.\n"
        "polkit.addRule(function (action, subject) {\n"
        f"    var children = [{children}];\n"
        f"    if (action.id.indexOf(\"{PACKAGEKIT_ACTION_PREFIX}\") === 0 && children.indexOf(subject.user) >= 0) {{\n"
        "        return polkit.Result.AUTH_ADMIN;\n"
        "    }\n"
        "});\n"
    )


def render_apt_pin() -> str:
    """apt preferences that stop the blocked packages being installed (priority -1), one stanza each."""
    stanzas = [f"Package: {name}\nPin: release *\nPin-Priority: -1\n" for name in BLOCKED_PACKAGES]
    return "# Family Linux (managed; do not edit). Installs that bypass the parent's approval.\n" + "\n".join(stanzas)


def pin_in_place(content: str) -> bool:
    return all(f"Package: {name}\n" in content for name in BLOCKED_PACKAGES) and "Pin-Priority: -1" in content


def rule_in_place(content: str, child_usernames: Sequence[str]) -> bool:
    """True when the rule file names every child and the PackageKit prefix it gates."""
    if "polkit.Result.AUTH_ADMIN" not in content or PACKAGEKIT_ACTION_PREFIX not in content:
        return False
    return all(f'"{name}"' in content for name in child_usernames)


class PackageInstallGate:
    """Makes software changes by child accounts require the parent's password."""

    def __init__(
        self,
        adapter: Optional[SystemAdapter] = None,
        rule_path: Path = POLKIT_RULE_PATH,
        pin_path: Path = APT_PIN_PATH,
    ):
        self.adapter = adapter or SystemAdapter()
        self.rule_path = rule_path
        self.pin_path = pin_path

    def apply(self, child_usernames: Sequence[str]) -> List[str]:
        """Installs PackageKit if missing, removes and pins Flatpak and Snap, writes the polkit rule.
        Returns warnings."""
        warnings: List[str] = []
        installed = [name for name in BLOCKED_PACKAGES if self.adapter.run_command(["dpkg", "-s", name]).returncode == 0]
        if installed:
            purge = self.adapter.run_command(["apt-get", "purge", "-y", "-q", *installed])
            if purge.returncode != 0:
                warnings.append(f"Could not remove {', '.join(installed)}; children may be able to install apps without approval")
        self.adapter.write_system_file(self.pin_path, render_apt_pin(), mode=0o644)
        if self.adapter.run_command(["dpkg", "-s", PACKAGEKIT_PACKAGE]).returncode != 0:
            install = self.adapter.run_command(["apt-get", "install", "-y", "-q", PACKAGEKIT_PACKAGE])
            if install.returncode != 0:
                warnings.append("PackageKit could not be installed; the app store is not available")
        self.adapter.write_system_file(self.rule_path, render_polkit_rule(child_usernames), mode=0o644)
        return warnings

    def is_in_place(self, child_usernames: Sequence[str]) -> bool:
        return self.rule_path.exists() and rule_in_place(self.rule_path.read_text(encoding="utf-8"), child_usernames)

    def bypasses_removed(self) -> bool:
        """True when no blocked package is installed and the apt pin is written."""
        if any(self.adapter.run_command(["dpkg", "-s", name]).returncode == 0 for name in BLOCKED_PACKAGES):
            return False
        return self.pin_path.exists() and pin_in_place(self.pin_path.read_text(encoding="utf-8"))
