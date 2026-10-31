"""KDE Plasma desktop lockdown for child sessions.

AppArmor confines only programs a child launches through the approved wrapper. A shell started from
the Alt+F2 run dialog, a shell-access action, or a config override (`--config`) runs outside that
profile, so those entry points are locked with Plasma's kiosk restrictions instead.

Kiosk restrictions are read from the system-wide /etc/xdg/kdeglobals, so they apply to every user on
the machine, including the parent. The keys are in the [KDE Action Restrictions][$i] group, which
makes only those keys immutable (see develop.kde.org, "Kiosk keys"). The group is written as a
managed block, so the rest of kdeglobals (Debian's own defaults) is left as it is.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from family_linux.security.adapter import SystemAdapter

KDEGLOBALS_PATH = Path("/etc/xdg/kdeglobals")
BEGIN_MARKER = "# BEGIN family-linux desktop lockdown (managed; do not edit)"
END_MARKER = "# END family-linux desktop lockdown"

# Keys that stop a shell, the Alt+F2 run dialog, and the --config override.
LOCKED_RESTRICTIONS = [
    "shell_access=false",      # no shell suitable for entering commands, and no Alt+F2 shell commands
    "run_command=false",       # the "Run Command" option (Alt+F2)
    "action/run_command=false",  # the same option in menus and the desktop context menu
    "custom_config=false",     # --config cannot point an application at unlocked settings
]


def render_block() -> List[str]:
    return [BEGIN_MARKER, "[KDE Action Restrictions][$i]", *LOCKED_RESTRICTIONS, END_MARKER]


def with_lockdown(current: str) -> str:
    """Returns kdeglobals with the managed block in place. Applying twice leaves one copy."""
    lines = current.splitlines()
    kept: List[str] = []
    skipping = False
    for line in lines:
        if line.strip() == BEGIN_MARKER:
            skipping = True
            continue
        if skipping:
            if line.strip() == END_MARKER:
                skipping = False
            continue
        kept.append(line)
    while kept and kept[-1].strip() == "":
        kept.pop()
    if kept:
        kept.append("")
    return "\n".join(kept + render_block()) + "\n"


def lockdown_in_place(content: str) -> bool:
    """True when the managed block holds every locked restriction."""
    return BEGIN_MARKER in content and all(item in content for item in LOCKED_RESTRICTIONS)


class DesktopLockdown:
    """Writes the Plasma kiosk restrictions for every user."""

    def __init__(self, adapter: SystemAdapter, path: Path = KDEGLOBALS_PATH):
        self.adapter = adapter
        self.path = path

    def apply(self) -> List[str]:
        """Writes the managed block. Returns warnings."""
        current = self.path.read_text(encoding="utf-8") if self.path.exists() and not self.adapter.dry_run else ""
        updated = with_lockdown(current)
        if updated != current:
            self.adapter.write_system_file(self.path, updated, mode=0o644)
        return []
