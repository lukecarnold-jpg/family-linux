"""KDE Plasma desktop lockdown for child sessions only.

AppArmor confines only programs a child launches through the approved wrapper. A shell started from
the Alt+F2 run dialog, a shell-access action, or a config override (`--config`) runs outside that
profile, so those entry points are locked with Plasma's kiosk restrictions instead.

The restrictions are in a children-only config folder, /etc/xdg/family-linux-children/kdeglobals, in
the [KDE Action Restrictions][$i] group, which makes those keys immutable (develop.kde.org, "Kiosk
keys"). A PAM rule in SDDM's session stack puts that folder first in XDG_CONFIG_DIRS for members of
family-children, so the parent keeps a terminal and Alt+F2. A child cannot undo the variable at sign
in, because their sign-in startup files are locked (child_startup.py).

Earlier versions wrote the restrictions to the system-wide /etc/xdg/kdeglobals, which also locked the
parent out of a terminal. That managed block is removed when it is found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List

from family_linux.security.adapter import SystemAdapter
from family_linux.security.users import CHILD_GROUP

CHILD_XDG_DIR = Path("/etc/xdg/family-linux-children")
CHILD_KDEGLOBALS_PATH = CHILD_XDG_DIR / "kdeglobals"
ENV_CONF_PATH = Path("/etc/security/family-linux-children.conf")
SDDM_PAM_PATH = Path("/etc/pam.d/sddm")
SYSTEM_KDEGLOBALS_PATH = Path("/etc/xdg/kdeglobals")  # earlier versions only; cleaned up

BEGIN_MARKER = "# BEGIN family-linux desktop lockdown (managed; do not edit)"
END_MARKER = "# END family-linux desktop lockdown"
PAM_BEGIN = "# BEGIN family-linux children's kiosk (managed; do not edit)"
PAM_END = "# END family-linux children's kiosk"
GATE_BEGIN = "# BEGIN family-linux children's sign-in hours (managed; do not edit)"
GATE_END = "# END family-linux children's sign-in hours"
RELOCK_BEGIN = "# BEGIN family-linux children's sign-in files (managed; do not edit)"
RELOCK_END = "# END family-linux children's sign-in files"
# The include that starts the user's systemd manager (pam_systemd), which reads user units.
SESSION_INCLUDE = re.compile(r"^\s*@include\s+common-session\s*$")

# Keys that stop a shell, the Alt+F2 run dialog, and the --config override.
LOCKED_RESTRICTIONS = [
    "shell_access=false",      # no shell suitable for entering commands, and no Alt+F2 shell commands
    "run_command=false",       # the "Run Command" option (Alt+F2)
    "action/run_command=false",  # the same option in menus and the desktop context menu
    "custom_config=false",     # --config cannot point an application at unlocked settings
    "run_desktop_files=false",  # a .desktop file saved anywhere (Downloads, Desktop) cannot be run
    "action/openwith=false",   # "Open With" cannot be given a command line to run
]


def render_child_kdeglobals() -> str:
    return "\n".join(["# Managed by Family Linux. Do not edit.", "[KDE Action Restrictions][$i]", *LOCKED_RESTRICTIONS]) + "\n"


def render_env_conf() -> str:
    """pam_env configuration: children's sessions read the kiosk folder before /etc/xdg."""
    return (
        "# Managed by Family Linux. Do not edit. Read by pam_env for family-children only.\n"
        f"XDG_CONFIG_DIRS\tOVERRIDE={CHILD_XDG_DIR}:/etc/xdg\n"
    )


def render_pam_block() -> List[str]:
    """Skips the pam_env line for anyone not in family-children."""
    return [
        PAM_BEGIN,
        f"session [success=1 default=ignore] pam_succeed_if.so quiet user notingroup {CHILD_GROUP}",
        f"session required pam_env.so readenv=0 user_readenv=0 conffile={ENV_CONF_PATH}",
        PAM_END,
    ]


def render_relock_block(python: str = sys.executable) -> List[str]:
    """Re-locks a child's sign-in files as root before their session starts.

    The locked folders sit in folders the child owns (~/.config/systemd, for example). A child can
    rename such a parent folder and make a new one, which the immutable flag does not stop, so the
    locks are checked and re-made at every sign-in. If that fails the sign-in is refused.
    """
    return [
        RELOCK_BEGIN,
        f"session [success=1 default=ignore] pam_succeed_if.so quiet user notingroup {CHILD_GROUP}",
        f"session required pam_exec.so quiet type=open_session {python} -m family_linux.security.child_startup --pam",
        RELOCK_END,
    ]


def render_gate_block(python: str = sys.executable) -> List[str]:
    """Refuses a child's sign-in at bedtime, after the day's limit, or when turned off (screentime/gate.py)."""
    return [
        GATE_BEGIN,
        f"account [success=1 default=ignore] pam_succeed_if.so quiet user notingroup {CHILD_GROUP}",
        f"account required pam_exec.so quiet {python} -m family_linux.screentime.gate",
        GATE_END,
    ]


def _without(lines: List[str], begin: str, end: str) -> List[str]:
    kept: List[str] = []
    skipping = False
    for line in lines:
        if line.strip() == begin:
            skipping = True
            continue
        if skipping:
            if line.strip() == end:
                skipping = False
            continue
        kept.append(line)
    return kept


def with_pam_block(current: str, python: str = sys.executable) -> str:
    """Returns SDDM's PAM file with the managed blocks. Applying twice leaves one copy of each.

    The kiosk block goes at the end. The re-lock block goes straight before `@include common-session`,
    so it runs before the user's systemd manager starts and reads their user units; without that
    include it goes at the end.
    """
    kept = current.splitlines()
    for begin, end in ((PAM_BEGIN, PAM_END), (RELOCK_BEGIN, RELOCK_END), (GATE_BEGIN, GATE_END)):
        kept = _without(kept, begin, end)
    while kept and kept[-1].strip() == "":
        kept.pop()
    relock = render_relock_block(python)
    at = next((i for i, line in enumerate(kept) if SESSION_INCLUDE.match(line)), None)
    if at is None:
        kept = kept + relock
    else:
        kept = kept[:at] + relock + kept[at:]
    return "\n".join(kept + render_gate_block(python) + render_pam_block()) + "\n"


def without_system_block(current: str) -> str:
    """Removes the system-wide block that earlier versions wrote to /etc/xdg/kdeglobals."""
    kept = _without(current.splitlines(), BEGIN_MARKER, END_MARKER)
    while kept and kept[-1].strip() == "":
        kept.pop()
    return "\n".join(kept) + "\n" if kept else ""


def lockdown_in_place(kdeglobals: str, pam: str) -> bool:
    """True when the children's kiosk file holds every restriction and SDDM applies it to children."""
    relock = render_relock_block()
    return (
        all(item in kdeglobals for item in LOCKED_RESTRICTIONS)
        and all(line in pam for line in render_pam_block())
        and all(line in pam for line in (relock[0], relock[1], relock[3]))
        and "family_linux.security.child_startup --pam" in pam
        and "family_linux.screentime.gate" in pam
    )


class DesktopLockdown:
    """Writes the children's kiosk restrictions and the PAM rule that applies them."""

    def __init__(
        self,
        adapter: SystemAdapter,
        pam_path: Path = SDDM_PAM_PATH,
        system_kdeglobals: Path = SYSTEM_KDEGLOBALS_PATH,
    ):
        self.adapter = adapter
        self.pam_path = pam_path
        self.system_kdeglobals = system_kdeglobals

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8") if path.exists() and not self.adapter.dry_run else ""

    def apply(self) -> List[str]:
        """Returns warnings."""
        warnings: List[str] = []
        self.adapter.write_system_file(CHILD_KDEGLOBALS_PATH, render_child_kdeglobals(), mode=0o644)
        self.adapter.write_system_file(ENV_CONF_PATH, render_env_conf(), mode=0o644)

        if not self.adapter.dry_run and not self.pam_path.exists():
            warnings.append(f"{self.pam_path} not found (is SDDM installed?); children's desktop lockdown not applied")
        else:
            current = self._read(self.pam_path)
            updated = with_pam_block(current)
            if updated != current:
                self.adapter.write_system_file(self.pam_path, updated, mode=0o644)

        old = self._read(self.system_kdeglobals)
        if BEGIN_MARKER in old:
            self.adapter.write_system_file(self.system_kdeglobals, without_system_block(old), mode=0o644)
        return warnings
