"""Application guard and desktop entry filtering for Family Linux.

Enforces parent app approvals for child accounts, hiding system settings,
terminals, and package managers from child desktop menus.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

from family_linux.models import ChildAccount, ALWAYS_BLOCKED_COMMANDS
from family_linux.security.adapter import SystemAdapter
from family_linux.security.apparmor import PROFILE_NAME
from family_linux.audit.logger import AuditLogger

SYSTEM_APP_DIRS = [
    Path("/usr/share/applications"),
    Path("/usr/local/share/applications"),
]


class AppGuard:
    """Controls application access and desktop launcher entries for children."""

    def __init__(self, adapter: Optional[SystemAdapter] = None, audit_logger: Optional[AuditLogger] = None):
        self.adapter = adapter or SystemAdapter()
        self.audit = audit_logger or AuditLogger(dry_run=self.adapter.dry_run)

    def is_app_allowed(self, child: ChildAccount, binary_or_app_name: str) -> bool:
        """Determines if a command or application is permitted for a child."""
        clean_name = Path(binary_or_app_name).name.lower().replace(".desktop", "")

        # Always block blacklist
        if clean_name in ALWAYS_BLOCKED_COMMANDS or clean_name in [b.lower() for b in child.app_policy.blocked_apps]:
            self.audit.log(
                event_type="APP_BLOCKED",
                user=child.username,
                severity="WARNING",
                details={"reason": "blocked_app_list", "app": binary_or_app_name},
            )
            return False

        # In allow-list mode, verify membership
        if child.app_policy.allow_list_mode:
            allowed = any(
                app.lower() in clean_name or clean_name in app.lower()
                for app in child.app_policy.approved_apps
            )
            if not allowed:
                self.audit.log(
                    event_type="APP_BLOCKED",
                    user=child.username,
                    severity="INFO",
                    details={"reason": "not_in_allow_list", "app": binary_or_app_name},
                )
                return False

        return True

    def discover_system_apps(self, app_dirs: Optional[List[Path]] = None) -> List[Dict[str, str]]:
        """Scans system application directories for installed desktop entries."""
        apps = []
        seen = set()

        for d in app_dirs if app_dirs is not None else SYSTEM_APP_DIRS:
            if not d.exists():
                continue
            for desktop_file in d.glob("*.desktop"):
                app_id = desktop_file.stem
                if app_id in seen:
                    continue
                seen.add(app_id)

                name = app_id
                exec_cmd = ""
                try:
                    with open(desktop_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("Name=") and name == app_id:
                                name = line.split("=", 1)[1].strip()
                            elif line.startswith("Exec=") and not exec_cmd:
                                exec_cmd = line.split("=", 1)[1].strip().split()[0]
                except OSError:
                    pass

                apps.append({
                    "id": app_id,
                    "name": name,
                    "exec": exec_cmd or app_id,
                    "file": str(desktop_file),
                })

        return sorted(apps, key=lambda a: a["name"].lower())

    def apply_child_desktop_filters(
        self,
        child: ChildAccount,
        confine: bool = False,
        home_root: Path = Path("/home"),
        app_dirs: Optional[List[Path]] = None,
    ) -> Tuple[int, int]:
        """Writes the child's ~/.local/share/applications overrides.

        Unapproved apps are hidden with NoDisplay=true. When confine is True (AppArmor is active
        and the profile is loaded), approved apps are rewritten to launch through
        `aa-exec -p family-linux-child`, which attaches the confinement profile to them.

        Returns (hidden, confined) counts.
        """
        child_apps_dir = home_root / child.username / ".local/share/applications"
        if not self.adapter.dry_run and not self.adapter.is_root():
            return 0, 0

        self.adapter.run_command(["mkdir", "-p", str(child_apps_dir)])

        hidden_count = 0
        confined_count = 0
        for app in self.discover_system_apps(app_dirs):
            override_file = child_apps_dir / f"{app['id']}.desktop"
            if not self.is_app_allowed(child, app["id"]):
                override_content = (
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    f"Name={app['name']}\n"
                    "NoDisplay=true\n"
                    "Hidden=true\n"
                )
                self.adapter.write_system_file(override_file, override_content, mode=0o644)
                hidden_count += 1
            elif confine:
                try:
                    source = Path(app["file"]).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                self.adapter.write_system_file(override_file, confine_desktop_entry(source), mode=0o644)
                confined_count += 1

        return hidden_count, confined_count


AA_EXEC_PREFIX = f"aa-exec -p {PROFILE_NAME} -- "


def confine_desktop_entry(source: str) -> str:
    """Returns a copy of a .desktop file whose Exec lines run through aa-exec."""
    lines = []
    for line in source.splitlines():
        if line.startswith("Exec="):
            lines.append("Exec=" + AA_EXEC_PREFIX + line[len("Exec="):])
        else:
            lines.append(line)
    return "\n".join(lines) + "\n"
