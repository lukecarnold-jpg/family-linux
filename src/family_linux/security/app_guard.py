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
from family_linux.security import child_dirs
from family_linux.security.apparmor import PROFILE_NAME
from family_linux.audit.logger import AuditLogger

# Desktop entries from Debian packages (apt and PackageKit) and from locally installed software.
SYSTEM_APP_DIRS = [
    Path("/usr/share/applications"),
    Path("/usr/local/share/applications"),
]

# First line of every override this module writes. Files without it were not written here and
# are left alone.
MANAGED_MARKER = "# Managed by Family Linux (app approval). Changes here are overwritten at the next apply."


def is_managed_override(text: str) -> bool:
    """True for overrides written by this module, including the hidden template used before the marker."""
    if MANAGED_MARKER in text:
        return True
    return "NoDisplay=true" in text and "Hidden=true" in text and "Exec=" not in text


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
        if not self.adapter.dry_run and not self.adapter.is_root():
            return 0, 0
        if self.adapter.dry_run:
            return self._apply_by_path(child, confine, home_root, app_dirs)
        return self._apply_as_root(child, confine, home_root, app_dirs)

    def _apply_as_root(
        self,
        child: ChildAccount,
        confine: bool,
        home_root: Path,
        app_dirs: Optional[List[Path]],
    ) -> Tuple[int, int]:
        """Real run as root. Every step goes through a descriptor opened with O_NOFOLLOW, so the
        child cannot make root write outside the child's own folders by replacing one with a link.
        """
        try:
            dir_fd = child_dirs.open_overrides_dir(home_root, child.username, child_dirs.child_owner(child.username), create=True)
        except OSError as exc:
            self.audit.log(
                event_type="APP_OVERRIDES_REFUSED",
                user=child.username,
                severity="WARNING",
                details={"reason": "override folder is not a plain folder", "error": str(exc)},
            )
            return 0, 0
        try:
            # Only the overrides folder is locked. Lifted just while it is rewritten.
            child_dirs.set_immutable(dir_fd, False)
            try:
                return self._write_child_overrides(child, _FdStore(dir_fd), confine, app_dirs)
            finally:
                if not child_dirs.set_immutable(dir_fd, True):
                    self.audit.log(
                        event_type="APP_OVERRIDES_UNLOCKED",
                        user=child.username,
                        severity="WARNING",
                        details={"reason": "chattr +i failed; hidden apps can be deleted"},
                    )
        finally:
            os.close(dir_fd)

    def _apply_by_path(
        self,
        child: ChildAccount,
        confine: bool,
        home_root: Path,
        app_dirs: Optional[List[Path]],
    ) -> Tuple[int, int]:
        """Dry run and tests: the same decisions, recorded as commands and simulated files."""
        child_apps_dir = home_root / child.username / ".local/share/applications"
        self.adapter.run_command(["mkdir", "-p", str(child_apps_dir)])
        # ~/.local and ~/.local/share belong to the child: KDE and apps keep the Trash, keyring,
        # recent files and app data there. When root owned them, apps that save there failed for
        # children (seen: ibus-table crashed at login).
        local_dir = child_apps_dir.parent.parent
        for directory in (local_dir, local_dir / "share"):
            self.adapter.run_command(["chown", f"{child.username}:", str(directory)])
        self.adapter.run_command(["chattr", "-i", str(child_apps_dir)])
        try:
            return self._write_child_overrides(child, _PathStore(self, child_apps_dir), confine, app_dirs)
        finally:
            self.adapter.run_command(["chattr", "+i", str(child_apps_dir)])

    def _write_child_overrides(
        self,
        child: ChildAccount,
        store,
        confine: bool,
        app_dirs: Optional[List[Path]],
    ) -> Tuple[int, int]:
        hidden_count = 0
        confined_count = 0
        discovered_ids = set()
        for app in self.discover_system_apps(app_dirs):
            discovered_ids.add(app["id"])
            name = f"{app['id']}.desktop"
            if not self.is_app_allowed(child, app["id"]):
                override_content = (
                    f"{MANAGED_MARKER}\n"
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    f"Name={app['name']}\n"
                    "NoDisplay=true\n"
                    "Hidden=true\n"
                )
                store.write(name, override_content)
                hidden_count += 1
            elif confine:
                try:
                    source = Path(app["file"]).read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                store.write(name, f"{MANAGED_MARKER}\n" + confine_desktop_entry(source))
                confined_count += 1
            else:
                # Approved and not confined. An override written while the app was unapproved would
                # keep it hidden, so remove it. Overrides not written here are kept.
                store.remove_managed(name)

        # Apps that are no longer installed: their hidden overrides are not needed any more.
        for leftover in store.names():
            if Path(leftover).stem not in discovered_ids:
                store.remove_managed(leftover)

        return hidden_count, confined_count


class _PathStore:
    """Overrides by path, through the adapter. Used in dry runs and tests."""

    def __init__(self, guard: "AppGuard", directory: Path):
        self.guard = guard
        self.directory = directory

    def write(self, name: str, content: str) -> None:
        self.guard.adapter.write_system_file(self.directory / name, content, mode=0o644)

    def remove_managed(self, name: str) -> None:
        """Removes an override only if this module wrote it. In dry run the removal is recorded."""
        path = self.directory / name
        if path.exists() and is_managed_override(path.read_text(encoding="utf-8", errors="ignore")):
            self.guard.adapter.remove_system_file(path)

    def names(self) -> List[str]:
        if not self.directory.exists():
            return []
        return [p.name for p in self.directory.glob("*.desktop")]


class _FdStore:
    """Overrides through a descriptor opened with O_NOFOLLOW. Used for real runs as root."""

    def __init__(self, dir_fd: int):
        self.dir_fd = dir_fd

    def write(self, name: str, content: str) -> None:
        child_dirs.write_file(self.dir_fd, name, content, mode=0o644)

    def remove_managed(self, name: str) -> None:
        content = child_dirs.read_file(self.dir_fd, name)
        if content is not None and is_managed_override(content):
            child_dirs.remove_file(self.dir_fd, name)

    def names(self) -> List[str]:
        return child_dirs.list_desktop_files(self.dir_fd)


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
