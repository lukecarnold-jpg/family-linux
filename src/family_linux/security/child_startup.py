"""A child's sign-in startup files: locked, so a child cannot run commands when signing in.

The desktop session reads these from the child's home at sign-in:

- ~/.profile, ~/.xprofile, ~/.xsessionrc: shell scripts sourced by SDDM's session scripts. A child's
  nologin shell takes the plain-sh branch, which sources ~/.profile.
- ~/.config/plasma-workspace/env and .../shutdown: shell scripts Plasma sources or runs.
- ~/.config/autostart and ~/.config/autostart-scripts: programs started at sign-in.
- ~/.config/environment.d: environment for the systemd user manager.
- ~/.config/systemd/user: systemd user units, which can run any command.

A child who can write any of these can start a shell at sign-in, or unset XDG_CONFIG_DIRS and leave
the Plasma kiosk restrictions behind (see desktop_lockdown.py). Each one is replaced by an empty,
root-owned file or folder with the immutable flag, so the child can neither edit it nor rename or
delete it. Something already in the way is renamed aside (".<name>.family-linux-disabled"), never
deleted. Every step opens names relative to a directory descriptor with O_NOFOLLOW, as in
child_dirs.py, so a symlink never makes root write elsewhere.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from family_linux.audit.logger import AuditLogger
from family_linux.models import ChildAccount
from family_linux.security import child_dirs
from family_linux.security.adapter import SystemAdapter

# (folders below the child's home, name, kind)
LOCKED_PATHS: Sequence[Tuple[Tuple[str, ...], str, str]] = (
    ((), ".profile", "file"),
    ((), ".xprofile", "file"),
    ((), ".xsessionrc", "file"),
    ((".config",), "autostart", "dir"),
    ((".config",), "autostart-scripts", "dir"),
    ((".config",), "environment.d", "dir"),
    ((".config", "plasma-workspace"), "env", "dir"),
    ((".config", "plasma-workspace"), "shutdown", "dir"),
    ((".config", "systemd"), "user", "dir"),
)
DISABLED_SUFFIX = ".family-linux-disabled"
ROOT = (0, 0)


def relative_paths() -> List[str]:
    return ["/".join((*parents, name)) for parents, name, _ in LOCKED_PATHS]


def _open_parent(home_root: Path, username: str, parents: Sequence[str], child_owner: Optional[Tuple[int, int]]) -> int:
    """Descriptor for home_root/<username>/<parents...>. Missing folders are made for the child."""
    fd = os.open(str(home_root), child_dirs._DIR_FLAGS)
    try:
        for index, name in enumerate((username, *parents)):
            try:
                nxt = os.open(name, child_dirs._DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if index == 0:  # the home folder itself is never created here
                    raise
                os.mkdir(name, 0o755, dir_fd=fd)
                nxt = os.open(name, child_dirs._DIR_FLAGS, dir_fd=fd)
                if child_owner is not None:
                    os.fchown(nxt, *child_owner)
            os.close(fd)
            fd = nxt
        return fd
    except OSError:
        os.close(fd)
        raise


def _lstat(dir_fd: int, name: str) -> Optional[os.stat_result]:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _is_empty_dir(parent_fd: int, name: str) -> bool:
    fd = os.open(name, child_dirs._DIR_FLAGS, dir_fd=parent_fd)
    try:
        return not os.listdir(fd)
    finally:
        os.close(fd)


def _set_aside(dir_fd: int, name: str) -> None:
    target = f".{name}{DISABLED_SUFFIX}"
    counter = 1
    while _lstat(dir_fd, target) is not None:
        counter += 1
        target = f".{name}{DISABLED_SUFFIX}.{counter}"
    os.rename(name, target, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def _lock_fd(fd: int, lock_owner: Optional[Tuple[int, int]], mode: int) -> bool:
    if lock_owner is not None:
        os.fchown(fd, *lock_owner)
    os.fchmod(fd, mode)
    return child_dirs.set_immutable(fd, True)


def lock_path(parent_fd: int, name: str, kind: str, lock_owner: Optional[Tuple[int, int]] = ROOT) -> bool:
    """Locks one file or folder in the directory behind parent_fd. Returns False if chattr failed."""
    current = _lstat(parent_fd, name)
    owner_uid = lock_owner[0] if lock_owner is not None else os.getuid()
    is_ours = current is not None and current.st_uid == owner_uid and (
        (kind == "file" and stat.S_ISREG(current.st_mode) and current.st_size == 0)
        or (kind == "dir" and stat.S_ISDIR(current.st_mode) and _is_empty_dir(parent_fd, name))
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if is_ours:
        # Locked by an earlier apply: ownership cannot change while immutable, so only re-assert the flag.
        fd = os.open(name, file_flags if kind == "file" else child_dirs._DIR_FLAGS, dir_fd=parent_fd)
        try:
            return child_dirs.set_immutable(fd, True)
        finally:
            os.close(fd)
    if current is not None:
        if stat.S_ISDIR(current.st_mode):
            _set_aside(parent_fd, name)
        else:
            os.unlink(name, dir_fd=parent_fd)  # a link is removed, not its target
    if kind == "file":
        fd = os.open(name, file_flags | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=parent_fd)
        mode = 0o644
    else:
        os.mkdir(name, 0o755, dir_fd=parent_fd)
        fd = os.open(name, child_dirs._DIR_FLAGS, dir_fd=parent_fd)
        mode = 0o755
    try:
        return _lock_fd(fd, lock_owner, mode)
    finally:
        os.close(fd)


def lock_startup_paths(
    home_root: Path,
    username: str,
    child_owner: Optional[Tuple[int, int]],
    lock_owner: Optional[Tuple[int, int]] = ROOT,
) -> Tuple[int, List[str]]:
    """Locks every startup path for one child. Returns (locked, problems)."""
    locked = 0
    problems: List[str] = []
    for parents, name, kind in LOCKED_PATHS:
        label = "/".join((*parents, name))
        try:
            parent_fd = _open_parent(home_root, username, parents, child_owner)
        except OSError as exc:
            problems.append(f"{label}: {exc}")
            continue
        try:
            if lock_path(parent_fd, name, kind, lock_owner):
                locked += 1
            else:
                problems.append(f"{label}: immutable flag not set")
        except OSError as exc:
            problems.append(f"{label}: {exc}")
        finally:
            os.close(parent_fd)
    return locked, problems


class ChildStartupLock:
    """Locks each child's sign-in startup files and folders."""

    def __init__(self, adapter: Optional[SystemAdapter] = None, audit_logger: Optional[AuditLogger] = None):
        self.adapter = adapter or SystemAdapter()
        self.audit = audit_logger or AuditLogger(dry_run=self.adapter.dry_run)

    def apply(self, child: ChildAccount, home_root: Path = Path("/home")) -> List[str]:
        """Returns warnings. Dry runs record the intended changes; real runs need root."""
        if self.adapter.dry_run:
            for parents, name, kind in LOCKED_PATHS:
                path = home_root / child.username / Path(*parents, name)
                if kind == "file":
                    self.adapter.write_system_file(path, "", mode=0o644)
                else:
                    self.adapter.run_command(["mkdir", "-p", str(path)])
                self.adapter.run_command(["chattr", "+i", str(path)])
            return []
        if not self.adapter.is_root():
            return [f"Sign-in files for '{child.username}' not locked (needs root)"]
        locked, problems = lock_startup_paths(home_root, child.username, child_dirs.child_owner(child.username))
        if problems:
            self.audit.log(
                event_type="CHILD_STARTUP_LOCK_INCOMPLETE",
                user=child.username,
                severity="WARNING",
                details={"problems": problems},
            )
            return [f"Sign-in files for '{child.username}' partly locked: {'; '.join(problems)}"]
        return []


def startup_locked(home_root: Path, username: str) -> Tuple[bool, str]:
    """Live check for verify: every path exists, is root-owned, and is not a link."""
    for label in relative_paths():
        path = home_root / username / label
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return False, f"{path} missing"
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            return False, f"{path} not root-owned"
    return True, f"{len(LOCKED_PATHS)} paths root-owned"
