"""Root-safe access to a child's desktop override folder.

Root writes the child's hidden-app overrides into ~/.local/share/applications. The child owns
~/.local and ~/.local/share, so the child can replace any of them with a symlink. A path-based
write as root would then follow the link (to /etc, for example). Every step here instead opens
the next name relative to a directory descriptor it already holds, with O_NOFOLLOW, so a
symlink is refused rather than followed. Writes go to a temporary name and are renamed into
place, and a rename replaces a symlink at the destination without following it.

Used only when running as root on a real system. Dry runs and tests use the path-based code in
app_guard.py instead.
"""

from __future__ import annotations

import os
import pwd
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

# Components below the child's home that the child owns, and the one root keeps.
CHILD_OWNED = (".local", "share")
OVERRIDES = "applications"


def child_owner(username: str) -> Optional[Tuple[int, int]]:
    """(uid, gid) of the child account, or None when it does not exist."""
    try:
        entry = pwd.getpwnam(username)
    except KeyError:
        return None
    return entry.pw_uid, entry.pw_gid


def open_overrides_dir(home_root: Path, username: str, owner: Optional[Tuple[int, int]], create: bool) -> int:
    """Returns a descriptor for home_root/<username>/.local/share/applications.

    Each component is opened with O_NOFOLLOW relative to the descriptor for the one above it.
    A symlink or a non-directory in the path raises OSError (ELOOP or ENOTDIR), and nothing is
    written. When create is True, missing components are made as root; the child-owned ones
    (.local and share) are given to the child, including ones that already existed owned by root.
    """
    fd = os.open(str(home_root), _DIR_FLAGS)
    try:
        for name in (username, *CHILD_OWNED, OVERRIDES):
            try:
                nxt = os.open(name, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create or name == username:
                    raise
                os.mkdir(name, 0o755, dir_fd=fd)
                nxt = os.open(name, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
            if owner is not None and name in CHILD_OWNED:
                os.fchown(fd, owner[0], owner[1])
        return fd
    except OSError:
        os.close(fd)
        raise


def set_immutable(fd: int, immutable: bool) -> bool:
    """Sets or clears the immutable flag on the directory behind fd. Returns False if chattr fails.

    chattr is given /proc/self/fd/N, so it operates on the descriptor and does not resolve the
    path again.
    """
    try:
        result = subprocess.run(
            ["chattr", "+i" if immutable else "-i", f"/proc/self/fd/{fd}"],
            pass_fds=(fd,),
            capture_output=True,
        )
    except OSError:
        return False
    return result.returncode == 0


def list_desktop_files(dir_fd: int) -> List[str]:
    return [name for name in os.listdir(dir_fd) if name.endswith(".desktop")]


def read_file(dir_fd: int, name: str) -> Optional[str]:
    """Contents of a regular file in the directory, or None if it is missing, a link or not a file."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return None
    with os.fdopen(fd, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def write_file(dir_fd: int, name: str, content: str, mode: int = 0o644) -> None:
    """Writes name in the directory without following any link. The rename replaces a link at name."""
    tmp = name + ".tmp"
    try:
        os.unlink(tmp, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, _FILE_FLAGS, mode, dir_fd=dir_fd)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)


def remove_file(dir_fd: int, name: str) -> None:
    """Removes the directory entry. unlink never follows a link, so a link is removed, not its target."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
