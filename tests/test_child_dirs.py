"""A child cannot make root write outside the child's folders by replacing one with a symlink.

These run on real files in a temporary directory, without root, so they check the descriptor-based
code path directly. Nothing is written outside the temporary directory."""

import os
from pathlib import Path

import pytest

from family_linux.audit.logger import AuditLogger
from family_linux.models import AppPolicy, ChildAccount
from family_linux.security import child_dirs
from family_linux.security.adapter import SystemAdapter
from family_linux.security.app_guard import MANAGED_MARKER, AppGuard

pytestmark = pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")


class RootAdapter(SystemAdapter):
    """Takes the real-run branch (not a dry run, and root) while doing no system calls."""

    def __init__(self):
        super().__init__(dry_run=False)
        # SystemAdapter forces dry run on non-Linux hosts; this test needs the real branch.
        self.dry_run = False

    def is_root(self) -> bool:
        return True


def _apps(tmp_path: Path) -> Path:
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "vlc.desktop").write_text("[Desktop Entry]\nName=VLC\nExec=vlc %U\n")
    (apps / "quake.desktop").write_text("[Desktop Entry]\nName=Quake\nExec=quake\n")
    return apps


def _child(approved):
    child = ChildAccount.create("kid", "Kid", "pre_teen")
    child.app_policy = AppPolicy(allow_list_mode=True, approved_apps=approved)
    return child


def test_symlinked_local_folder_is_refused_and_outside_is_untouched(tmp_path):
    home = tmp_path / "home"
    (home / "kid").mkdir(parents=True)
    outside = tmp_path / "etc"
    outside.mkdir()
    (home / "kid" / ".local").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        fd = child_dirs.open_overrides_dir(home, "kid", owner=None, create=True)
        os.close(fd)
    assert list(outside.iterdir()) == []


def test_symlinked_share_or_applications_folder_is_refused(tmp_path):
    home = tmp_path / "home"
    (home / "kid" / ".local").mkdir(parents=True)
    outside = tmp_path / "etc"
    outside.mkdir()
    (home / "kid" / ".local" / "share").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        os.close(child_dirs.open_overrides_dir(home, "kid", owner=None, create=True))
    assert list(outside.iterdir()) == []


def test_write_replaces_a_symlink_at_the_override_name_without_following_it(tmp_path):
    folder = tmp_path / "applications"
    folder.mkdir()
    victim = tmp_path / "sudoers-like"
    victim.write_text("original\n")
    (folder / "vlc.desktop").symlink_to(victim)

    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        child_dirs.write_file(fd, "vlc.desktop", "NEW\n")
    finally:
        os.close(fd)

    assert victim.read_text() == "original\n"  # the link's target was not written
    assert not (folder / "vlc.desktop").is_symlink()
    assert (folder / "vlc.desktop").read_text() == "NEW\n"


def test_a_symlink_planted_at_the_temporary_name_is_not_followed(tmp_path):
    folder = tmp_path / "applications"
    folder.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("original\n")
    (folder / "vlc.desktop.tmp").symlink_to(victim)

    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        child_dirs.write_file(fd, "vlc.desktop", "NEW\n")
    finally:
        os.close(fd)

    assert victim.read_text() == "original\n"
    assert (folder / "vlc.desktop").read_text() == "NEW\n"


def test_remove_removes_a_link_not_its_target(tmp_path):
    folder = tmp_path / "applications"
    folder.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep me\n")
    (folder / "evil.desktop").symlink_to(victim)

    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        child_dirs.remove_file(fd, "evil.desktop")
    finally:
        os.close(fd)

    assert victim.read_text() == "keep me\n"
    assert not (folder / "evil.desktop").is_symlink()


def test_root_path_writes_hidden_overrides_and_refuses_a_linked_home(tmp_path):
    apps = _apps(tmp_path)
    home = tmp_path / "home"
    (home / "kid").mkdir(parents=True)
    audit = AuditLogger(dry_run=True)
    guard = AppGuard(RootAdapter(), audit)

    hidden, confined = guard.apply_child_desktop_filters(
        _child(["vlc"]), home_root=home, app_dirs=[apps]
    )
    assert (hidden, confined) == (1, 0)  # quake is hidden; vlc is approved and not confined
    overrides = home / "kid" / ".local" / "share" / "applications"
    assert (overrides / "quake.desktop").read_text().startswith(MANAGED_MARKER)
    assert not (overrides / "vlc.desktop").exists()

    # A child who swaps ~/.local for a link to somewhere else gets nothing written there.
    outside = tmp_path / "etc"
    outside.mkdir()
    (home / "kid" / ".local").rename(tmp_path / "moved")
    (home / "kid" / ".local").symlink_to(outside, target_is_directory=True)
    assert guard.apply_child_desktop_filters(_child([]), home_root=home, app_dirs=[apps]) == (0, 0)
    assert list(outside.iterdir()) == []
