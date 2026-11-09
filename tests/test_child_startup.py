"""A child's sign-in startup files are locked: replaced by empty files and folders the child cannot
change, without following any symlink the child planted. Runs on real files without root (no chown,
and chattr is allowed to fail), so it checks the descriptor-based code directly."""

import os
from pathlib import Path

import pytest

from family_linux.models import ChildAccount
from family_linux.security.adapter import SystemAdapter
from family_linux.security.child_startup import (
    LOCKED_PATHS,
    ChildStartupLock,
    lock_startup_paths,
    relative_paths,
)

pytestmark = pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    (home / "kid").mkdir(parents=True)
    return home


def test_every_sign_in_script_and_startup_folder_is_covered():
    paths = relative_paths()
    for expected in (".profile", ".config/plasma-workspace/env", ".config/autostart",
                     ".config/environment.d", ".config/systemd/user"):
        assert expected in paths


def test_lock_creates_empty_files_and_folders(tmp_path):
    home = _home(tmp_path)
    locked, problems = lock_startup_paths(home, "kid", child_owner=None, lock_owner=None)
    # The immutable flag needs root and ext4; without them the files and folders are still in place.
    assert all("immutable flag not set" in p for p in problems)
    for parents, name, kind in LOCKED_PATHS:
        path = home / "kid" / Path(*parents, name)
        assert path.is_file() if kind == "file" else path.is_dir()
        if kind == "file":
            assert path.read_text() == ""


def test_an_existing_profile_is_emptied_and_an_autostart_folder_is_set_aside(tmp_path):
    home = _home(tmp_path)
    (home / "kid" / ".profile").write_text("konsole &\n")
    autostart = home / "kid" / ".config" / "autostart"
    autostart.mkdir(parents=True)
    (autostart / "shell.desktop").write_text("[Desktop Entry]\nExec=konsole\n")

    lock_startup_paths(home, "kid", child_owner=None, lock_owner=None)

    assert (home / "kid" / ".profile").read_text() == ""
    assert list(autostart.iterdir()) == []
    kept = home / "kid" / ".config" / ".autostart.family-linux-disabled" / "shell.desktop"
    assert kept.exists()  # set aside, not deleted


def test_a_symlinked_profile_is_replaced_without_touching_its_target(tmp_path):
    home = _home(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me\n")
    os.symlink(outside, home / "kid" / ".profile")

    lock_startup_paths(home, "kid", child_owner=None, lock_owner=None)

    assert outside.read_text() == "keep me\n"
    assert not (home / "kid" / ".profile").is_symlink()


def test_a_symlinked_config_folder_is_refused_and_outside_is_untouched(tmp_path):
    home = _home(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, home / "kid" / ".config")

    locked, problems = lock_startup_paths(home, "kid", child_owner=None, lock_owner=None)

    assert list(outside.iterdir()) == []
    assert any(".config" in p for p in problems)


def test_a_second_apply_keeps_the_locked_paths(tmp_path):
    home = _home(tmp_path)
    lock_startup_paths(home, "kid", child_owner=None, lock_owner=None)
    lock_startup_paths(home, "kid", child_owner=None, lock_owner=None)
    assert not (home / "kid" / ".config" / ".autostart.family-linux-disabled").exists()


def test_dry_run_records_every_path():
    adapter = SystemAdapter(dry_run=True)
    child = ChildAccount.create("kid", "Kid", "pre_teen")
    assert ChildStartupLock(adapter).apply(child, home_root=Path("/home")) == []
    assert adapter.simulated_files["/home/kid/.profile"] == ""
    assert ["chattr", "+i", "/home/kid/.config/plasma-workspace/env"] in adapter.executed_commands


def test_data_folder_start_up_paths_are_locked():
    from family_linux.security.child_startup import relative_paths

    paths = relative_paths()
    for path in (".local/share/systemd/user", ".local/share/dbus-1/services", ".local/share/kio/servicemenus",
                 ".local/share/plasma/plasmoids", ".local/share/kwin/scripts"):
        assert path in paths


def test_pam_hook_refuses_unknown_users_and_ignores_close_session():
    from family_linux.security.child_startup import pam_main

    assert pam_main({"PAM_USER": "no-such-user-here", "PAM_TYPE": "open_session"}) == 1
    assert pam_main({"PAM_USER": "", "PAM_TYPE": "open_session"}) == 1
    assert pam_main({"PAM_USER": "anyone", "PAM_TYPE": "close_session"}) == 0


def test_relock_after_a_parent_folder_is_renamed(tmp_path, monkeypatch):
    # The immutable flag does not stop renaming ~/.config/systemd (owned by the child) and making a
    # new one. Locking again, as the sign-in hook does, sets the child's folder aside and puts the
    # lock back. Runs without root, so ownership is the test user's and the flag is not set.
    import os
    from family_linux.security import child_startup

    home = tmp_path / "kid"
    home.mkdir()
    me = (os.getuid(), os.getgid())
    monkeypatch.setattr(child_startup.child_dirs, "set_immutable", lambda fd, on: True)
    assert child_startup.lock_startup_paths(tmp_path, "kid", me, lock_owner=me)[1] == []

    (home / ".config" / "systemd").rename(home / ".config" / "systemd-old")
    (home / ".config" / "systemd" / "user").mkdir(parents=True)
    (home / ".config" / "systemd" / "user" / "evil.service").write_text("[Service]\nExecStart=/bin/sh\n")

    assert child_startup.lock_startup_paths(tmp_path, "kid", me, lock_owner=me)[1] == []
    assert list((home / ".config" / "systemd" / "user").iterdir()) == []
    assert (home / ".config" / "systemd" / ".user.family-linux-disabled" / "evil.service").exists()
