"""Child app visibility follows approval: approved apps show, unapproved apps are hidden, and
overrides that are no longer needed are removed. Overrides this tool did not write are left alone."""

from pathlib import Path

from family_linux.models import AppPolicy, ChildAccount
from family_linux.security.adapter import SystemAdapter
from family_linux.security.app_guard import (
    MANAGED_MARKER,
    SYSTEM_APP_DIRS,
    AppGuard,
    is_managed_override,
)

HIDDEN_OVERRIDE = (
    f"{MANAGED_MARKER}\n[Desktop Entry]\nType=Application\nName=Quake\nNoDisplay=true\nHidden=true\n"
)


def _setup(tmp_path: Path, approved):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "vlc.desktop").write_text("[Desktop Entry]\nName=VLC\nExec=vlc %U\n")
    home = tmp_path / "home"
    child = ChildAccount.create("kid", "Kid", "pre_teen")
    child.app_policy = AppPolicy(allow_list_mode=True, approved_apps=approved)
    overrides = home / "kid" / ".local" / "share" / "applications"
    overrides.mkdir(parents=True)
    return apps, home, child, overrides


def test_approved_app_loses_an_override_written_while_it_was_unapproved(tmp_path):
    apps, home, child, overrides = _setup(tmp_path, approved=["vlc"])
    stale = overrides / "vlc.desktop"
    stale.write_text(HIDDEN_OVERRIDE.replace("Quake", "VLC"))

    adapter = SystemAdapter(dry_run=True)
    AppGuard(adapter).apply_child_desktop_filters(child, home_root=home, app_dirs=[apps])

    assert str(stale) in adapter.removed_files


def test_override_not_written_by_us_is_kept(tmp_path):
    apps, home, child, overrides = _setup(tmp_path, approved=["vlc"])
    mine = overrides / "vlc.desktop"
    mine.write_text("[Desktop Entry]\nName=VLC\nNoDisplay=true\nExec=vlc --my-own-flags\n")

    adapter = SystemAdapter(dry_run=True)
    AppGuard(adapter).apply_child_desktop_filters(child, home_root=home, app_dirs=[apps])

    assert str(mine) not in adapter.removed_files


def test_override_for_an_uninstalled_app_is_removed(tmp_path):
    apps, home, child, overrides = _setup(tmp_path, approved=["vlc"])
    gone = overrides / "old-game.desktop"
    gone.write_text(HIDDEN_OVERRIDE)

    adapter = SystemAdapter(dry_run=True)
    AppGuard(adapter).apply_child_desktop_filters(child, home_root=home, app_dirs=[apps])

    assert str(gone) in adapter.removed_files


def test_hidden_overrides_carry_the_marker(tmp_path):
    apps, home, child, overrides = _setup(tmp_path, approved=[])
    adapter = SystemAdapter(dry_run=True)
    AppGuard(adapter).apply_child_desktop_filters(child, home_root=home, app_dirs=[apps])

    content = adapter.simulated_files[str(overrides / "vlc.desktop")]
    assert content.startswith(MANAGED_MARKER)
    assert "NoDisplay=true" in content


def test_legacy_hidden_template_is_recognised_as_ours():
    legacy = "[Desktop Entry]\nType=Application\nName=Quake\nNoDisplay=true\nHidden=true\n"
    assert is_managed_override(legacy)
    assert not is_managed_override("[Desktop Entry]\nName=Mine\nExec=mine\n")


def test_debian_application_folders_are_discovered():
    assert Path("/usr/share/applications") in SYSTEM_APP_DIRS
    assert Path("/usr/local/share/applications") in SYSTEM_APP_DIRS


def test_child_owns_local_and_share_and_the_overrides_folder_is_locked_after_writing(tmp_path):
    # Root used to own ~/.local and ~/.local/share, so apps could not save there for children.
    apps, home, child, overrides = _setup(tmp_path, approved=[])
    adapter = SystemAdapter(dry_run=True)
    AppGuard(adapter).apply_child_desktop_filters(child, home_root=home, app_dirs=[apps])

    local = home / "kid" / ".local"
    commands = adapter.executed_commands
    assert ["chown", "kid:", str(local)] in commands
    assert ["chown", "kid:", str(local / "share")] in commands
    unlock = commands.index(["chattr", "-i", str(overrides)])
    assert commands[-1] == ["chattr", "+i", str(overrides)]  # locked again, last
    assert unlock < len(commands) - 1
    assert str(overrides / "vlc.desktop") in adapter.simulated_files  # the hidden override was written
