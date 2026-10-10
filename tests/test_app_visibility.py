"""Child app visibility follows approval: approved apps show, unapproved apps are hidden, and
overrides that are no longer needed are removed. Overrides this tool did not write are left alone."""

from pathlib import Path

from family_linux.models import AppPolicy, ChildAccount
from family_linux.security.adapter import SystemAdapter
from family_linux.security.app_guard import (
    FLATPAK_DESKTOP_DIR,
    MANAGED_MARKER,
    SNAP_DESKTOP_DIR,
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


def test_system_and_snap_and_flatpak_exports_are_all_discovered():
    assert SNAP_DESKTOP_DIR in SYSTEM_APP_DIRS
    assert FLATPAK_DESKTOP_DIR in SYSTEM_APP_DIRS
