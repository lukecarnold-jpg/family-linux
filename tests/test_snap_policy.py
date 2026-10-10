"""Snap installs for child accounts: the polkit rule and AppGuard handling of snap desktop entries."""

from pathlib import Path

import pytest

from family_linux.models import AppPolicy, ChildAccount, ParentAccount, FamilyPolicy
from family_linux.security.adapter import SystemAdapter
from family_linux.security.app_guard import AppGuard, SNAP_DESKTOP_DIR
from family_linux.security.snap_policy import SNAP_ACTIONS, SnapInstallGate, render_polkit_rule, rule_in_place


def test_rule_requires_admin_authentication_for_child_snap_actions():
    rule = render_polkit_rule(["kid", "teen"])
    assert "polkit.Result.AUTH_ADMIN" in rule
    assert "polkit.Result.AUTH_ADMIN_KEEP" not in rule
    for action in SNAP_ACTIONS:
        assert f'"{action}"' in rule
    assert '"kid", "teen"' in rule


def test_rule_with_no_children_names_nobody():
    rule = render_polkit_rule([])
    assert "var children = [];" in rule


def test_rule_refuses_unsafe_usernames():
    with pytest.raises(ValueError):
        render_polkit_rule(['kid"); evil(); ("'])


def test_rule_in_place_checks_every_child_and_action():
    rule = render_polkit_rule(["kid"])
    assert rule_in_place(rule, ["kid"])
    assert not rule_in_place(rule, ["kid", "teen"])
    assert not rule_in_place("polkit.addRule(function () {});", ["kid"])


def test_dry_run_writes_the_rule_and_does_not_need_root(tmp_path):
    rule_path = tmp_path / "50-family-linux-snap.rules"
    adapter = SystemAdapter(dry_run=True)
    gate = SnapInstallGate(adapter, rule_path=rule_path)

    gate.apply(["kid"])

    assert adapter.simulated_files[str(rule_path)] == render_polkit_rule(["kid"])
    assert not rule_path.exists()


def test_appguard_hides_unapproved_snap_apps_and_does_not_confine_approved_ones(tmp_path):
    snap_dir = tmp_path / "snapd"
    snap_dir.mkdir()
    (snap_dir / "vlc_vlc.desktop").write_text("[Desktop Entry]\nName=VLC\nExec=/snap/bin/vlc %U\n")
    (snap_dir / "games_quake.desktop").write_text("[Desktop Entry]\nName=Quake\nExec=/snap/bin/quake\n")
    home = tmp_path / "home"
    child = ChildAccount.create("kid", "Kid", "pre_teen")
    child.app_policy = AppPolicy(allow_list_mode=True, approved_apps=["vlc"])
    apps_dir = home / "kid" / ".local" / "share" / "applications"

    adapter = SystemAdapter(dry_run=True)
    hidden, confined = AppGuard(adapter).apply_child_desktop_filters(
        child, confine=True, home_root=home, app_dirs=[snap_dir], snap_dir=snap_dir
    )

    assert (hidden, confined) == (1, 0)
    written = adapter.simulated_files
    assert "NoDisplay=true" in written[str(apps_dir / "games_quake.desktop")]
    # Approved snap apps are left as snapd exports them: no aa-exec wrapper, not hidden
    assert str(apps_dir / "vlc_vlc.desktop") not in written


def test_snap_desktop_dir_is_in_the_default_discovery_list():
    from family_linux.security.app_guard import SYSTEM_APP_DIRS
    assert SNAP_DESKTOP_DIR in SYSTEM_APP_DIRS
