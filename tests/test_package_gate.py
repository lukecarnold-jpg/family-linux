"""Software installs for child accounts: the polkit rule that asks for the parent's password, and the
desktop filter for apps installed from Debian packages."""

from pathlib import Path

import pytest

from family_linux.models import AppPolicy, ChildAccount
from family_linux.security.adapter import SystemAdapter
from family_linux.security.app_guard import AppGuard
from family_linux.security.package_gate import (
    PACKAGEKIT_ACTION_PREFIX,
    PackageInstallGate,
    render_polkit_rule,
    rule_in_place,
)


def test_rule_requires_admin_authentication_for_every_packagekit_action():
    rule = render_polkit_rule(["kid", "teen"])
    assert "polkit.Result.AUTH_ADMIN" in rule
    assert "polkit.Result.AUTH_ADMIN_KEEP" not in rule
    # A prefix, not a list of names, so install, remove and update are all covered
    assert f'action.id.indexOf("{PACKAGEKIT_ACTION_PREFIX}") === 0' in rule
    assert '"kid", "teen"' in rule


def test_rule_with_no_children_names_nobody():
    rule = render_polkit_rule([])
    assert "var children = [];" in rule


def test_rule_refuses_unsafe_usernames():
    with pytest.raises(ValueError):
        render_polkit_rule(['kid"); evil(); ("'])


def test_rule_in_place_checks_every_child_and_the_packagekit_prefix():
    rule = render_polkit_rule(["kid"])
    assert rule_in_place(rule, ["kid"])
    assert not rule_in_place(rule, ["kid", "teen"])
    assert not rule_in_place("polkit.addRule(function () {});", ["kid"])


def test_dry_run_writes_the_rule_and_does_not_need_root(tmp_path):
    rule_path = tmp_path / "50-family-linux-packages.rules"
    adapter = SystemAdapter(dry_run=True)
    gate = PackageInstallGate(adapter, rule_path=rule_path)

    gate.apply(["kid"])

    assert adapter.simulated_files[str(rule_path)] == render_polkit_rule(["kid"])
    assert not rule_path.exists()


def test_appguard_hides_unapproved_apps_and_confines_approved_ones(tmp_path):
    apps_dir = tmp_path / "applications"
    apps_dir.mkdir()
    (apps_dir / "vlc.desktop").write_text("[Desktop Entry]\nName=VLC\nExec=vlc %U\n")
    (apps_dir / "quake.desktop").write_text("[Desktop Entry]\nName=Quake\nExec=quake\n")
    home = tmp_path / "home"
    child = ChildAccount.create("kid", "Kid", "pre_teen")
    child.app_policy = AppPolicy(allow_list_mode=True, approved_apps=["vlc"])
    child_apps = home / "kid" / ".local" / "share" / "applications"

    adapter = SystemAdapter(dry_run=True)
    hidden, confined = AppGuard(adapter).apply_child_desktop_filters(
        child, confine=True, home_root=home, app_dirs=[apps_dir]
    )

    assert (hidden, confined) == (1, 1)
    written = adapter.simulated_files
    assert "NoDisplay=true" in written[str(child_apps / "quake.desktop")]
    assert "Exec=aa-exec -p family-linux-child -- vlc %U" in written[str(child_apps / "vlc.desktop")]


def test_debian_package_folder_is_in_the_default_discovery_list():
    from family_linux.security.app_guard import SYSTEM_APP_DIRS
    assert Path("/usr/share/applications") in SYSTEM_APP_DIRS
