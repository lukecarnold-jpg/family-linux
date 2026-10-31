"""Child menu refresh: the systemd path unit and the re-apply run it triggers."""

from family_linux.config import PolicyConfigManager
from family_linux.models import AppPolicy, ChildAccount, FamilyPolicy, ParentAccount
from family_linux.security.adapter import SystemAdapter
from family_linux.security.app_guard import SYSTEM_APP_DIRS
from family_linux.security.desktop_refresh import (
    WATCHED_DIRS,
    refresh,
    render_path_unit,
    render_service_unit,
)


def test_path_unit_watches_every_install_location_and_starts_the_refresh_service():
    unit = render_path_unit()
    for directory in ("/usr/share/applications", "/usr/local/share/applications"):
        assert f"PathChanged={directory}" in unit
    assert "Unit=family-appguard.service" in unit
    assert list(WATCHED_DIRS) == list(SYSTEM_APP_DIRS)


def test_service_unit_runs_the_module_with_the_installing_interpreter():
    unit = render_service_unit("/opt/fl/bin/python3")
    assert "ExecStart=/opt/fl/bin/python3 -m family_linux.security.desktop_refresh" in unit
    assert "Type=oneshot" in unit


def test_refresh_reapplies_approvals_for_every_child(tmp_path):
    config = tmp_path / "policy.yaml"
    policy = FamilyPolicy(
        parent=ParentAccount("parent", "Parent Admin", password=None),
        children=[ChildAccount.create("kid", "Kid", "pre_teen")],
    )
    policy.children[0].app_policy = AppPolicy(allow_list_mode=True, approved_apps=["firefox"])
    PolicyConfigManager(config).save_policy(policy, reason="test")  # writes only under tmp_path

    lines = refresh(SystemAdapter(dry_run=True), config_path=config)

    assert len(lines) == 1
    assert lines[0].startswith("kid: ") and lines[0].endswith("confined")
