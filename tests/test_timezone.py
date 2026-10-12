"""Time zone in setup: curfews and bedtimes use local time, so the installed system must use the
family's time zone instead of Ubuntu's UTC default."""

import os
from pathlib import Path

import pytest
import yaml

from family_linux.models import FamilyPolicy, ParentAccount
from family_linux.provisioner.autoinstall import SubiquityAutoinstallGenerator
from family_linux.timezones import detect_host_timezone, is_valid_timezone

STRONG = "Correct-Horse-42-Battery"


@pytest.mark.parametrize("name", ["Australia/Sydney", "Europe/London", "America/Argentina/Buenos_Aires", "UTC"])
def test_real_time_zones_are_valid(name):
    assert is_valid_timezone(name)


@pytest.mark.parametrize("name", ["", None, "Mars/Base", "../etc/passwd", "Australia/Sydney; rm -rf /", "/etc/localtime"])
def test_unknown_or_unsafe_names_are_rejected(name):
    assert not is_valid_timezone(name)


def test_host_time_zone_is_read_from_the_localtime_link(tmp_path, monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    zone = tmp_path / "zoneinfo" / "Europe" / "London"
    zone.parent.mkdir(parents=True)
    zone.write_bytes(b"TZif")
    link = tmp_path / "localtime"
    link.symlink_to(zone)
    assert detect_host_timezone(link) == "Europe/London"


def test_tz_variable_wins_and_unreadable_host_falls_back_to_utc(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    assert detect_host_timezone(tmp_path / "missing") == "Asia/Tokyo"
    monkeypatch.delenv("TZ")
    assert detect_host_timezone(tmp_path / "missing") == "UTC"


def test_policy_rejects_an_unknown_zone_and_keeps_a_valid_one():
    policy = FamilyPolicy(parent=ParentAccount("parent", "Parent"), timezone="Mars/Base")
    assert any("time zone" in e for e in policy.validate())
    policy.timezone = "Australia/Sydney"
    assert policy.validate() == []
    assert FamilyPolicy.from_dict(policy.to_dict()).timezone == "Australia/Sydney"


def test_autoinstall_sets_the_zone_or_detects_it_when_unset():
    def zone(policy):
        text = SubiquityAutoinstallGenerator(policy).generate_user_data(locale="en_US.UTF-8", keyboard_layout="us")
        return yaml.safe_load(text.split("\n", 1)[1])["autoinstall"]["timezone"]

    assert zone(FamilyPolicy(parent=ParentAccount("parent", "P", password=STRONG), timezone="Europe/London")) == "Europe/London"
    assert zone(FamilyPolicy(parent=ParentAccount("parent", "P", password=STRONG))) == "geoip"


def test_apply_sets_the_system_time_zone(tmp_path):
    from family_linux.config import PolicyConfigManager
    from family_linux.provisioner.system import SystemProvisioner
    from family_linux.security.adapter import SystemAdapter

    adapter = SystemAdapter(dry_run=True)
    policy = FamilyPolicy(parent=ParentAccount("parent", "Parent Admin"), timezone="Australia/Sydney")
    SystemProvisioner(adapter=adapter, config_manager=PolicyConfigManager(tmp_path / "p.yaml")).apply_policy(policy)
    assert ["timedatectl", "set-timezone", "Australia/Sydney"] in adapter.executed_commands


def test_unattended_install_takes_the_zone_and_rejects_unknown_ones(monkeypatch, tmp_path):
    from family_linux.installer import wizard as wizard_module

    out = tmp_path / "user-data"
    monkeypatch.setattr("sys.argv", ["family-installer", "--dry-run", "--non-interactive", "--parent-pass", STRONG,
                                     "--timezone", "Mars/Base", "--export-autoinstall", str(out)])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert "time zone" in str(exc.value)

    monkeypatch.setattr("sys.argv", ["family-installer", "--dry-run", "--non-interactive", "--parent-pass", STRONG,
                                     "--timezone", "Europe/London", "--export-autoinstall", str(out)])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert exc.value.code == 0
    assert "timezone: Europe/London" in out.read_text()


def test_interactive_step_defaults_to_the_host_zone_and_retries_on_unknown(monkeypatch):
    from family_linux.installer.wizard import InstallerWizard

    wizard = InstallerWizard(dry_run=True, interactive=True)
    wizard.timezone = "Australia/Melbourne"
    answers = iter(["Mars/Base", ""])  # unknown, then Enter to take the default
    monkeypatch.setattr(wizard, "prompt", lambda text, default=None: next(answers) or default)
    wizard.run_step_1_timezone()
    assert wizard.timezone == "Australia/Melbourne"
