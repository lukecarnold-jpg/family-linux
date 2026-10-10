"""Tests for Family Linux interactive installer and Subiquity autoinstall generator."""

import itertools
from pathlib import Path
import pytest
import yaml

from family_linux.models import ParentAccount, ChildAccount, FamilyPolicy, AgeTier
from family_linux.installer.wizard import InstallerWizard
from family_linux.provisioner.autoinstall import SubiquityAutoinstallGenerator


def test_installer_wizard_validation_and_dry_run():
    wizard = InstallerWizard(dry_run=True, interactive=False)
    wizard.parent = ParentAccount(
        username="lead_parent",
        full_name="Lead Parent Admin",
        password="SafePassword123!",
        role="local_admin",
        sudo_access=True,
    )
    wizard.children.append(ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.YOUNG_CHILD))

    policy = wizard.run_step_9_validation()
    assert policy.parent.username == "lead_parent"
    assert len(policy.children) == 1

    # Check summary
    confirmed = wizard.run_step_10_summary_and_confirmation(policy)
    assert confirmed is True

    # Check apply in dry run
    results = wizard.run_step_11_apply(policy)
    assert results["success"] is True
    assert len(results["actions"]) > 0


def test_installer_wizard_rejects_missing_parent():
    wizard = InstallerWizard(dry_run=True, interactive=False)
    wizard.parent = None

    with pytest.raises(ValueError, match="Parent account was not configured"):
        wizard.run_step_9_validation()


def test_subiquity_autoinstall_generator():
    parent = ParentAccount(
        username="parent",
        full_name="Family Admin",
        password="SuperSecretPassword!",
        sudo_access=True,
    )
    child = ChildAccount.create("alice", "Alice", password="ChildSecretPassword!")
    policy = FamilyPolicy(parent=parent, children=[child])

    generator = SubiquityAutoinstallGenerator(policy)
    yaml_text = generator.generate_user_data(hostname="family-desktop")

    assert yaml_text.startswith("#cloud-config")
    # Parse YAML to verify validity
    parsed = yaml.safe_load(yaml_text)
    assert "autoinstall" in parsed
    auto = parsed["autoinstall"]
    assert auto["identity"]["username"] == "parent"
    assert auto["identity"]["hostname"] == "family-desktop"
    assert "ufw" in auto["packages"]
    assert "apparmor" in auto["packages"]

    # Verify late commands enforce group separation and ufw
    late_cmds = auto["late-commands"]
    assert any("family-children" in cmd for cmd in late_cmds)
    assert any("ufw --force enable" in cmd for cmd in late_cmds)


def test_non_interactive_install_rejects_weak_parent_password(monkeypatch, capsys):
    from family_linux.installer import wizard as wizard_module

    for weak in ["Short1!", "alllowercase1!", "NoDigitsHere!!", "NoSpecialChar123", "nouppercase123!"]:
        monkeypatch.setattr("sys.argv", ["family-installer", "--dry-run", "--non-interactive", "--parent-pass", weak])
        with pytest.raises(SystemExit) as exc:
            wizard_module.main()
        assert "--parent-pass" in str(exc.value)
        assert weak not in str(exc.value)  # the message never echoes the password


def test_non_interactive_install_accepts_a_compliant_parent_password(monkeypatch, tmp_path):
    from family_linux.installer import wizard as wizard_module

    out = tmp_path / "user-data"
    monkeypatch.setattr("sys.argv", [
        "family-installer", "--dry-run", "--non-interactive", "--export-autoinstall", str(out),
        "--parent-pass", "Correct-Horse-42",
    ])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert exc.value.code == 0
    assert out.exists()


def test_interactive_parent_step_retries_until_password_complies(monkeypatch):
    wizard = InstallerWizard(dry_run=True, interactive=True)
    answers = itertools.cycle(["parent", "Parent Admin"])
    passwords = iter(["short1!", "LongEnoughButNoSymbol1", "Long-Enough-Password1"])
    monkeypatch.setattr(wizard, "prompt", lambda text, default=None: next(answers))
    monkeypatch.setattr(wizard, "secret_prompt", lambda text: next(passwords))

    wizard.run_step_5_parent_account()

    assert wizard.parent is not None
    assert wizard.parent.password == "Long-Enough-Password1"
