"""Tests for Family Linux interactive installer and Subiquity autoinstall generator."""

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
