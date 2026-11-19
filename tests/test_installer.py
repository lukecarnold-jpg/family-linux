"""Tests for Family Linux interactive installer and the Debian preseed generator."""

import itertools
from pathlib import Path
import pytest
import yaml

from family_linux.models import ParentAccount, ChildAccount, FamilyPolicy, AgeTier
from family_linux.installer.wizard import InstallerWizard
from family_linux.provisioner.preseed import DebianPreseedGenerator


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


def test_debian_preseed_generator_writes_the_install_plan():
    parent = ParentAccount(
        username="parent",
        full_name="Family Admin",
        password="SuperSecretPassword!",
        sudo_access=True,
    )
    child = ChildAccount.create("alice", "Alice", password="ChildSecretPassword!")
    policy = FamilyPolicy(parent=parent, children=[child])

    preseed = DebianPreseedGenerator(policy).generate_preseed(hostname="family-desktop")
    assert "d-i netcfg/get_hostname string family-desktop" in preseed
    assert "d-i passwd/username string parent" in preseed
    assert "tasksel tasksel/first multiselect kde-desktop" in preseed
    assert "ufw" in preseed.split("d-i pkgsel/include string ", 1)[1].split("\n", 1)[0].split()
    assert "apparmor" in preseed.split("d-i pkgsel/include string ", 1)[1].split("\n", 1)[0].split()

    # The late script enforces group separation, sudo for the parent only, and the firewall
    late = DebianPreseedGenerator(policy).generate_late_script()
    assert "family-children" in late
    assert "%family-children ALL=(ALL:ALL) !ALL" in late
    assert "in-target ufw" not in late  # ufw cannot run in the chroot; the first boot applies it


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
        "family-installer", "--dry-run", "--non-interactive", "--export-preseed", str(out),
        "--parent-pass", "Correct-Horse-42",
    ])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert exc.value.code == 0
    assert out.exists()
    assert (out.parent / "late-command.sh").exists()


def test_non_interactive_starter_sites_can_be_declined_per_child(monkeypatch, tmp_path):
    from family_linux.installer import wizard as wizard_module

    policy_out = tmp_path / "policy.yaml"
    monkeypatch.setattr("sys.argv", [
        "family-installer", "--dry-run", "--non-interactive", "--export-preseed", str(tmp_path / "user-data"),
        "--export-policy", str(policy_out), "--parent-pass", "Correct-Horse-42",
        "--child", "kid1:Kid One:young_child:ChildSecret12",
        "--child", "kid2:Kid Two:teen:ChildSecret12",
        "--no-starter-sites", "kid1",
    ])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert exc.value.code == 0

    kids = {c["username"]: c for c in yaml.safe_load(policy_out.read_text())["children"]}
    assert kids["kid1"]["web_filter"]["allowed_domains"] == []
    assert "britannica.com" in kids["kid2"]["web_filter"]["allowed_domains"]


def test_non_interactive_no_starter_sites_must_name_a_child(monkeypatch):
    from family_linux.installer import wizard as wizard_module

    monkeypatch.setattr("sys.argv", [
        "family-installer", "--dry-run", "--non-interactive", "--parent-pass", "Correct-Horse-42",
        "--child", "kid1:Kid One:young_child:ChildSecret12",
        "--no-starter-sites", "kid9",
    ])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert "kid9" in str(exc.value)


def test_interactive_child_step_offers_the_starter_sites_and_a_declined_list_is_empty(monkeypatch, capsys):
    wizard = InstallerWizard(dry_run=True, interactive=True)
    answers = {
        "Do you want to create a child account now?": "y",
        "Child username": "kid1",
        "Child full name": "Kid One",
        "Pre-fill these starter sites": "n",
        "Add another child account?": "n",
    }
    asked = []

    def fake_prompt(text, default=None):
        asked.append(text)
        for key, value in answers.items():
            if key in text:
                return value
        return default

    monkeypatch.setattr(wizard, "prompt", fake_prompt)
    monkeypatch.setattr(wizard, "prompt_choice", lambda text, options, default: options[2])  # teen
    monkeypatch.setattr(wizard, "secret_prompt", lambda text: "ChildSecret12")
    wizard.run_step_6_child_accounts()

    assert sum("Pre-fill these starter sites" in text for text in asked) == 1
    assert "britannica.com" in capsys.readouterr().out
    assert len(wizard.children) == 1
    assert wizard.children[0].web_filter.allowed_domains == []


def test_interactive_parent_step_retries_until_password_complies(monkeypatch):
    wizard = InstallerWizard(dry_run=True, interactive=True)
    answers = itertools.cycle(["parent", "Parent Admin"])
    passwords = iter(["short1!", "LongEnoughButNoSymbol1", "Long-Enough-Password1"])
    monkeypatch.setattr(wizard, "prompt", lambda text, default=None: next(answers))
    monkeypatch.setattr(wizard, "secret_prompt", lambda text: next(passwords))

    wizard.run_step_5_parent_account()

    assert wizard.parent is not None
    assert wizard.parent.password == "Long-Enough-Password1"
