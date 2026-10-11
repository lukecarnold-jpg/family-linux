"""ISO payload: autoinstall copies the Family Linux payload and enables the first-boot apply.
The first-boot step applies the policy once, then leaves a marker."""

import yaml

from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount
from family_linux.provisioner.autoinstall import FIRSTBOOT_UNIT, ISO_PAYLOAD_DIR, SubiquityAutoinstallGenerator
from family_linux.provisioner import firstboot


def _policy(parent_password="Correct-Horse-42-Battery"):
    return FamilyPolicy(
        parent=ParentAccount("parent", "Family Administrator", password=parent_password),
        children=[ChildAccount.create("kid", "Kid", "pre_teen", password="kidpass123")],
    )


def _user_data(policy=None):
    text = SubiquityAutoinstallGenerator(policy or _policy()).generate_user_data(locale="en_US.UTF-8", keyboard_layout="us")
    return text, yaml.safe_load(text.split("\n", 1)[1])["autoinstall"]


def test_autoinstall_copies_the_payload_and_enables_first_boot():
    _, auto = _user_data()
    commands = "\n".join(auto["late-commands"])
    assert f"cp -a {ISO_PAYLOAD_DIR} /target/opt/" in commands
    assert f"cp {ISO_PAYLOAD_DIR}/policy.yaml /target/etc/family-linux/policy.yaml" in commands
    assert f"curtin in-target -- systemctl enable {FIRSTBOOT_UNIT}" in commands


def test_autoinstall_installs_the_desktop_the_children_need():
    _, auto = _user_data()
    assert "ubuntu-desktop-minimal" in auto["packages"]


def test_autoinstall_contains_no_plaintext_passwords():
    text, _ = _user_data()
    assert "Correct-Horse-42-Battery" not in text
    assert "kidpass123" not in text


def test_firstboot_is_skipped_once_the_marker_exists(tmp_path):
    marker = tmp_path / "firstboot.done"
    marker.write_text("applied\n")
    assert firstboot.run(policy_path=tmp_path / "missing.yaml", marker=marker) == 0


def test_firstboot_applies_the_policy_and_leaves_a_marker(tmp_path):
    from family_linux.config import PolicyConfigManager

    policy_path = tmp_path / "policy.yaml"
    PolicyConfigManager(policy_path).save_policy(_policy(), reason="test")
    marker = tmp_path / "state" / "firstboot.done"

    assert firstboot.run(policy_path=policy_path, marker=marker) == 0
    assert marker.exists()


def test_browser_policies_are_written_even_with_no_children(tmp_path):
    from family_linux.security.adapter import SystemAdapter
    from family_linux.provisioner.system import SystemProvisioner
    from family_linux.config import PolicyConfigManager

    adapter = SystemAdapter(dry_run=True)
    policy = FamilyPolicy(parent=ParentAccount("parent", "Parent Admin", password=None), children=[])
    provisioner = SystemProvisioner(adapter=adapter, config_manager=PolicyConfigManager(tmp_path / "policy.yaml"))
    provisioner.apply_policy(policy, reason="test")

    written = set(adapter.simulated_files)
    assert "/etc/firefox/policies/policies.json" in written
    assert "/etc/chromium/policies/managed/family-policy.json" in written
