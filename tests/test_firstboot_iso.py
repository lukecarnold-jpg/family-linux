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


def test_late_commands_do_not_touch_child_accounts_that_do_not_exist_yet():
    # Children are created by cloud-init on first boot, after the late commands have run.
    _, auto = _user_data()
    assert not any("kid" in command for command in auto["late-commands"])


def test_disk_gets_a_removable_media_boot_path():
    _, auto = _user_data()
    commands = "\n".join(auto["late-commands"])
    assert "BOOTAA64.EFI" in commands and "BOOTX64.EFI" in commands


def test_firstboot_runs_after_cloud_init_creates_the_accounts():
    from pathlib import Path
    unit = Path(__file__).resolve().parents[1] / "config" / "systemd" / "family-linux-firstboot.service"
    after = next(line for line in unit.read_text().splitlines() if line.startswith("After="))
    assert "cloud-init.service" in after
    # cloud-final.service runs after multi-user.target; ordering after it is a cycle (job dropped).
    assert "cloud-final" not in after


def test_installed_system_can_import_the_package_from_any_service():
    _, auto = _user_data()
    commands = "\n".join(auto["late-commands"])
    assert "/target/usr/lib/python3/dist-packages/family-linux.pth" in commands
    assert f"install -m 755 {ISO_PAYLOAD_DIR}/family-ctl /target/usr/local/sbin/family-ctl" in commands


def test_gateway_reloads_the_child_rules_on_every_start():
    # nftables rules do not survive a reboot; found when a VirtualBox VM rebooted with no child rules.
    from family_linux.security.web_gateway import NFT_RULES_PATH, render_service
    unit = render_service("/usr/bin/python3")
    assert f"ExecStartPre=/usr/sbin/nft -f {NFT_RULES_PATH}" in unit
    assert unit.index("ExecStartPre=") < unit.index("ExecStart=/usr/bin/python3")


def test_child_shell_is_listed_so_the_login_screen_shows_children(tmp_path):
    from family_linux.security.adapter import SystemAdapter
    from family_linux.security.users import UserManager

    shells = tmp_path / "shells"
    shells.write_text("/bin/sh\n/bin/bash\n")
    adapter = SystemAdapter(dry_run=True)
    UserManager(adapter).allow_child_shell_on_login_screen("/usr/sbin/nologin", shells_file=shells)
    assert adapter.simulated_files[str(shells)] == "/bin/sh\n/bin/bash\n/usr/sbin/nologin\n"

    shells.write_text("/bin/sh\n/usr/sbin/nologin\n")
    adapter = SystemAdapter(dry_run=True)
    UserManager(adapter).allow_child_shell_on_login_screen("/usr/sbin/nologin", shells_file=shells)
    assert str(shells) not in adapter.simulated_files


def test_network_is_managed_by_networkmanager_without_the_networkd_wait():
    _, auto = _user_data()
    assert auto["network"]["network"]["renderer"] == "NetworkManager"
    assert "curtin in-target -- systemctl disable systemd-networkd-wait-online.service" in auto["late-commands"]
