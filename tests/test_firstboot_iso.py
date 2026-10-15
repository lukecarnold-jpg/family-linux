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


def test_child_is_marked_as_a_regular_account_for_the_login_screen(tmp_path):
    # AccountsService hides nologin accounts even when /etc/shells lists nologin (seen in VirtualBox).
    from family_linux.security.adapter import SystemAdapter
    from family_linux.security.users import UserManager

    adapter = SystemAdapter(dry_run=True)
    UserManager(adapter).show_child_on_login_screen("kid", users_dir=tmp_path)
    assert adapter.simulated_files[str(tmp_path / "kid")] == "[User]\nSystemAccount=false\n"


def test_login_screen_override_keeps_other_accountsservice_settings(tmp_path):
    from family_linux.security.adapter import SystemAdapter
    from family_linux.security.users import UserManager

    (tmp_path / "kid").write_text("[User]\nSession=ubuntu\nSystemAccount=true\nLanguage=en_AU.UTF-8\n")
    adapter = SystemAdapter(dry_run=True)
    UserManager(adapter).show_child_on_login_screen("kid", users_dir=tmp_path)
    written = adapter.simulated_files[str(tmp_path / "kid")]
    assert "SystemAccount=false" in written and "SystemAccount=true" not in written
    assert "Session=ubuntu" in written and "Language=en_AU.UTF-8" in written

    (tmp_path / "kid").write_text(written)
    adapter = SystemAdapter(dry_run=True)
    UserManager(adapter).show_child_on_login_screen("kid", users_dir=tmp_path)
    assert str(tmp_path / "kid") not in adapter.simulated_files  # already correct: no rewrite


def test_installed_system_uses_networkmanager_but_the_installer_does_not():
    _, auto = _user_data()
    # The live-server installer has no NetworkManager; a renderer here broke the install.
    assert "renderer" not in auto["network"]["network"]
    commands = "\n".join(auto["late-commands"])
    assert "/target/etc/netplan/01-network-manager-all.yaml" in commands
    assert "renderer: NetworkManager" in commands
    assert "curtin in-target -- systemctl disable systemd-networkd-wait-online.service" in auto["late-commands"]


def test_wallpaper_is_installed_only_when_the_iso_carries_one():
    from family_linux.models import FamilyPolicy, ParentAccount
    from family_linux.provisioner.autoinstall import ISO_PAYLOAD_DIR, SubiquityAutoinstallGenerator, WALLPAPER_OVERRIDE

    text = SubiquityAutoinstallGenerator(FamilyPolicy(parent=ParentAccount("parent", "P", password="Correct-Horse-42-Battery"))).generate_user_data(locale="en_US.UTF-8", keyboard_layout="us")
    commands = yaml.safe_load(text.split("\n", 1)[1])["autoinstall"]["late-commands"]
    wallpaper = next(c for c in commands if WALLPAPER_OVERRIDE in c)
    # guarded, so an ISO built without config/wallpaper/ installs nothing and does not fail
    assert wallpaper.startswith(f"sh -c 'if [ -f {ISO_PAYLOAD_DIR}/{WALLPAPER_OVERRIDE} ]")
    assert "/target/usr/share/backgrounds/family-linux/" in wallpaper
    assert "/target/usr/share/glib-2.0/schemas/" in wallpaper
    assert commands[commands.index(wallpaper) + 1] == "curtin in-target -- glib-compile-schemas /usr/share/glib-2.0/schemas"
