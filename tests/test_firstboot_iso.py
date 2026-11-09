"""First boot on the installed system: the apply runs once and leaves a marker. The services it relies
on (DNS filter, browsers, wallpaper) are checked here too. The installer side is in test_preseed.py."""

from pathlib import Path

from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount
from family_linux.provisioner import firstboot


def _policy():
    return FamilyPolicy(
        parent=ParentAccount("parent", "Family Administrator", password="Correct-Horse-42-Battery"),
        children=[ChildAccount.create("kid", "Kid", "pre_teen", password="kidpass123")],
    )


def _unit_text():
    return (Path(__file__).resolve().parents[1] / "config" / "systemd" / "family-linux-firstboot.service").read_text()


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
    from family_linux.security.browser import CHROMIUM_POLICY_PATH, FIREFOX_ETC_POLICY_PATHS, FIREFOX_POLICY_PATH

    adapter = SystemAdapter(dry_run=True)
    policy = FamilyPolicy(parent=ParentAccount("parent", "Parent Admin", password=None), children=[])
    provisioner = SystemProvisioner(adapter=adapter, config_manager=PolicyConfigManager(tmp_path / "policy.yaml"))
    provisioner.apply_policy(policy, reason="test")

    written = set(adapter.simulated_files)
    assert str(FIREFOX_POLICY_PATH) in written
    assert all(str(path) in written for path in FIREFOX_ETC_POLICY_PATHS)
    assert str(CHROMIUM_POLICY_PATH) in written


def test_firefox_policy_is_written_to_the_firefox_esr_folder_the_debian_package_reads():
    from family_linux.security.browser import FIREFOX_POLICY_PATH

    assert str(FIREFOX_POLICY_PATH) == "/usr/lib/firefox-esr/distribution/policies.json"


def test_firstboot_runs_after_the_network_and_resolver_are_up():
    after = next(line for line in _unit_text().splitlines() if line.startswith("After="))
    assert "systemd-resolved.service" in after
    assert "network-online.target" in after
    # The installer creates the accounts now; no cloud-init ordering is needed.
    assert "cloud-init" not in _unit_text()


def test_wallpaper_script_applies_once_per_account_and_keeps_later_choices():
    import os
    import subprocess

    script = Path(__file__).resolve().parents[1] / "config" / "bin" / "family-linux-set-wallpaper"
    text = script.read_text()
    assert os.access(script, os.X_OK)
    assert "plasma-apply-wallpaperimage" in text
    assert 'MARKER="$STATE/wallpaper-set"' in text and '[ -e "$MARKER" ] && exit 0' in text
    assert subprocess.run(["sh", "-n", str(script)], capture_output=True).returncode == 0


def test_wallpaper_autostart_runs_the_script_at_login():
    desktop = Path(__file__).resolve().parents[1] / "config" / "xdg" / "autostart" / "family-linux-wallpaper.desktop"
    text = desktop.read_text()
    assert "Exec=/usr/libexec/family-linux/family-linux-set-wallpaper" in text


def test_child_rules_load_at_every_boot_without_the_gateway():
    # nftables rules do not survive a reboot; found when a VirtualBox VM rebooted with no child rules.
    # They were loaded by the gateway's ExecStartPre, so a gateway that failed to start left no
    # rules at all (children unfiltered). They now have their own early unit.
    from family_linux.security.web_gateway import NFT_RULES_PATH, render_rules_service, render_service
    rules = render_rules_service()
    assert f"ExecStart=/usr/sbin/nft -f {NFT_RULES_PATH}" in rules
    assert "Before=network-pre.target family-dnsd.service" in rules
    assert "WantedBy=sysinit.target" in rules
    gateway = render_service("/usr/bin/python3")
    assert "ExecStartPre" not in gateway
    assert "Wants=family-web-rules.service" in gateway


def test_firstboot_runs_before_the_sign_in_screen():
    assert "Before=display-manager.service" in _unit_text()


def test_installer_creates_children_locked():
    from family_linux.provisioner.preseed import DebianPreseedGenerator
    script = DebianPreseedGenerator(_policy()).generate_late_script()
    assert script.index("useradd") < script.index("in-target usermod -L kid ")


def test_children_are_unlocked_only_after_every_layer_applied():
    from family_linux.security.adapter import SystemAdapter
    from family_linux.provisioner.system import SystemProvisioner

    adapter = SystemAdapter(dry_run=True)
    SystemProvisioner(adapter=adapter).apply_policy(_policy())
    cmds = adapter.executed_commands
    unlock = cmds.index(["usermod", "-U", "kid"])
    # The new account is kept locked after its password is set, and unlocked after the web filter
    # and the screen time service are in place.
    assert ["usermod", "-L", "kid"] in cmds[:unlock]
    assert unlock > cmds.index(["systemctl", "enable", "--now", "family-dnsd"])
    assert unlock > cmds.index(["systemctl", "enable", "--now", "family-policyd"])
    assert cmds.count(["usermod", "-U", "kid"]) == 1


def test_a_failed_apply_leaves_a_new_child_locked(monkeypatch):
    import pytest
    from family_linux.security.adapter import SystemAdapter
    from family_linux.provisioner.system import ProvisioningError, SystemProvisioner

    adapter = SystemAdapter(dry_run=True)
    provisioner = SystemProvisioner(adapter=adapter)
    monkeypatch.setattr(provisioner.web_gateway, "apply", lambda policy: (_ for _ in ()).throw(RuntimeError("nft broke")))
    with pytest.raises(ProvisioningError):
        provisioner.apply_policy(_policy())
    assert ["usermod", "-U", "kid"] not in adapter.executed_commands


def test_firstboot_reports_installer_steps_that_failed(tmp_path, capsys):
    from family_linux.config import PolicyConfigManager

    policy_path = tmp_path / "policy.yaml"
    PolicyConfigManager(policy_path).save_policy(_policy(), reason="test")
    failures = tmp_path / "install-failures"
    failures.write_text("in-target ufw --force enable\n")

    assert firstboot.run(policy_path=policy_path, marker=tmp_path / "done", failures_path=failures) == 0
    assert "installer step failed: in-target ufw --force enable" in capsys.readouterr().out
    assert firstboot.installer_failures(tmp_path / "missing") == []


def test_appliance_first_boot_powers_off_once_then_boots_normally(tmp_path):
    from family_linux.config import PolicyConfigManager

    policy_path = tmp_path / "policy.yaml"
    PolicyConfigManager(policy_path).save_policy(_policy(), reason="test")
    flag = tmp_path / "poweroff-after-firstboot"
    flag.write_text("")
    calls = []

    assert firstboot.run(policy_path=policy_path, marker=tmp_path / "done", failures_path=tmp_path / "none",
                         poweroff_flag=flag, power_off=lambda: calls.append("off")) == 0
    assert calls == ["off"] and not flag.exists()


def test_ordinary_first_boot_does_not_power_off(tmp_path):
    from family_linux.config import PolicyConfigManager

    policy_path = tmp_path / "policy.yaml"
    PolicyConfigManager(policy_path).save_policy(_policy(), reason="test")
    calls = []
    firstboot.run(policy_path=policy_path, marker=tmp_path / "done", failures_path=tmp_path / "none",
                  poweroff_flag=tmp_path / "absent", power_off=lambda: calls.append("off"))
    assert calls == []


def test_wallpaper_script_also_sets_the_lock_screen():
    script = (Path(__file__).resolve().parents[1] / "config" / "bin" / "family-linux-set-wallpaper").read_text()
    assert "kscreenlockerrc" in script and "--key Image" in script


def test_appliance_drops_the_build_serial_console_from_the_kernel_line():
    debian = 'GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT="quiet"\nGRUB_CMDLINE_LINUX="console=ttyAMA0"\n'
    out = firstboot.without_serial_console(debian)
    assert 'GRUB_CMDLINE_LINUX=""' in out and 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"' in out
    assert "console=ttyS0" not in firstboot.without_serial_console('GRUB_CMDLINE_LINUX="splash console=ttyS0"\n')
    assert firstboot.without_serial_console(out) == out


def test_apply_removes_the_installer_script_left_in_opt_by_older_isos():
    from family_linux.security.adapter import SystemAdapter
    from family_linux.provisioner.system import SystemProvisioner

    adapter = SystemAdapter(dry_run=True)
    SystemProvisioner(adapter=adapter).apply_policy(_policy())
    assert ["rm", "-f", "/opt/family-linux/late-command.sh", "/opt/family-linux/policy.yaml"] in adapter.executed_commands


def test_every_unit_in_config_is_installed_by_the_iso():
    # family-policyd.service sat in config/systemd with nothing installing it, so screen time was
    # never enforced on an installed system. Each file there must be copied by the ISO build and
    # installed by the late command; units written by the apply live in Python, not here.
    root = Path(__file__).resolve().parents[1]
    build = (root / "scripts" / "build-debian-iso.sh").read_text()
    from family_linux.provisioner.preseed import DebianPreseedGenerator
    late = DebianPreseedGenerator(_policy()).generate_late_script()
    for unit in sorted((root / "config" / "systemd").glob("*.service")):
        assert f"config/systemd/{unit.name}" in build, f"{unit.name} is not copied into the ISO"
        assert f"$T/etc/systemd/system/{unit.name}" in late, f"{unit.name} is not installed by the late command"


def test_every_service_the_apply_writes_is_enabled():
    from family_linux.security.adapter import SystemAdapter
    from family_linux.provisioner.system import SystemProvisioner

    adapter = SystemAdapter(dry_run=True)
    SystemProvisioner(adapter=adapter).apply_policy(_policy())
    written = {Path(p).name for p in adapter.simulated_files if p.startswith("/etc/systemd/system/")}
    enabled = set()
    for c in adapter.executed_commands:
        if c[:2] == ["systemctl", "enable"]:
            enabled.add(c[-1] if "." in c[-1] else c[-1] + ".service")
    # A .service started by a .path unit needs only the .path enabled
    started_by_path = {name.replace(".path", ".service") for name in enabled if name.endswith(".path")}
    assert written, "the apply wrote no units"
    for unit in sorted(written):
        assert unit in enabled or unit in started_by_path, f"{unit} is written but never enabled"
