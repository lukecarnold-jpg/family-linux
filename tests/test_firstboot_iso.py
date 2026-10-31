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


def test_gateway_reloads_the_child_rules_on_every_start():
    # nftables rules do not survive a reboot; found when a VirtualBox VM rebooted with no child rules.
    from family_linux.security.web_gateway import NFT_RULES_PATH, render_service
    unit = render_service("/usr/bin/python3")
    assert f"ExecStartPre=/usr/sbin/nft -f {NFT_RULES_PATH}" in unit
    assert unit.index("ExecStartPre=") < unit.index("ExecStart=/usr/bin/python3")
