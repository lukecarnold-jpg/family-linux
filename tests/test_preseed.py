"""Debian preseed and late command: what the unattended install builds, and that the shell is valid."""

import shlex
import subprocess

from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount
from family_linux.provisioner.preseed import ISO_PAYLOAD_DIR, PACKAGES, DebianPreseedGenerator
from family_linux.provisioner.sha512crypt import sha512_crypt

PARENT_PASS = "Correct-Horse-42-Battery"
CHILD_PASS = "kidpass123"


def _policy(child_name="Kid"):
    return FamilyPolicy(
        parent=ParentAccount("parent", "Family Administrator", password=PARENT_PASS),
        children=[ChildAccount.create("kid", child_name, "pre_teen", password=CHILD_PASS)],
    )


def _preseed(policy=None, **kwargs):
    return DebianPreseedGenerator(policy or _policy()).generate_preseed(locale="en_US.UTF-8", keyboard_layout="us", **kwargs)


def _late(policy=None):
    return DebianPreseedGenerator(policy or _policy()).generate_late_script()


def _value(text, key):
    """The value of a debconf line: 'd-i passwd/username string parent' gives 'parent'."""
    line = next(line for line in text.splitlines() if line.startswith(f"d-i {key} "))
    return line.split(" ", 3)[3]


def test_preseed_installs_kde_plasma_and_the_debian_repositories():
    text = _preseed()
    assert "tasksel tasksel/first multiselect kde-desktop" in text
    assert "d-i apt-setup/contrib boolean true" in text
    assert "d-i apt-setup/non-free-firmware boolean true" in text
    assert "d-i mirror/http/hostname string deb.debian.org" in text


def test_preseed_has_no_root_login_and_makes_the_parent_an_administrator():
    text = _preseed()
    assert "d-i passwd/root-login boolean false" in text
    assert _value(text, "passwd/username") == "parent"
    assert "d-i passwd/user-default-groups string sudo adm" in text


def test_preseed_contains_only_password_hashes():
    text = _preseed()
    assert PARENT_PASS not in text
    assert CHILD_PASS not in _preseed() and CHILD_PASS not in _late()
    stored = _value(text, "passwd/user-password-crypted")
    assert stored.startswith("$6$") and stored == sha512_crypt(PARENT_PASS, stored.split("$")[2])


def test_preseed_packages_cover_the_baseline_the_children_need():
    text = _preseed()
    package_line = next(line for line in text.splitlines() if line.startswith("d-i pkgsel/include string "))
    listed = package_line.split(" string ", 1)[1].split()
    assert listed == PACKAGES
    for name in ("ufw", "apparmor", "unattended-upgrades", "nftables", "systemd-resolved", "libpam-pwquality",
                 "network-manager", "firefox-esr", "python3-pyqt6", "plasma-discover", "packagekit"):
        assert name in listed, name
    assert "ubuntu-desktop-minimal" not in listed and "gnome-software" not in listed


def test_preseed_uses_the_chosen_disk_or_the_first_disk_the_installer_finds():
    assert "d-i partman-auto/disk string /dev/nvme0n1" in _preseed(target_disk="/dev/nvme0n1")
    assert "list-devices disk | head -n1" in _preseed()


def test_preseed_boots_uefi_with_the_removable_media_path():
    text = _preseed()
    assert "d-i grub-installer/force-efi-extra-removable boolean true" in text
    assert "d-i grub-installer/only_debian boolean true" in text


def test_preseed_runs_the_late_command_from_the_iso():
    text = _preseed()
    assert f"d-i preseed/late_command string sh {ISO_PAYLOAD_DIR}/late-command.sh" in text


def test_preseed_has_no_ubuntu_or_subiquity_leftovers():
    text = _preseed() + _late()
    for word in ("ubuntu", "Ubuntu", "subiquity", "curtin", "snap", "netplan", "gnome"):
        assert word not in text, word


def test_late_script_creates_groups_sudoers_and_the_children():
    script = _late()
    assert "in-target groupadd -f family-parent" in script
    assert "in-target usermod -aG sudo,adm,family-parent parent" in script
    assert "family-linux-admin" in script and "!ALL" in script
    child_line = next(line for line in script.splitlines() if "useradd" in line and "kid" in line)
    assert "-s /usr/sbin/nologin" in child_line and "-g family-children" in child_line
    assert "-p '$6$" in child_line  # the hash, quoted: "$" must not expand in the installer shell


def test_late_script_copies_the_payload_and_enables_first_boot():
    script = _late()
    assert f"cp -a $PAYLOAD $T/opt/" in script
    assert "install -m 644 $PAYLOAD/policy.yaml $T/etc/family-linux/policy.yaml" in script
    assert "in-target systemctl enable family-linux-firstboot.service" in script
    assert "/usr/lib/python3/dist-packages/family-linux.pth" in script
    assert "$T/usr/local/sbin/family-ctl" in script


def test_late_script_routes_dns_through_systemd_resolved_and_networkmanager():
    script = _late()
    assert "dns=systemd-resolved" in script
    assert "managed=true" in script
    assert "in-target systemctl enable systemd-resolved.service" in script
    assert "in-target ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf" in script


def test_late_script_sets_the_wallpaper_once_per_account():
    script = _late()
    assert "$T/usr/share/backgrounds/family-linux" in script
    assert "$T/usr/libexec/family-linux/family-linux-set-wallpaper" in script
    assert "$T/etc/xdg/autostart/family-linux-wallpaper.desktop" in script


def test_late_script_is_valid_shell_even_with_quotes_in_a_child_name(tmp_path):
    policy = _policy(child_name="Mo'Hamed \"Kid\" $HOME")
    script = tmp_path / "late-command.sh"
    script.write_text(_late(policy), encoding="utf-8")
    result = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert shlex.quote("Mo'Hamed \"Kid\" $HOME") in _late(policy)


def test_late_script_quotes_every_child_value_from_the_policy():
    policy = _policy(child_name="Kid; rm -rf /")
    assert f"-c {shlex.quote('Kid; rm -rf /')} " in _late(policy)
