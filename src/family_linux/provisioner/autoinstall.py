"""Ubuntu Subiquity autoinstall generator for Family Linux.

Generates Ubuntu LTS (22.04 / 24.04) autoinstall user-data configuration
to create unattended bootable ISOs or automated installations aligned
with Family Linux security baseline.
"""

from __future__ import annotations

import secrets
from typing import Dict, Any, Optional
import yaml

from family_linux.models import FamilyPolicy, ParentAccount, ChildAccount
from family_linux.provisioner.sha512crypt import sha512_crypt


# Paths on the ISO and on the installed system. The build script copies the payload to ISO_PAYLOAD_DIR.
ISO_PAYLOAD_DIR = "/cdrom/family-linux"
FIRSTBOOT_UNIT = "family-linux-firstboot.service"


class SubiquityAutoinstallGenerator:
    """Generates Ubuntu autoinstall cloud-config YAML from FamilyPolicy."""

    def __init__(self, policy: FamilyPolicy):
        self.policy = policy

    def _hash_password(self, plaintext: Optional[str]) -> str:
        """Returns a SHA-512 crypt hash for /etc/shadow. Locked ("*") when there is no password."""
        if not plaintext:
            return "*"
        return sha512_crypt(plaintext, secrets.token_hex(8))

    def generate_user_data(
        self,
        hostname: str = "family-linux",
        locale: str = "en_US.UTF-8",
        keyboard_layout: str = "us",
        target_disk: Optional[str] = None,
    ) -> str:
        """Constructs the Subiquity autoinstall user-data YAML."""
        parent = self.policy.parent

        # Child users definition for cloud-init
        cloud_users = []
        for child in self.policy.children:
            cloud_users.append({
                "name": child.username,
                "gecos": child.full_name,
                "groups": ["family-children"],
                "shell": child.shell,
                "lock_passwd": child.password is None,
                "passwd": self._hash_password(child.password) if child.password else None,
            })

        # Base packages to install
        packages = [
            "ufw",
            "apparmor",
            "apparmor-utils",
            "unattended-upgrades",
            "firefox",
            "tuxpaint",
            "libreoffice",
            "vlc",
            "libnotify-bin",
            "python3",
            "python3-yaml",
            # The live-server image has no desktop. Child accounts need a session and a menu.
            "ubuntu-desktop-minimal",
            # Family Controls, the parent's GNOME app (GTK 4 and libadwaita).
            "python3-gi",
            "gir1.2-gtk-4.0",
            "gir1.2-adw-1",
        ]

        # Late commands to configure family linux hardening
        late_commands = [
            # 1. Create family groups
            "curtin in-target -- groupadd -f family-parent",
            "curtin in-target -- groupadd -f family-children",
            f"curtin in-target -- usermod -aG family-parent {parent.username}",
            # 2. Strict sudoers
            f'curtin in-target -- bash -c "echo \'{parent.username} ALL=(ALL:ALL) ALL\' > /etc/sudoers.d/family-linux-admin"',
            'curtin in-target -- bash -c "echo \'%family-children ALL=(ALL:ALL) !ALL\' >> /etc/sudoers.d/family-linux-admin"',
            "curtin in-target -- chmod 0440 /etc/sudoers.d/family-linux-admin",
            # 3. UFW default deny incoming
            "curtin in-target -- ufw --force default deny incoming",
            "curtin in-target -- ufw --force default allow outgoing",
            "curtin in-target -- ufw --force enable",
            # 4. Lock down home directories
            "curtin in-target -- chmod 700 /home/* || true",
        ]

        # 5. Family Linux itself. The ISO carries the source, the policy (no passwords) and the
        #    first-boot unit; the full apply runs once on first boot, when systemd and the network are up.
        late_commands += [
            "mkdir -p /target/opt /target/etc/family-linux /target/etc/systemd/system",
            f"cp -a {ISO_PAYLOAD_DIR} /target/opt/",
            f"cp {ISO_PAYLOAD_DIR}/policy.yaml /target/etc/family-linux/policy.yaml",
            f"cp {ISO_PAYLOAD_DIR}/{FIRSTBOOT_UNIT} /target/etc/systemd/system/",
            f"curtin in-target -- systemctl enable {FIRSTBOOT_UNIT}",
            # Every service and command imports family_linux from /opt, not only the first-boot unit.
            "sh -c 'echo /opt/family-linux/src > /target/usr/lib/python3/dist-packages/family-linux.pth'",
            f"install -m 755 {ISO_PAYLOAD_DIR}/family-ctl /target/usr/local/sbin/family-ctl",
            # Family Controls app: launcher, menu entry, and the polkit action it runs family-ctl under
            f"install -m 755 {ISO_PAYLOAD_DIR}/family-linux-parent /target/usr/local/bin/family-linux-parent",
            f"install -m 644 {ISO_PAYLOAD_DIR}/org.familylinux.Parent.desktop /target/usr/share/applications/org.familylinux.Parent.desktop",
            f"install -m 644 {ISO_PAYLOAD_DIR}/org.familylinux.manage.policy /target/usr/share/polkit-1/actions/org.familylinux.manage.policy",
        ]

        # The installed desktop uses NetworkManager, as Ubuntu Desktop does. Not set in the installer's
        # own network config: the live-server installer has no NetworkManager and its network step
        # fails. With networkd left on the installed system, every boot waited about 2 minutes.
        late_commands += [
            "sh -c 'rm -f /target/etc/netplan/*.yaml && printf \"network:\\n  version: 2\\n  renderer: NetworkManager\\n\" "
            "> /target/etc/netplan/01-network-manager-all.yaml && chmod 600 /target/etc/netplan/01-network-manager-all.yaml'",
            "curtin in-target -- systemctl disable systemd-networkd-wait-online.service",
        ]

        # Child accounts are created by cloud-init on first boot ("user-data" below), so they do not
        # exist yet. Their primary group and home permissions are set by the first-boot apply.

        # 6. Removable-media boot path, so the disk still boots when moved to a VM with empty
        #    firmware boot entries (for example after importing an exported appliance).
        late_commands.append(
            "curtin in-target -- sh -c 'cd /boot/efi/EFI/ubuntu && mkdir -p ../BOOT && "
            "if [ -f shimaa64.efi ]; then cp shimaa64.efi ../BOOT/BOOTAA64.EFI; fi && "
            "if [ -f shimx64.efi ]; then cp shimx64.efi ../BOOT/BOOTX64.EFI; fi && "
            "cp grub*.efi mm*.efi grub.cfg ../BOOT/ 2>/dev/null; true'"
        )

        # Without an explicit target, Subiquity's "direct" layout picks the first disk.
        layout: Dict[str, Any] = {"name": "direct"}
        if target_disk:
            layout["match"] = {"path": target_disk}

        autoinstall_data: Dict[str, Any] = {
            "autoinstall": {
                "version": 1,
                "interactive-sections": [],
                "locale": locale,
                "keyboard": {"layout": keyboard_layout},
                # Without this Ubuntu installs on UTC, and curfews would fire at the wrong local time.
                # "geoip" asks the installer to detect it from the network.
                "timezone": self.policy.timezone or "geoip",
                "network": {
                    "network": {
                        "version": 2,
                        "ethernets": {
                            "all-en": {"match": {"name": "en*"}, "dhcp4": True},
                            "all-wl": {"match": {"name": "wl*"}, "dhcp4": True},
                        },
                    }
                },
                "identity": {
                    "hostname": hostname,
                    "username": parent.username,
                    "realname": parent.full_name,
                    "password": self._hash_password(parent.password),
                },
                "storage": {
                    "layout": layout,
                },
                "packages": packages,
                "user-data": {
                    "users": cloud_users,
                },
                "late-commands": late_commands,
            }
        }

        header = "#cloud-config\n# Family Linux Ubuntu LTS Autoinstall Configuration\n"
        return header + yaml.dump(autoinstall_data, default_flow_style=False, sort_keys=False)
