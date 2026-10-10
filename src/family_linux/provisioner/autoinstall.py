"""Ubuntu Subiquity autoinstall generator for Family Linux.

Generates Ubuntu LTS (22.04 / 24.04) autoinstall user-data configuration
to create unattended bootable ISOs or automated installations aligned
with Family Linux security baseline.
"""

from __future__ import annotations

try:
    import crypt
except ImportError:
    crypt = None  # Removed in Python 3.13+

import hashlib
import secrets
from typing import Dict, Any, Optional
import yaml

from family_linux.models import FamilyPolicy, ParentAccount, ChildAccount


class SubiquityAutoinstallGenerator:
    """Generates Ubuntu autoinstall cloud-config YAML from FamilyPolicy."""

    def __init__(self, policy: FamilyPolicy):
        self.policy = policy

    def _hash_password(self, plaintext: Optional[str]) -> str:
        if not plaintext:
            return "*"
        salt = secrets.token_hex(8)
        if crypt is not None:
            try:
                return crypt.crypt(plaintext, f"$6${salt}$")
            except (AttributeError, ValueError):
                pass

        # Standard SHA512 crypt hash simulation for Python 3.13+
        h = hashlib.sha512(f"{salt}{plaintext}".encode("utf-8")).hexdigest()
        return f"$6${salt}${h}"

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

        for child in self.policy.children:
            late_commands.append(f"curtin in-target -- usermod -g family-children -G '' {child.username}")
            late_commands.append(f"curtin in-target -- chmod 700 /home/{child.username}")

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
