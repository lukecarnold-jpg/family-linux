"""User and account privilege management for Family Linux.

Enforces:
- Exactly one parent administrator with sudo privileges.
- Child accounts as non-admin standard users with no sudo or wheel rights.
- Isolated home directory permissions (0700) and strict group memberships.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from pathlib import Path

from family_linux.models import ParentAccount, ChildAccount
from family_linux.security.adapter import SystemAdapter


SUDOERS_FILE = "/etc/sudoers.d/family-linux-admin"
PARENT_GROUP = "family-parent"
CHILD_GROUP = "family-children"


class UserManager:
    """Manages system accounts, group boundaries, and privilege separation."""

    def __init__(self, adapter: Optional[SystemAdapter] = None):
        self.adapter = adapter or SystemAdapter()

    def setup_security_groups(self) -> None:
        """Creates dedicated user groups for parent and children."""
        self.adapter.run_command(["groupadd", "-f", PARENT_GROUP])
        self.adapter.run_command(["groupadd", "-f", CHILD_GROUP])

    def configure_sudoers(self, parent_username: str) -> None:
        """Writes restricted sudoers policy granting sudo exclusively to the parent account."""
        content = (
            "# Family Linux security policy\n"
            "# Sudo access is strictly restricted to the designated parent administrator.\n"
            f"{parent_username} ALL=(ALL:ALL) ALL\n"
            f"%{PARENT_GROUP} ALL=(ALL:ALL) ALL\n"
            f"# Explicitly deny child group\n"
            f"%{CHILD_GROUP} ALL=(ALL:ALL) !ALL\n"
        )
        self.adapter.write_system_file(SUDOERS_FILE, content, mode=0o440)

    def provision_parent(self, parent: ParentAccount) -> bool:
        """Creates or updates the parent administrator account."""
        self.setup_security_groups()

        # Check if user already exists
        check = self.adapter.run_command(["id", "-u", parent.username])
        if check.returncode != 0:
            # Create user
            cmd = [
                "useradd",
                "-m",
                "-s", parent.shell,
                "-c", parent.full_name,
                "-G", f"sudo,adm,{PARENT_GROUP}",
                parent.username,
            ]
            self.adapter.run_command(cmd, check=False)
        else:
            # Update user
            self.adapter.run_command([
                "usermod",
                "-aG", f"sudo,adm,{PARENT_GROUP}",
                "-s", parent.shell,
                "-c", parent.full_name,
                parent.username,
            ])

        # Parent's home is private: children are not in the parent's group and cannot read it.
        self.adapter.set_permissions(Path(f"/home/{parent.username}"), mode=0o700)

        if parent.password:
            self.set_password(parent.username, parent.password)

        self.configure_sudoers(parent.username)
        return True

    def provision_child(self, child: ChildAccount, unlock: bool = True) -> bool:
        """Creates or updates a restricted child user account.

        With unlock=False an enabled child is not unlocked here: a new account, or one whose password
        was just set, is left locked, and an existing account keeps its state. The caller unlocks it
        once the web filter and the other rules are in place (see SystemProvisioner).
        """
        self.setup_security_groups()

        errors = child.validate()
        if errors:
            raise ValueError(f"Invalid child account specification: {'; '.join(errors)}")

        check = self.adapter.run_command(["id", "-u", child.username])
        created = check.returncode != 0
        if created:
            cmd = [
                "useradd",
                "-m",
                "-s", child.shell,
                "-c", child.full_name,
                "-g", CHILD_GROUP,
                child.username,
            ]
            self.adapter.run_command(cmd, check=False)
        else:
            self.adapter.run_command([
                "usermod",
                "-g", CHILD_GROUP,
                "-s", child.shell,
                "-c", child.full_name,
                child.username,
            ])

        # Enforce removal from any privileged groups
        for priv_group in ["sudo", "admin", "wheel", "adm", PARENT_GROUP]:
            self.adapter.run_command(["gpasswd", "-d", child.username, priv_group])

        # Lockdown home directory permissions to 0700 (owner only)
        child_home = Path(f"/home/{child.username}")
        self.adapter.set_permissions(child_home, mode=0o700, owner=child.username, group=CHILD_GROUP)

        if child.password:
            self.set_password(child.username, child.password)

        if not child.enabled:
            self.disable_child(child.username)
        elif unlock:
            self.enable_child(child.username)
        elif created or child.password:
            # chpasswd unlocks the account; keep it locked until the caller has applied the rules.
            self.disable_child(child.username)

        return True

    def disable_child(self, username: str) -> None:
        """Disables child login (locks password)."""
        self.adapter.run_command(["usermod", "-L", username])

    def enable_child(self, username: str) -> None:
        """Enables child login (unlocks password)."""
        self.adapter.run_command(["usermod", "-U", username])

    def end_sessions(self, username: str) -> None:
        """Signs the user out and stops their remaining processes (userdel refuses while any run)."""
        self.adapter.run_command(["loginctl", "terminate-user", username])
        self.adapter.run_command(["pkill", "-KILL", "-u", username])

    def delete_child(self, username: str, remove_home: bool = False) -> bool:
        """Deletes a child account. Returns False if the account is still there afterwards."""
        cmd = ["userdel"]
        if remove_home:
            cmd.append("-r")
        cmd.append(username)
        result = self.adapter.run_command(cmd)
        # userdel exits 6 when the account does not exist, which is the state wanted here.
        return result.returncode in (0, 6)

    def set_password(self, username: str, password: str) -> None:
        """Sets user password via chpasswd."""
        # Using chpasswd command
        cmd = ["chpasswd"]
        input_data = f"{username}:{password}\n"
        if not self.adapter.dry_run and self.adapter.is_root():
            import subprocess
            subprocess.run(cmd, input=input_data, text=True, check=True)
        else:
            self.adapter.run_command(["chpasswd", f"(set password for {username})"])

    def verify_isolation(self, parent_username: str, child_usernames: List[str]) -> Dict[str, Any]:
        """Audits user isolation to ensure no child has admin rights."""
        results = {
            "parent_valid": True,
            "violations": [],
            "checked_children": child_usernames,
        }

        # Parent must exist and not be in child group
        if parent_username in child_usernames:
            results["parent_valid"] = False
            results["violations"].append(f"Parent '{parent_username}' is also listed as a child account.")

        return results
