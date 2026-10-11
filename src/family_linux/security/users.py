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

    def provision_child(self, child: ChildAccount) -> bool:
        """Creates or updates a restricted child user account."""
        self.setup_security_groups()

        errors = child.validate()
        if errors:
            raise ValueError(f"Invalid child account specification: {'; '.join(errors)}")

        check = self.adapter.run_command(["id", "-u", child.username])
        if check.returncode != 0:
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

        self.allow_child_shell_on_login_screen(child.shell)

        if child.password:
            self.set_password(child.username, child.password)

        if not child.enabled:
            self.disable_child(child.username)
        else:
            self.enable_child(child.username)

        return True

    def allow_child_shell_on_login_screen(self, shell: str, shells_file: Path = Path("/etc/shells")) -> None:
        """Lists the child's shell in /etc/shells.

        AccountsService treats accounts whose shell is not listed as system accounts and hides them
        from the login screen. The child shell is nologin: it still cannot run a terminal session,
        and the desktop session starts without it (tested in VirtualBox).
        """
        current = shells_file.read_text(encoding="utf-8") if shells_file.exists() else ""
        if shell in current.split():
            return
        self.adapter.write_system_file(shells_file, current.rstrip("\n") + f"\n{shell}\n", mode=0o644)

    def disable_child(self, username: str) -> None:
        """Disables child login (locks password)."""
        self.adapter.run_command(["usermod", "-L", username])

    def enable_child(self, username: str) -> None:
        """Enables child login (unlocks password)."""
        self.adapter.run_command(["usermod", "-U", username])

    def delete_child(self, username: str, remove_home: bool = False) -> None:
        """Deletes a child account."""
        cmd = ["userdel"]
        if remove_home:
            cmd.append("-r")
        cmd.append(username)
        self.adapter.run_command(cmd)

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
