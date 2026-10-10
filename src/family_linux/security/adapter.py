"""System execution adapter for Family Linux.

Provides a safe abstraction over low-level Linux administration commands
(useradd, usermod, ufw, systemctl, file permissions) with full support
for dry-run mode, mock test execution, and Linux live execution.
"""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Dict


@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    simulated: bool = False


class SystemAdapter:
    """Safely runs system commands or records them in simulated/dry-run mode."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run or (platform.system() != "Linux")
        self.executed_commands: List[List[str]] = []
        self.simulated_users: Dict[str, Dict] = {}
        self.simulated_files: Dict[str, str] = {}
        self.simulated_firewall_rules: List[str] = []

    def is_root(self) -> bool:
        if platform.system() != "Linux":
            return False
        return os.geteuid() == 0

    def run_command(self, cmd: List[str], check: bool = False) -> CommandResult:
        """Executes a command or simulates it if in dry-run mode."""
        self.executed_commands.append(cmd)

        if self.dry_run or not self.is_root():
            rc = 0
            # Track user existence in simulation
            if len(cmd) >= 3 and cmd[0] == "id" and cmd[1] == "-u":
                username = cmd[2]
                if username not in self.simulated_users:
                    rc = 1
            elif cmd[0] == "useradd":
                username = cmd[-1]
                self.simulated_users[username] = {"cmd": cmd}
            elif cmd[0] == "userdel":
                username = cmd[-1]
                self.simulated_users.pop(username, None)

            return CommandResult(
                command=cmd,
                returncode=rc,
                stdout=f"[SIMULATED] Executed: {' '.join(cmd)}" if rc == 0 else "",
                stderr="" if rc == 0 else f"id: '{cmd[-1]}': no such user",
                simulated=True,
            )

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=check)
            return CommandResult(
                command=cmd,
                returncode=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                simulated=False,
            )
        except subprocess.CalledProcessError as e:
            if check:
                raise
            return CommandResult(
                command=cmd,
                returncode=e.returncode,
                stdout=e.stdout,
                stderr=e.stderr,
                simulated=False,
            )
        except FileNotFoundError as e:
            return CommandResult(
                command=cmd,
                returncode=127,
                stdout="",
                stderr=str(e),
                simulated=False,
            )

    def write_system_file(self, path: Path | str, content: str, mode: int = 0o644) -> None:
        """Writes a system configuration file atomically or records in simulation."""
        target = Path(path)
        if self.dry_run or not self.is_root():
            self.simulated_files[str(target)] = content
            return

        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, target)
        os.chmod(target, mode)

    def set_permissions(self, path: Path | str, mode: int, owner: Optional[str] = None, group: Optional[str] = None) -> None:
        """Sets file/directory permissions and ownership."""
        target = Path(path)
        if self.dry_run or not self.is_root():
            return

        if target.exists():
            os.chmod(target, mode)
            if owner or group:
                import shutil
                shutil.chown(str(target), user=owner, group=group)
