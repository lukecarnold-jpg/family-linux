"""Installs family-policyd.service, which enforces screen time, bedtimes and disabled accounts.

The unit is written by the apply (like family-dnsd.service), so the first boot of an installed
system, and every later full apply, install and start it. The daemon reads the policy every cycle,
so a change of limits needs no restart.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

from family_linux.security.adapter import SystemAdapter

SERVICE_NAME = "family-policyd"
SERVICE_PATH = Path("/etc/systemd/system/family-policyd.service")
POLL_SECONDS = 60


def render_service(python: str = sys.executable) -> str:
    """Unit that runs the daemon with the interpreter that has family_linux installed."""
    return (
        "[Unit]\n"
        "Description=Family Linux screen time, bedtimes and disabled accounts\n"
        "After=systemd-logind.service\n"
        "Wants=systemd-logind.service\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={python} -m family_linux.screentime.daemon --interval {POLL_SECONDS}\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "User=root\n"
        "Group=root\n"
        # It only writes its usage file and the audit log; everything else is read-only.
        "ProtectSystem=full\n"
        "ProtectHome=read-only\n"
        "ReadOnlyPaths=-/etc/family-linux\n"  # "-": a missing folder does not stop the start
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class ScreenTimeService:
    """Writes, enables and (re)starts the screen time service."""

    def __init__(self, adapter: SystemAdapter):
        self.adapter = adapter

    def apply(self) -> List[str]:
        """Returns warnings; never raises for a missing systemd."""
        self.adapter.write_system_file(SERVICE_PATH, render_service(), mode=0o644)
        self.adapter.run_command(["systemctl", "daemon-reload"])
        enabled = self.adapter.run_command(["systemctl", "enable", "--now", SERVICE_NAME])
        if enabled.returncode != 0:
            return [f"{SERVICE_NAME} could not start (systemd not available); screen time and bedtimes not enforced"]
        # Picks up a new version of the code after an update.
        self.adapter.run_command(["systemctl", "restart", SERVICE_NAME])
        return []
