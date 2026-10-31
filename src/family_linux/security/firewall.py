"""Firewall configuration and management for Family Linux.

Configures UFW (Uncomplicated Firewall) with conservative defaults:
- Deny all incoming connections
- Allow standard outbound connections
- Block legacy insecure ports (Telnet, SMB, NetBIOS)
"""

from __future__ import annotations

from typing import List, Optional
from family_linux.models import SecurityPolicy
from family_linux.security.adapter import SystemAdapter


class FirewallManager:
    """Configures and validates UFW firewall rules on Debian."""

    def __init__(self, adapter: Optional[SystemAdapter] = None):
        self.adapter = adapter or SystemAdapter()

    def configure_baseline(self, policy: Optional[SecurityPolicy] = None) -> List[str]:
        """Applies conservative firewall rules."""
        sec = policy or SecurityPolicy()
        actions_taken = []

        # 1. Reset or set default policies
        inc_policy = "deny" if "deny" in sec.firewall_default.lower() else "allow"
        out_policy = "allow" if "allow" in sec.firewall_outgoing.lower() else "deny"

        self.adapter.run_command(["ufw", "--force", "default", inc_policy, "incoming"])
        actions_taken.append(f"Default incoming: {inc_policy}")

        self.adapter.run_command(["ufw", "--force", "default", out_policy, "outgoing"])
        actions_taken.append(f"Default outgoing: {out_policy}")

        # 2. Block legacy insecure ports explicitly
        for port in sec.firewall_blocked_ports:
            self.adapter.run_command(["ufw", "deny", "out", str(port)])
            actions_taken.append(f"Blocked outbound port {port}")

        # 3. Allow loopback traffic
        self.adapter.run_command(["ufw", "allow", "in", "on", "lo"])
        self.adapter.run_command(["ufw", "allow", "out", "on", "lo"])

        # 4. Enable firewall
        self.adapter.run_command(["ufw", "--force", "enable"])
        actions_taken.append("UFW enabled")

        return actions_taken

    def get_status(self) -> str:
        """Returns the current UFW status."""
        res = self.adapter.run_command(["ufw", "status", "verbose"])
        return res.stdout
