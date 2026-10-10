"""DNS filtering and safety configuration for Family Linux.

Configures system-wide family safe DNS using systemd-resolved and
parent-managed domain blocklists/allowlists.
"""

from __future__ import annotations

from typing import List, Optional, Dict
from pathlib import Path

from family_linux.models import DNSProvider, DNS_SERVERS
from family_linux.security.adapter import SystemAdapter

RESOLVED_CONF_DROPIN = Path("/etc/systemd/resolved.conf.d/family-linux-dns.conf")
HOSTS_BLOCK_HEADER = "# --- Family Linux Managed Blocklist ---"


class DNSFilterManager:
    """Manages family-safe DNS resolvers and domain filtering."""

    def __init__(self, adapter: Optional[SystemAdapter] = None):
        self.adapter = adapter or SystemAdapter()

    def configure_provider(self, provider: str = DNSProvider.CLEANBROWSING_FAMILY.value) -> List[str]:
        """Configures systemd-resolved with family-safe DNS servers."""
        servers = DNS_SERVERS.get(provider, DNS_SERVERS[DNSProvider.CLEANBROWSING_FAMILY.value])
        servers_str = " ".join(servers)

        content = (
            "# Family Linux Protected DNS Configuration\n"
            "[Resolve]\n"
            f"DNS={servers_str}\n"
            "FallbackDNS=1.1.1.3 1.0.0.3\n"
            "DNSOverTLS=opportunistic\n"
        )

        self.adapter.write_system_file(RESOLVED_CONF_DROPIN, content, mode=0o644)
        self.adapter.run_command(["systemctl", "restart", "systemd-resolved"])
        return servers

    def update_hosts_blocklist(self, blocked_domains: List[str]) -> List[str]:
        """Appends blocked domains to /etc/hosts resolving to 0.0.0.0.

        /etc/hosts cannot match wildcards, so "*.example" entries are skipped. Returns the skipped entries.
        """
        # Read existing /etc/hosts
        hosts_path = Path("/etc/hosts")
        existing_lines = []

        if hosts_path.exists() and not self.adapter.dry_run:
            try:
                with open(hosts_path, "r", encoding="utf-8") as f:
                    in_blocklist = False
                    for line in f:
                        if HOSTS_BLOCK_HEADER in line:
                            in_blocklist = True
                            continue
                        if in_blocklist and line.startswith("# --- End"):
                            in_blocklist = False
                            continue
                        if not in_blocklist:
                            existing_lines.append(line.rstrip())
            except OSError:
                existing_lines = ["127.0.0.1 localhost"]
        else:
            existing_lines = ["127.0.0.1 localhost", "127.0.1.1 family-linux"]

        new_content = "\n".join(existing_lines) + "\n\n"
        new_content += f"{HOSTS_BLOCK_HEADER}\n"
        skipped: List[str] = []
        for domain in blocked_domains:
            entry = domain.strip()
            if not entry:
                continue
            if entry.startswith("*"):
                skipped.append(entry)
                continue
            new_content += f"0.0.0.0 {entry}\n"
            new_content += f"0.0.0.0 www.{entry}\n"
        new_content += "# --- End Family Linux Managed Blocklist ---\n"

        self.adapter.write_system_file(hosts_path, new_content, mode=0o644)
        return skipped
