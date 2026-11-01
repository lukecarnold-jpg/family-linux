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
NSSWITCH_PATH = Path("/etc/nsswitch.conf")
NSS_RESOLVE_PACKAGE = "libnss-resolve"
NSS_RESOLVE_PIN_PATH = Path("/etc/apt/preferences.d/family-linux-no-nss-resolve")
HOSTS_BLOCK_HEADER = "# --- Family Linux Managed Blocklist ---"


def hosts_without_nss_resolve(nsswitch: str) -> str:
    """Removes the `resolve` source (and its [action]) from the hosts line of nsswitch.conf.

    With `resolve`, lookups go to systemd-resolved over D-Bus instead of DNS port 53, so a child's
    lookups never reach the per-child gateway, and the gateway then refuses every connection the
    child makes (seen on Debian 13, where libnss-resolve comes with systemd-resolved).
    """
    lines = []
    for line in nsswitch.splitlines():
        if line.startswith("hosts:"):
            key, _, sources = line.partition(":")
            words = sources.split()
            kept = []
            skip_action = False
            for word in words:
                if word == "resolve":
                    skip_action = True
                    continue
                if skip_action and word.startswith("["):
                    skip_action = False
                    continue
                skip_action = False
                kept.append(word)
            line = f"{key}:{' ' * 10}{' '.join(kept)}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def lookups_use_dns(nsswitch: str) -> bool:
    """True when the hosts line does not send lookups to systemd-resolved over D-Bus."""
    hosts = next((line for line in nsswitch.splitlines() if line.startswith("hosts:")), "")
    return "resolve" not in hosts.split()


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

    def route_lookups_through_dns(self, nsswitch_path: Path = NSSWITCH_PATH) -> List[str]:
        """Makes every name lookup a DNS query, so children's lookups reach their gateway.

        libnss-resolve is removed (its removal takes `resolve` out of nsswitch.conf) and pinned so
        apt does not bring it back; any `resolve` left on the hosts line is removed. Returns warnings.
        """
        warnings: List[str] = []
        if self.adapter.run_command(["dpkg", "-s", NSS_RESOLVE_PACKAGE]).returncode == 0:
            if self.adapter.run_command(["apt-get", "purge", "-y", "-q", NSS_RESOLVE_PACKAGE]).returncode != 0:
                warnings.append(f"Could not remove {NSS_RESOLVE_PACKAGE}; children's lookups may bypass their web filter")
        pin = (
            "# Family Linux (managed; do not edit). nss-resolve sends lookups around the children's web filter.\n"
            f"Package: {NSS_RESOLVE_PACKAGE}\nPin: release *\nPin-Priority: -1\n"
        )
        self.adapter.write_system_file(NSS_RESOLVE_PIN_PATH, pin, mode=0o644)
        if nsswitch_path.exists() and not self.adapter.dry_run:
            current = nsswitch_path.read_text(encoding="utf-8")
            if not lookups_use_dns(current):
                self.adapter.write_system_file(nsswitch_path, hosts_without_nss_resolve(current), mode=0o644)
        return warnings

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
