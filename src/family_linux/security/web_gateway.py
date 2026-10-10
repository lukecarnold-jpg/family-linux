"""Provisioning for the per-child DNS gateway.

Renders and installs three things:
- /etc/family-linux/dns-gateway.json, read by the gateway service
- an nftables table that redirects each child's DNS to that child's listener and drops DoT
- family-dnsd.service, which runs the gateway as root

The gateway is the enforcement point for per-child web rules. Browser managed policies are
machine-wide, so they cannot express one child's rules and the hosts file is machine-wide too.
"""

from __future__ import annotations

import json
import pwd
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from family_linux.models import DNS_SERVERS, DNSProvider, FamilyPolicy
from family_linux.security.adapter import SystemAdapter

GATEWAY_CONFIG_PATH = Path("/etc/family-linux/dns-gateway.json")
NFT_RULES_PATH = Path("/etc/family-linux/nftables-children.nft")
SERVICE_PATH = Path("/etc/systemd/system/family-dnsd.service")
REQUESTS_PATH = Path("/var/lib/family-linux/web-requests.json")
SERVICE_NAME = "family-dnsd"
NFT_TABLE = "family_linux"
PORT_BASE = 5301
GENERAL_UPSTREAM = "1.1.1.1"  # used only for names the parent explicitly allows
LISTEN_ADDRESS = "127.0.0.1"


def child_ports(policy: FamilyPolicy) -> Dict[str, int]:
    """Stable loopback port per child, in policy order."""
    return {child.username: PORT_BASE + index for index, child in enumerate(policy.children)}


def render_config(policy: FamilyPolicy, provider: str, uids: Optional[Dict[str, int]] = None) -> dict:
    ports = child_ports(policy)
    uids = uids or {}
    family_upstream = DNS_SERVERS.get(provider, DNS_SERVERS[DNSProvider.CLEANBROWSING_FAMILY.value])[0]
    return {
        "listen_address": LISTEN_ADDRESS,
        "family_upstream": family_upstream,
        "general_upstream": GENERAL_UPSTREAM,
        "requests_path": str(REQUESTS_PATH),
        "flush_seconds": 30,
        "children": [
            {
                "username": child.username,
                "uid": uids.get(child.username),
                "port": ports[child.username],
                "blocked": list(child.web_filter.blocked_domains),
                "allowed": list(child.web_filter.allowed_domains),
            }
            for child in policy.children
        ],
    }


def render_nft(child_uids: List[Tuple[int, int]]) -> str:
    """Ruleset for (uid, port) pairs. Re-applying it replaces the table atomically.

    Per child: DNS is redirected to the child's gateway port, DNS over TLS is dropped, and all
    other outbound traffic is dropped unless it is loopback, part of an established
    connection, or to an address the gateway has just returned in a lookup (the allow sets).
    """
    lines = [
        f"add table inet {NFT_TABLE}",
        f"delete table inet {NFT_TABLE}",
        f"table inet {NFT_TABLE} {{",
    ]
    for uid, _ in child_uids:
        lines.append(f"  set allow4_{uid} {{ type ipv4_addr; flags timeout; }}")
        lines.append(f"  set allow6_{uid} {{ type ipv6_addr; flags timeout; }}")
    lines += [
        "  chain output_nat {",
        "    type nat hook output priority -100; policy accept;",
    ]
    for uid, port in child_uids:
        lines.append(f"    meta skuid {uid} udp dport 53 redirect to :{port}")
        lines.append(f"    meta skuid {uid} tcp dport 53 redirect to :{port}")
    lines += [
        "  }",
        "  chain output_filter {",
        "    type filter hook output priority 0; policy accept;",
    ]
    for uid, _ in child_uids:
        lines += [
            f"    meta skuid {uid} tcp dport 853 drop",
            f"    meta skuid {uid} udp dport 853 drop",
            # Match the destination, not the output interface: a redirected packet's
            # interface is chosen before the redirect, so oif "lo" does not match it.
            f"    meta skuid {uid} ip daddr 127.0.0.0/8 accept",
            f"    meta skuid {uid} ip6 daddr ::1 accept",
            f"    meta skuid {uid} ct state established,related accept",
            f"    meta skuid {uid} ip daddr @allow4_{uid} accept",
            f"    meta skuid {uid} ip6 daddr @allow6_{uid} accept",
            f"    meta skuid {uid} drop",
        ]
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def render_service(python: str = sys.executable) -> str:
    """Unit that runs the gateway with the interpreter that has family_linux installed."""
    return (
        "[Unit]\n"
        "Description=Family Linux per-child DNS filtering gateway\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={python} -m family_linux.security.dns_gateway --config {GATEWAY_CONFIG_PATH}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "User=root\n"
        "Group=root\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class WebGateway:
    """Installs the gateway configuration, redirect rules, and service for a policy."""

    def __init__(self, adapter: SystemAdapter):
        self.adapter = adapter

    def _uid(self, username: str) -> Optional[int]:
        try:
            return pwd.getpwnam(username).pw_uid
        except KeyError:
            return None

    def apply(self, policy: FamilyPolicy) -> List[str]:
        """Installs the gateway for all children. Returns warnings; never raises for missing tools."""
        warnings: List[str] = []
        if not policy.children:
            return warnings

        provider = policy.children[0].web_filter.dns_provider
        uids = {child.username: uid for child in policy.children if (uid := self._uid(child.username)) is not None}
        config = render_config(policy, provider, uids)
        self.adapter.write_system_file(GATEWAY_CONFIG_PATH, json.dumps(config, indent=2) + "\n", mode=0o600)
        self.adapter.write_system_file(SERVICE_PATH, render_service(), mode=0o644)

        ports = child_ports(policy)
        uid_pairs: List[Tuple[int, int]] = []
        for child in policy.children:
            uid = self._uid(child.username)
            if uid is None:
                if self.adapter.dry_run:
                    continue
                warnings.append(f"No Linux account '{child.username}' yet; web rules not active for this child")
                continue
            uid_pairs.append((uid, ports[child.username]))

        self.adapter.write_system_file(NFT_RULES_PATH, render_nft(uid_pairs), mode=0o644)
        if uid_pairs:
            nft = self.adapter.run_command(["nft", "-f", str(NFT_RULES_PATH)])
            if nft.returncode != 0:
                warnings.append("nftables not available; per-child DNS redirect not active")

        self.adapter.run_command(["systemctl", "daemon-reload"])
        restart = self.adapter.run_command(["systemctl", "enable", "--now", SERVICE_NAME])
        if restart.returncode == 0:
            self.adapter.run_command(["systemctl", "restart", SERVICE_NAME])
        else:
            warnings.append("family-dnsd could not start (systemd not available); per-child web rules not enforced")
        return warnings
