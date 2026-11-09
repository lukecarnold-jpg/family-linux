"""Provisioning for the per-child DNS gateway.

Renders and installs three things:
- /etc/family-linux/dns-gateway.json, read by the gateway service
- an nftables table that redirects each child's DNS to that child's listener and drops DoT
- family-web-rules.service, which loads that table early at every boot
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
RULES_SERVICE_PATH = Path("/etc/systemd/system/family-web-rules.service")
RULES_SERVICE_NAME = "family-web-rules"
NFT_TABLE = "family_linux"
PORT_BASE = 5301
TLS_PORT_BASE = 5401  # per-child HTTP(S) name-check proxy
GENERAL_UPSTREAM = "1.1.1.1"  # used only for names the parent explicitly allows
GENERAL_UPSTREAMS = (GENERAL_UPSTREAM, "1.0.0.1")
LISTEN_ADDRESS = "127.0.0.1"


def child_ports(policy: FamilyPolicy) -> Dict[str, int]:
    """Stable loopback port per child, in policy order."""
    return {child.username: PORT_BASE + index for index, child in enumerate(policy.children)}


def tls_ports(policy: FamilyPolicy) -> Dict[str, int]:
    return {child.username: TLS_PORT_BASE + index for index, child in enumerate(policy.children)}


def render_config(policy: FamilyPolicy, provider: str, uids: Optional[Dict[str, int]] = None) -> dict:
    ports = child_ports(policy)
    proxy_ports = tls_ports(policy)
    uids = uids or {}
    family_upstreams = list(DNS_SERVERS.get(provider, DNS_SERVERS[DNSProvider.CLEANBROWSING_FAMILY.value]))
    return {
        "listen_address": LISTEN_ADDRESS,
        # Both servers of the provider, tried in order (the gateway falls back when one does not answer)
        "family_upstream": family_upstreams[0],
        "family_upstreams": family_upstreams,
        "general_upstream": GENERAL_UPSTREAM,
        "general_upstreams": list(GENERAL_UPSTREAMS),
        "requests_path": str(REQUESTS_PATH),
        "flush_seconds": 30,
        "children": [
            {
                "username": child.username,
                "uid": uids.get(child.username),
                "port": ports[child.username],
                "tls_port": proxy_ports[child.username],
                "blocked": list(child.web_filter.blocked_domains),
                "allowed": list(child.web_filter.allowed_domains),
                # Each child's own DNS provider (it used to be the first child's for everyone)
                "family_upstreams": list(DNS_SERVERS.get(child.web_filter.dns_provider, family_upstreams)),
                "safe_search": bool(child.web_filter.safe_search_enforced),
            }
            for child in policy.children
        ],
    }


def render_nft(child_uids: List[Tuple[int, int, int]], ipv6: bool = True) -> str:
    """Ruleset for (uid, dns_port, tls_port) triples. Re-applying it replaces the table atomically.

    Per child: DNS is redirected to the child's gateway port; HTTP and HTTPS are redirected to the
    name-check proxy; QUIC and DNS over TLS are dropped (they would bypass both checks); and all
    other outbound traffic is dropped unless it is loopback, part of an established connection,
    or to an address the gateway has just returned in a lookup (the allow sets).
    """
    if not ipv6:
        # Without an IPv6 route, an IPv6 connection would be accepted by the local proxy and then
        # fail upstream, so the browser never falls back to IPv4. Refuse IPv6 at the source instead.
        return _render_nft_ipv4_only(child_uids)
    lines = [
        f"add table inet {NFT_TABLE}",
        f"delete table inet {NFT_TABLE}",
        f"table inet {NFT_TABLE} {{",
    ]
    for uid, _, _ in child_uids:
        lines.append(f"  set allow4_{uid} {{ type ipv4_addr; flags timeout; }}")
        lines.append(f"  set allow6_{uid} {{ type ipv6_addr; flags timeout; }}")
    lines += [
        "  chain output_nat {",
        "    type nat hook output priority -100; policy accept;",
    ]
    for uid, port, tls_port in child_uids:
        # IPv4 redirects to 127.0.0.1. IPv6 names ::1 explicitly: the plain redirect target for
        # IPv6 did not reach the listeners on the VM.
        lines.append(f"    meta skuid {uid} meta nfproto ipv4 udp dport 53 redirect to :{port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv4 tcp dport 53 redirect to :{port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv6 udp dport 53 dnat ip6 to [::1]:{port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv6 tcp dport 53 dnat ip6 to [::1]:{port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv4 tcp dport {{ 80, 443 }} redirect to :{tls_port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv6 tcp dport {{ 80, 443 }} dnat ip6 to [::1]:{tls_port}")
    lines += [
        "  }",
        "  chain output_filter {",
        "    type filter hook output priority 0; policy accept;",
    ]
    for uid, port, tls_port in child_uids:
        lines += [
            f"    meta skuid {uid} tcp dport 853 drop",
            f"    meta skuid {uid} udp dport 853 drop",
            f"    meta skuid {uid} udp dport 443 drop",
            *_own_gateway_only(uid, port, tls_port, ipv6=True),
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


GATEWAY_PORT_RANGE = f"{PORT_BASE}-{TLS_PORT_BASE + 98}"  # every child's DNS and proxy ports


def _own_gateway_only(uid: int, port: int, tls_port: int, ipv6: bool) -> List[str]:
    """A child reaches their own gateway ports on loopback, not a brother's or sister's (whose
    rules may be looser). Redirected traffic arrives here already pointed at the child's own ports."""
    own = f"meta l4proto {{ tcp, udp }} th dport {{ {port}, {tls_port} }}"
    others = f"meta l4proto {{ tcp, udp }} th dport {GATEWAY_PORT_RANGE}"
    lines = [
        f"    meta skuid {uid} ip daddr 127.0.0.0/8 {own} accept",
        f"    meta skuid {uid} ip daddr 127.0.0.0/8 {others} drop",
    ]
    if ipv6:
        lines += [
            f"    meta skuid {uid} ip6 daddr ::1 {own} accept",
            f"    meta skuid {uid} ip6 daddr ::1 {others} drop",
        ]
    return lines


def _render_nft_ipv4_only(child_uids: List[Tuple[int, int, int]]) -> str:
    lines = [
        f"add table inet {NFT_TABLE}",
        f"delete table inet {NFT_TABLE}",
        f"table inet {NFT_TABLE} {{",
    ]
    for uid, _, _ in child_uids:
        lines.append(f"  set allow4_{uid} {{ type ipv4_addr; flags timeout; }}")
    lines += [
        "  chain output_nat {",
        "    type nat hook output priority -100; policy accept;",
    ]
    for uid, port, tls_port in child_uids:
        lines.append(f"    meta skuid {uid} meta nfproto ipv4 udp dport 53 redirect to :{port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv4 tcp dport 53 redirect to :{port}")
        lines.append(f"    meta skuid {uid} meta nfproto ipv4 tcp dport {{ 80, 443 }} redirect to :{tls_port}")
    lines += [
        "  }",
        "  chain output_filter {",
        "    type filter hook output priority 0; policy accept;",
    ]
    for uid, port, tls_port in child_uids:
        lines += [
            f"    meta skuid {uid} meta nfproto ipv6 drop",
            f"    meta skuid {uid} tcp dport 853 drop",
            f"    meta skuid {uid} udp dport 853 drop",
            f"    meta skuid {uid} udp dport 443 drop",
            *_own_gateway_only(uid, port, tls_port, ipv6=False),
            f"    meta skuid {uid} ip daddr 127.0.0.0/8 accept",
            f"    meta skuid {uid} ct state established,related accept",
            f"    meta skuid {uid} ip daddr @allow4_{uid} accept",
            f"    meta skuid {uid} drop",
        ]
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def _structure(config: dict) -> tuple:
    """What a running gateway cannot change without a restart: listeners, accounts and servers."""
    return (
        config.get("listen_address"),
        tuple(config.get("family_upstreams") or [config.get("family_upstream")]),
        tuple(config.get("general_upstreams") or [config.get("general_upstream")]),
        tuple(
            (c.get("username"), c.get("uid"), c.get("port"), c.get("tls_port"), tuple(c.get("family_upstreams") or ()))
            for c in config.get("children", [])
        ),
    )


def rules_cover_children(listing: str, children: Dict[str, int]) -> List[str]:
    """Children (name -> uid) with no rule in an `nft list table` listing. nft may print a
    UID as the number or as the user name, so both are accepted."""
    return [
        name for name, uid in children.items()
        if f"skuid {uid} " not in listing and f'skuid "{name}" ' not in listing and f"skuid {name} " not in listing
    ]


def has_ipv6_route(adapter: SystemAdapter) -> bool:
    """True when the host has an IPv6 default route (checked read-only)."""
    result = adapter.run_command(["ip", "-6", "route", "show", "default"])
    return result.returncode == 0 and bool(result.stdout.strip())


def render_rules_service() -> str:
    """Unit that loads the children's nftables table at boot, before any network comes up.

    It is separate from the gateway, so the rules are in place even if the gateway fails to start
    or is stopped: a child then has no DNS at all (fails closed) instead of unfiltered access.
    """
    return (
        "[Unit]\n"
        "Description=Family Linux children's network rules\n"
        "DefaultDependencies=no\n"
        "After=local-fs.target nftables.service\n"
        f"Before=network-pre.target {SERVICE_NAME}.service\n"
        "Wants=network-pre.target\n"
        f"ConditionPathExists={NFT_RULES_PATH}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart=/usr/sbin/nft -f {NFT_RULES_PATH}\n"
        "\n"
        "[Install]\n"
        "WantedBy=sysinit.target\n"
    )


def render_service(python: str = sys.executable) -> str:
    """Unit that runs the gateway with the interpreter that has family_linux installed."""
    return (
        "[Unit]\n"
        "Description=Family Linux per-child DNS filtering gateway\n"
        f"After=network.target {RULES_SERVICE_NAME}.service\n"
        f"Wants={RULES_SERVICE_NAME}.service\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        # The child rules are loaded by family-web-rules.service, not here, so they do not depend
        # on the gateway starting. If the gateway stops, the redirect stays and the child loses
        # DNS: it fails closed, not open.
        f"ExecStart={python} -m family_linux.security.dns_gateway --config {GATEWAY_CONFIG_PATH}\n"
        # New website rules are read on reload (SIGHUP), so lookups already made stay allowed.
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "User=root\n"
        "Group=root\n"
        # It reads data from children's connections, so it gets only what it needs: CAP_NET_ADMIN
        # for nft, its request file to write, and nothing else on disk. The request file is
        # private (UMask), so a child cannot read their brothers' and sisters' blocked sites.
        "CapabilityBoundingSet=CAP_NET_ADMIN\n"
        "NoNewPrivileges=yes\n"
        "ProtectSystem=strict\n"
        # StateDirectory makes /var/lib/family-linux writable and creates it if missing.
        # ReadWritePaths= failed to start the service when the folder did not exist yet
        # (status=226/NAMESPACE, seen in CI).
        f"StateDirectory={REQUESTS_PATH.parent.name}\n"
        "StateDirectoryMode=0755\n"
        # read-only, not yes: an installed package may live under /home (seen in CI)
        "ProtectHome=read-only\n"
        "PrivateTmp=yes\n"
        "PrivateDevices=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectKernelLogs=yes\n"
        "ProtectControlGroups=yes\n"
        "ProtectClock=yes\n"
        "ProtectHostname=yes\n"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"
        "RestrictNamespaces=yes\n"
        "RestrictSUIDSGID=yes\n"
        "LockPersonality=yes\n"
        "SystemCallArchitectures=native\n"
        "UMask=0077\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class WebGateway:
    """Installs the gateway configuration, redirect rules, and service for a policy."""

    def __init__(self, adapter: SystemAdapter):
        self.adapter = adapter

    def _read_text(self, path: Path) -> Optional[str]:
        if self.adapter.dry_run:
            return self.adapter.simulated_files.get(str(path))
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return None

    def _read(self, path: Path) -> Optional[dict]:
        text = self._read_text(path)
        try:
            return json.loads(text) if text else None
        except ValueError:
            return None

    def _uid(self, username: str) -> Optional[int]:
        try:
            return pwd.getpwnam(username).pw_uid
        except KeyError:
            return None

    def apply(self, policy: FamilyPolicy) -> List[str]:
        """Installs the gateway for all children. Returns warnings; never raises for missing tools."""
        warnings: List[str] = []
        # Applied with no children too, so the rules of a removed last child are cleared.
        provider = policy.children[0].web_filter.dns_provider if policy.children else DNSProvider.CLEANBROWSING_FAMILY.value
        uids = {child.username: uid for child in policy.children if (uid := self._uid(child.username)) is not None}
        config = render_config(policy, provider, uids)
        previous = self._read(GATEWAY_CONFIG_PATH)
        # Only a change of children, ports or servers needs a restart; website rules are reloaded.
        restart_needed = previous is None or _structure(previous) != _structure(config)
        self.adapter.write_system_file(GATEWAY_CONFIG_PATH, json.dumps(config, indent=2) + "\n", mode=0o600)
        self.adapter.write_system_file(SERVICE_PATH, render_service(), mode=0o644)
        self.adapter.write_system_file(RULES_SERVICE_PATH, render_rules_service(), mode=0o644)

        ports = child_ports(policy)
        proxy_ports = tls_ports(policy)
        uid_pairs: List[Tuple[int, int, int]] = []
        for child in policy.children:
            uid = self._uid(child.username)
            if uid is None:
                if self.adapter.dry_run:
                    continue
                warnings.append(f"No Linux account '{child.username}' yet; web rules not active for this child")
                continue
            uid_pairs.append((uid, ports[child.username], proxy_ports[child.username]))

        ipv6 = has_ipv6_route(self.adapter)
        if not ipv6:
            warnings.append("No IPv6 route on this host; children's IPv6 traffic is refused so browsers use IPv4")
        rules_text = render_nft(uid_pairs, ipv6=ipv6)
        loaded = self.adapter.run_command(["nft", "list", "table", "inet", NFT_TABLE]).returncode == 0
        if rules_text != self._read_text(NFT_RULES_PATH) or not loaded:
            # Reloading the table empties the children's allow sets, so it is done only on a change.
            self.adapter.write_system_file(NFT_RULES_PATH, rules_text, mode=0o644)
            nft = self.adapter.run_command(["nft", "-f", str(NFT_RULES_PATH)])
            if nft.returncode != 0 and uid_pairs:
                warnings.append("nftables not available; per-child DNS redirect not active")

        self.adapter.run_command(["systemctl", "daemon-reload"])
        # Enabled for the next boot; the rules were loaded above for this one.
        if self.adapter.run_command(["systemctl", "enable", RULES_SERVICE_NAME]).returncode != 0:
            warnings.append(f"{RULES_SERVICE_NAME} could not be enabled; children's rules are not loaded at boot")
        restart = self.adapter.run_command(["systemctl", "enable", "--now", SERVICE_NAME])
        if restart.returncode == 0:
            self.adapter.run_command(["systemctl", "restart" if restart_needed else "reload", SERVICE_NAME])
        else:
            warnings.append("family-dnsd could not start (systemd not available); per-child web rules not enforced")
        return warnings
