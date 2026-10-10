"""Per-child DNS filtering gateway for Family Linux.

One resolver listens on loopback for each child account. nftables redirects a child's DNS
traffic (matched by Linux UID) to that child's listener, so each child gets their own rules.

For each query the resolver decides one of three things:
- block: the name matches a parent block rule. Answer 0.0.0.0 (AAAA gets an empty answer).
- allow: the name matches a parent allow rule. Forward to an unfiltered upstream.
- default: forward to the family-safe upstream chosen in the policy.

Blocked lookups and names the family upstream refuses are recorded as requests, so a parent
can review them and approve or dismiss them.

Stdlib only, so it runs on a stock Ubuntu install with no extra packages.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

BLOCK_IPV4 = b"\x00\x00\x00\x00"
DNS_PORT = 53
UDP_LIMIT = 4096
TCP_TIMEOUT = 5.0
UDP_TIMEOUT = 3.0

RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3


def normalise(name: str) -> str:
    return name.strip().rstrip(".").lower()


class DomainRules:
    """Parent rules for one child.

    "example.com" matches example.com and its subdomains.
    "*.example" matches any host under example (the TLD-style wildcard used by the defaults).
    Allow rules take precedence over block rules.
    """

    def __init__(self, blocked: List[str], allowed: List[str]):
        self.blocked = [normalise(d) for d in blocked if d and d.strip()]
        self.allowed = [normalise(d) for d in allowed if d and d.strip()]

    @staticmethod
    def _matches(name: str, rule: str) -> bool:
        if rule.startswith("*."):
            return name.endswith("." + rule[2:])
        return name == rule or name.endswith("." + rule)

    def decide(self, name: str) -> str:
        """Returns "allow", "block", or "default"."""
        if any(self._matches(name, r) for r in self.allowed):
            return "allow"
        if any(self._matches(name, r) for r in self.blocked):
            return "block"
        return "default"


def parse_question(packet: bytes) -> Tuple[str, int, int]:
    """Returns (qname, qtype, end offset) for the first question. Raises ValueError if malformed."""
    if len(packet) < 17:
        raise ValueError("packet too short")
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        raise ValueError("no question")

    pos = 12
    labels: List[str] = []
    while True:
        if pos >= len(packet):
            raise ValueError("truncated name")
        length = packet[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0:
            raise ValueError("compressed names are not expected in questions")
        if pos + 1 + length > len(packet):
            raise ValueError("truncated label")
        labels.append(packet[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length

    if pos + 4 > len(packet):
        raise ValueError("truncated question")
    qtype = struct.unpack("!H", packet[pos:pos + 2])[0]
    return normalise(".".join(labels)), qtype, pos + 4


def _response_header(query: bytes, rcode: int, ancount: int) -> bytes:
    request_flags = struct.unpack("!H", query[2:4])[0]
    recursion_desired = request_flags & 0x0100
    flags = 0x8000 | recursion_desired | 0x0080 | rcode  # QR, RD copied, RA
    return query[:2] + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)


def block_response(query: bytes) -> bytes:
    """Answers a blocked query. A records get 0.0.0.0; other types get an empty answer."""
    _, qtype, end = parse_question(query)
    question = query[12:end]
    if qtype == 1:  # A
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + BLOCK_IPV4
        return _response_header(query, 0, 1) + question + answer
    return _response_header(query, 0, 0) + question


def error_response(query: bytes, rcode: int) -> bytes:
    """Returns a header-only reply with the given rcode, echoing the question when it parses."""
    try:
        _, _, end = parse_question(query)
        question = query[12:end]
    except ValueError:
        question = b""
    if len(query) < 4:
        # Too short to echo the question; reply with the transaction ID only.
        return query[:2].ljust(2, b"\x00") + struct.pack("!HHHHH", 0x8000 | rcode, 0, 0, 0, 0)
    return _response_header(query, rcode, 0) + question


def _udp_forward(query: bytes, upstream: str) -> Optional[bytes]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(UDP_TIMEOUT)
        try:
            sock.sendto(query, (upstream, DNS_PORT))
            reply, _ = sock.recvfrom(UDP_LIMIT)
            return reply
        except OSError:
            return None


def _tcp_forward(query: bytes, upstream: str) -> Optional[bytes]:
    try:
        with socket.create_connection((upstream, DNS_PORT), timeout=TCP_TIMEOUT) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            size = struct.unpack("!H", _recv_exact(sock, 2))[0]
            return _recv_exact(sock, size)
    except OSError:
        return None


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("connection closed")
        data += chunk
    return data


Forwarder = Callable[[bytes, str, bool], Optional[bytes]]


def forward_dns(query: bytes, upstream: str, tcp: bool) -> Optional[bytes]:
    return _tcp_forward(query, upstream) if tcp else _udp_forward(query, upstream)


class RequestLog:
    """Blocked and unresolved lookups per child, kept in memory and flushed to a JSON file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._pending: Dict[str, Dict[str, Dict[str, object]]] = {}

    def record(self, child: str, name: str, reason: str) -> None:
        with self._lock:
            entry = self._pending.setdefault(child, {}).setdefault(
                name, {"count": 0, "reason": reason, "last_seen": ""}
            )
            entry["count"] = int(entry["count"]) + 1
            entry["last_seen"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            entry["reason"] = reason

    def flush(self) -> None:
        with self._lock:
            if not self._pending:
                return
            merged = load_requests(self.path)
            for child, names in self._pending.items():
                bucket = merged.setdefault(child, {})
                for name, entry in names.items():
                    existing = bucket.setdefault(name, {"count": 0, "reason": entry["reason"], "last_seen": ""})
                    existing["count"] = int(existing["count"]) + int(entry["count"])
                    existing["last_seen"] = entry["last_seen"]
                    existing["reason"] = entry["reason"]
            self._pending.clear()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


def load_requests(path: Path) -> Dict[str, Dict[str, Dict[str, object]]]:
    """Returns {child: {domain: {count, reason, last_seen}}} from the request file."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def clear_request(path: Path, child: str, name: str) -> None:
    requests = load_requests(path)
    if name in requests.get(child, {}):
        del requests[child][name]
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(requests, indent=2), encoding="utf-8")


def _skip_name(packet: bytes, pos: int) -> int:
    """Returns the offset just past a (possibly compressed) name starting at pos."""
    while True:
        length = packet[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0:
            return pos + 2
        pos += 1 + length


def parse_answer_addresses(reply: bytes) -> List[Tuple[str, int]]:
    """Returns (address, ttl) for every A and AAAA record in a successful reply.

    Malformed replies yield whatever was read before the error, so a bad reply never
    stops the resolver.
    """
    found: List[Tuple[str, int]] = []
    try:
        if len(reply) < 12 or (reply[3] & 0x0F) != 0:
            return found
        qdcount, ancount = struct.unpack("!HH", reply[4:8])
        pos = 12
        for _ in range(qdcount):
            pos = _skip_name(reply, pos) + 4
        for _ in range(ancount):
            pos = _skip_name(reply, pos)
            rtype, _, ttl, rdlength = struct.unpack("!HHIH", reply[pos:pos + 10])
            pos += 10
            rdata = reply[pos:pos + rdlength]
            pos += rdlength
            if rtype == 1 and rdlength == 4:
                found.append((socket.inet_ntop(socket.AF_INET, rdata), ttl))
            elif rtype == 28 and rdlength == 16:
                found.append((socket.inet_ntop(socket.AF_INET6, rdata), ttl))
    except (IndexError, struct.error, OSError, ValueError):
        pass
    return found


NFT_TABLE_NAME = "family_linux"
MIN_ALLOW_SECONDS = 60
MAX_ALLOW_SECONDS = 3600
MAX_ADDRESSES_PER_ANSWER = 32


def allow_set_names(uid: int) -> Tuple[str, str]:
    """Names of the IPv4 and IPv6 address sets for one child's UID."""
    return f"allow4_{uid}", f"allow6_{uid}"


class AddressAllowList:
    """Keeps a child's nftables address sets in step with the addresses their lookups returned.

    Each address is allowed for the TTL of the record that returned it. The sets are
    defined by web_gateway.render_nft; this only adds and refreshes elements.
    """

    def __init__(self, uid: int, runner: Optional[Callable[[List[str]], int]] = None):
        self.uid = uid
        self.v4, self.v6 = allow_set_names(uid)
        self._run = runner or _run_nft

    def add(self, entries: List[Tuple[str, int]]) -> int:
        """Allows each address. Returns how many were added."""
        added = 0
        for address, ttl in entries[:MAX_ADDRESSES_PER_ANSWER]:
            family_set = self.v6 if ":" in address else self.v4
            seconds = min(max(int(ttl), MIN_ALLOW_SECONDS), MAX_ALLOW_SECONDS)
            # Delete first so the timeout is refreshed; both commands may report "no such element".
            self._run(["delete", "element", "inet", NFT_TABLE_NAME, family_set, "{", address, "}"])
            if self._run(["add", "element", "inet", NFT_TABLE_NAME, family_set, "{", f"{address} timeout {seconds}s", "}"]) == 0:
                added += 1
        return added


def _run_nft(args: List[str]) -> int:
    try:
        return subprocess.run(["nft", *args], capture_output=True, text=True).returncode
    except OSError:
        return 127


class ChildResolver:
    """Answers one child's DNS queries according to that child's rules."""

    def __init__(
        self,
        username: str,
        rules: DomainRules,
        family_upstream: str,
        general_upstream: str,
        log: RequestLog,
        forward: Forwarder = forward_dns,
        allow_list: Optional[AddressAllowList] = None,
        learned_addresses=None,
        learned_names=None,
    ):
        self.username = username
        self.rules = rules
        self.family_upstream = family_upstream
        self.general_upstream = general_upstream
        self.log = log
        self.forward = forward
        self.allow_list = allow_list
        # Stores from tls_proxy (duck-typed: remember(key, seconds)). They let the HTTPS
        # proxy check that a connection's address and name came from an allowed lookup.
        self.learned_addresses = learned_addresses
        self.learned_names = learned_names

    def answer(self, query: bytes, tcp: bool = False) -> bytes:
        try:
            name, _, _ = parse_question(query)
        except ValueError:
            return error_response(query, RCODE_FORMERR)

        decision = self.rules.decide(name)
        if decision == "block":
            self.log.record(self.username, name, "blocked by parent rule")
            return block_response(query)

        upstream = self.general_upstream if decision == "allow" else self.family_upstream
        reply = self.forward(query, upstream, tcp)
        if reply is None:
            return error_response(query, RCODE_SERVFAIL)

        if decision == "default" and len(reply) >= 4 and (reply[3] & 0x0F) == RCODE_NXDOMAIN:
            self.log.record(self.username, name, "not resolved by family filter")
        # Only answers the parent allowed (directly or by default) reach this point, so only their
        # addresses and names become reachable. Blocked answers never do.
        addresses = parse_answer_addresses(reply)
        if addresses:
            if self.allow_list is not None:
                self.allow_list.add(addresses)
            ttl = min(max(min(ttl for _, ttl in addresses), MIN_ALLOW_SECONDS), MAX_ALLOW_SECONDS)
            if self.learned_addresses is not None:
                for address, _ in addresses[:MAX_ADDRESSES_PER_ANSWER]:
                    self.learned_addresses.remember(address, ttl)
            if self.learned_names is not None:
                self.learned_names.remember(name, ttl)
        return reply


def _serve_udp(host: str, port: int, resolver: ChildResolver, family: int = socket.AF_INET) -> None:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))

    def handle(query: bytes, addr) -> None:
        sock.sendto(resolver.answer(query), addr)

    while True:
        query, addr = sock.recvfrom(UDP_LIMIT)
        threading.Thread(target=handle, args=(query, addr), daemon=True).start()


def _serve_tcp(host: str, port: int, resolver: ChildResolver, family: int = socket.AF_INET) -> None:
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((host, port))
    listener.listen(16)

    def handle(conn: socket.socket) -> None:
        with conn:
            conn.settimeout(TCP_TIMEOUT)
            try:
                size = struct.unpack("!H", _recv_exact(conn, 2))[0]
                query = _recv_exact(conn, size)
            except OSError:
                return
            reply = resolver.answer(query, tcp=True)
            conn.sendall(struct.pack("!H", len(reply)) + reply)

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def _listen(target: Callable, address: str, port: int, args: tuple, family: int) -> None:
    """Runs one listener. An unavailable address (for example IPv6 disabled) is reported, not fatal."""
    try:
        target(address, port, *args, family=family)
    except OSError as exc:
        print(f"[Family Linux] listener {address}:{port} not started: {exc}", file=sys.stderr, flush=True)


def load_config(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def run(config: dict) -> None:
    """Starts DNS and HTTP(S) name-check listeners per child, plus the periodic request flush."""
    from family_linux.security import tls_proxy  # imported here: tls_proxy depends on this module

    log = RequestLog(Path(config["requests_path"]))
    host = config.get("listen_address", "127.0.0.1")
    threads = []
    for child in config["children"]:
        rules = DomainRules(child.get("blocked", []), child.get("allowed", []))
        learned_addresses = tls_proxy.LearnedAddresses()
        learned_names = tls_proxy.LearnedNames()
        resolver = ChildResolver(
            username=child["username"],
            rules=rules,
            family_upstream=config["family_upstream"],
            general_upstream=config["general_upstream"],
            log=log,
            allow_list=AddressAllowList(child["uid"]) if child.get("uid") is not None else None,
            learned_addresses=learned_addresses,
            learned_names=learned_names,
        )
        ctx = None
        if child.get("tls_port") is not None:
            ctx = tls_proxy.ProxyContext(
                username=child["username"],
                rules=rules,
                learned_addresses=learned_addresses,
                learned_names=learned_names,
                log=log,
            )
        # Redirected IPv6 traffic lands on ::1, so every service listens on both loopbacks.
        for family, address in ((socket.AF_INET, host), (socket.AF_INET6, "::1")):
            for target, port, args in (
                (_serve_udp, int(child["port"]), (resolver,)),
                (_serve_tcp, int(child["port"]), (resolver,)),
                *(((tls_proxy.serve, int(child["tls_port"]), (ctx,)),) if ctx is not None else ()),
            ):
                thread = threading.Thread(
                    target=_listen, args=(target, address, port, args, family), daemon=True
                )
                thread.start()
                threads.append(thread)

    print(f"[Family Linux] DNS gateway serving {len(config['children'])} child account(s)", flush=True)
    interval = float(config.get("flush_seconds", 30))
    try:
        while True:
            time.sleep(interval)
            log.flush()
    except KeyboardInterrupt:
        log.flush()


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Family Linux per-child DNS gateway")
    parser.add_argument("--config", type=Path, required=True, help="Gateway configuration JSON")
    args = parser.parse_args(argv)
    run(load_config(args.config))


if __name__ == "__main__":
    sys.exit(main())
