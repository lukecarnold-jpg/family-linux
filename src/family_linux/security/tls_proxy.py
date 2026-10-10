"""Server-name control for a child's HTTPS and HTTP connections.

Address allow sets stop a child reaching addresses no allowed lookup returned, but a CDN address
serves many sites. This module checks the name each connection asks for:

- HTTPS (port 443): the server name in the TLS ClientHello (SNI). It is sent in plain text, so
  it can be read without decrypting anything.
- HTTP (port 80): the Host header.

nftables redirects a child's port 80 and 443 traffic to a per-child proxy. The proxy reads the
first bytes, decides, and then either relays the connection to its original destination or
closes it. A connection is allowed when all of these hold:

- the destination address was returned by an allowed lookup of this child
- the name was looked up through this child's gateway (so it passed the family filter), or a
  parent allow rule names it
- the name is not blocked by a parent rule
- the ClientHello carries no encrypted server name (ECH), which would hide the real name

Linux only: the original destination comes from the kernel's connection tracking.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from family_linux.security.dns_gateway import DomainRules, RequestLog, TCP_TIMEOUT

TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
SO_ORIGINAL_DST = 80
HELLO_LIMIT = 16384
HELLO_TIMEOUT = 5.0


class _Store:
    """Timed membership: each key is remembered until its expiry."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._expiry: Dict[str, float] = {}
        self._lock = threading.Lock()

    def remember(self, key: str, seconds: float) -> None:
        with self._lock:
            self._expiry[key] = self._clock() + seconds

    def remembered(self, key: str) -> bool:
        with self._lock:
            expiry = self._expiry.get(key)
            if expiry is None:
                return False
            if expiry <= self._clock():
                del self._expiry[key]
                return False
            return True


class LearnedAddresses(_Store):
    """Addresses returned by this child's allowed lookups, for their TTL."""

    def remember(self, address: str, seconds: float) -> None:  # type: ignore[override]
        super().remember(str(ipaddress.ip_address(address)), seconds)

    def allowed(self, address: str) -> bool:
        return self.remembered(str(ipaddress.ip_address(address)))


class LearnedNames(_Store):
    """Names this child looked up through the gateway and was allowed to resolve."""

    def remember(self, name: str, seconds: float) -> None:  # type: ignore[override]
        super().remember(name.rstrip(".").lower(), seconds)

    def allowed(self, name: str) -> bool:
        return self.remembered(name.rstrip(".").lower())


@dataclass
class ClientHelloInfo:
    sni: Optional[str]
    ech: bool


def parse_client_hello(data: bytes) -> Optional[ClientHelloInfo]:
    """Reads the server name from a TLS ClientHello.

    Returns None while the hello is incomplete. Raises ValueError if the bytes are not a TLS
    ClientHello.
    """
    if len(data) < 5:
        return None
    if data[0] != TLS_CONTENT_HANDSHAKE:
        raise ValueError("not a TLS handshake record")
    record_length = struct.unpack("!H", data[3:5])[0]
    if len(data) < 5 + record_length:
        return None
    body = data[5:5 + record_length]
    if len(body) < 4 or body[0] != TLS_HANDSHAKE_CLIENT_HELLO:
        raise ValueError("not a ClientHello")
    hello_length = int.from_bytes(body[1:4], "big")
    hello = body[4:4 + hello_length]
    try:
        pos = 2 + 32  # client version and random
        pos += 1 + hello[pos]  # session id
        pos += 2 + struct.unpack("!H", hello[pos:pos + 2])[0]  # cipher suites
        pos += 1 + hello[pos]  # compression methods
        if pos + 2 > len(hello):
            return ClientHelloInfo(sni=None, ech=False)  # TLS hello without extensions
        extensions_length = struct.unpack("!H", hello[pos:pos + 2])[0]
        pos += 2
        end = min(pos + extensions_length, len(hello))
        sni: Optional[str] = None
        ech = False
        while pos + 4 <= end:
            ext_type, ext_length = struct.unpack("!HH", hello[pos:pos + 4])
            pos += 4
            if pos + ext_length > len(hello):
                raise ValueError("truncated extension")  # never read a partial value
            ext_data = hello[pos:pos + ext_length]
            pos += ext_length
            if ext_type == EXT_SERVER_NAME and sni is None:
                sni = _parse_server_name(ext_data)
            elif ext_type == EXT_ENCRYPTED_CLIENT_HELLO:
                ech = True
        return ClientHelloInfo(sni=sni, ech=ech)
    except (IndexError, struct.error) as exc:
        raise ValueError("malformed ClientHello") from exc


def _parse_server_name(data: bytes) -> Optional[str]:
    if len(data) < 2:
        return None
    pos = 2
    list_end = min(2 + struct.unpack("!H", data[:2])[0], len(data))
    while pos + 3 <= list_end:
        name_type = data[pos]
        name_length = struct.unpack("!H", data[pos + 1:pos + 3])[0]
        if pos + 3 + name_length > len(data):
            raise ValueError("truncated server name")  # never return a partial name
        name = data[pos + 3:pos + 3 + name_length]
        if name_type == 0:
            return name.decode("ascii", "replace").rstrip(".").lower()
        pos += 3 + name_length
    return None


def parse_http_host(data: bytes) -> Optional[str]:
    """Returns the Host header (without port), "" if absent, or None while the headers are incomplete."""
    if b"\r\n\r\n" not in data:
        return None if len(data) < HELLO_LIMIT else ""
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "host":
            return value.strip().split(":")[0].rstrip(".").lower()
    return ""


def original_destination(sock: socket.socket) -> Tuple[str, int]:
    """The address a redirected connection was originally sent to (Linux netfilter)."""
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack("!H", raw[2:4])[0]
    return socket.inet_ntoa(raw[4:8]), port


def decide(
    rules: DomainRules,
    learned_addresses: LearnedAddresses,
    learned_names: LearnedNames,
    address: str,
    name: Optional[str],
    ech: bool,
) -> Tuple[bool, str]:
    """Returns (allowed, reason) for one connection."""
    if not learned_addresses.allowed(address):
        return False, "address not returned by an allowed lookup"
    if ech:
        return False, "encrypted server name not permitted"
    if not name:
        return False, "no server name"
    verdict = rules.decide(name)
    if verdict == "block":
        return False, "blocked by parent rule"
    if verdict == "allow":
        return True, "allowed by parent rule"
    if learned_names.allowed(name):
        return True, "looked up through the gateway"
    return False, "name was not looked up through the gateway"


def _relay(source: socket.socket, target: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            target.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass


@dataclass
class ProxyContext:
    username: str
    rules: DomainRules
    learned_addresses: LearnedAddresses
    learned_names: LearnedNames
    log: RequestLog
    # Opens the upstream connection. Injected by tests; production uses the default.
    connect: Callable[[Tuple[str, int], float], socket.socket] = socket.create_connection


def handle_connection(client: socket.socket, ctx: ProxyContext) -> None:
    """Reads the first bytes, decides, then relays or closes."""
    with client:
        try:
            address, port = original_destination(client)
        except OSError:
            return
        client.settimeout(HELLO_TIMEOUT)
        buffered = b""
        name: Optional[str] = None
        ech = False
        try:
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buffered += chunk
                if port == 443:
                    info = parse_client_hello(buffered)
                    if info is not None:
                        name, ech = info.sni, info.ech
                        break
                else:
                    host = parse_http_host(buffered)
                    if host is not None:
                        name = host or None
                        break
                if len(buffered) > HELLO_LIMIT:
                    return
        except (OSError, ValueError):
            return

        allowed, reason = decide(ctx.rules, ctx.learned_addresses, ctx.learned_names, address, name, ech)
        if not allowed:
            if name:
                ctx.log.record(ctx.username, name, reason)
            return

        try:
            upstream = ctx.connect((address, port), TCP_TIMEOUT)
        except OSError:
            return
        with upstream:
            upstream.sendall(buffered)
            client.settimeout(None)
            outbound = threading.Thread(target=_relay, args=(client, upstream), daemon=True)
            outbound.start()
            _relay(upstream, client)
            outbound.join(timeout=TCP_TIMEOUT)


def serve(host: str, port: int, ctx: ProxyContext) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle_connection, args=(conn, ctx), daemon=True).start()
