"""HTTPS and HTTP name checks: handshake parsing, decisions, and the proxy's relay behaviour."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from family_linux.security import tls_proxy as tp
from family_linux.security.dns_gateway import DomainRules, RequestLog


def client_hello(sni=None, ech=False, extra_extensions=b"") -> bytes:
    """Builds a minimal TLS 1.2 ClientHello, optionally with SNI and an ECH extension."""
    extensions = b""
    if sni is not None:
        name = sni.encode()
        server_name_list = b"\x00" + struct.pack("!H", len(name)) + name
        ext_data = struct.pack("!H", len(server_name_list)) + server_name_list
        extensions += struct.pack("!HH", 0x0000, len(ext_data)) + ext_data
    if ech:
        # outer ECH: type 0, kdf 0x0001, aead 0x0001, config_id 0x07, enc (empty), payload (empty)
        ech_data = b"\x00\x00\x01\x00\x01\x07" + b"\x00\x00" + b"\x00\x00"
        extensions += struct.pack("!HH", 0xFE0D, len(ech_data)) + ech_data
    extensions += extra_extensions
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01"
    body += b"\x01\x00"  # one compression method: null
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# --- handshake parsing ----------------------------------------------------

def test_reads_sni_from_client_hello():
    info = tp.parse_client_hello(client_hello(sni="Example.COM"))
    assert info == tp.ClientHelloInfo(sni="example.com", ech=False)


def test_detects_encrypted_client_hello():
    info = tp.parse_client_hello(client_hello(sni="example.com", ech=True))
    assert info.ech is True


def test_client_hello_without_sni_has_no_name():
    assert tp.parse_client_hello(client_hello(sni=None)) == tp.ClientHelloInfo(sni=None, ech=False)


def test_incomplete_client_hello_returns_none_until_complete():
    hello = client_hello(sni="example.com")
    assert tp.parse_client_hello(hello[:20]) is None
    assert tp.parse_client_hello(hello) is not None


def test_non_tls_bytes_are_rejected():
    with pytest.raises(ValueError):
        tp.parse_client_hello(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")


def test_truncated_extensions_do_not_raise_out_of_bounds():
    hello = client_hello(sni="example.com")
    # shrink the declared record so the extension block is cut in the middle
    truncated = hello[:-5]
    record_len = len(truncated) - 5
    truncated = truncated[:3] + struct.pack("!H", record_len) + truncated[5:]
    try:
        info = tp.parse_client_hello(truncated)
    except ValueError:
        info = None  # malformed input is rejected, never a crash
    # A cut-off name must never be returned as if it were the real one.
    assert info is None or info.sni is None


def test_http_host_header_is_read_without_port():
    assert tp.parse_http_host(b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n") == "example.com"
    assert tp.parse_http_host(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n") == ""
    assert tp.parse_http_host(b"GET / HTTP/1.1\r\nHost: partial") is None


# --- decisions --------------------------------------------------------------

def stores(addresses=(), names=()):
    addr = tp.LearnedAddresses()
    nm = tp.LearnedNames()
    for a in addresses:
        addr.remember(a, 300)
    for n in names:
        nm.remember(n, 300)
    return addr, nm


def test_allowed_when_address_and_name_both_came_from_allowed_lookups():
    addr, nm = stores(["93.184.216.34"], ["example.com"])
    assert tp.decide(DomainRules([], []), addr, nm, "93.184.216.34", "example.com", False) == (True, "looked up through the gateway")


def test_name_not_looked_up_is_refused_even_on_a_learned_address():
    # A CDN address serves many sites: the name must have come through the gateway.
    addr, nm = stores(["93.184.216.34"], [])
    allowed, reason = tp.decide(DomainRules([], []), addr, nm, "93.184.216.34", "tiktok.com", False)
    assert not allowed and "not looked up" in reason


def test_blocked_name_is_refused_even_when_looked_up():
    addr, nm = stores(["93.184.216.34"], ["tiktok.com"])
    allowed, reason = tp.decide(DomainRules(["tiktok.com"], []), addr, nm, "93.184.216.34", "tiktok.com", False)
    assert not allowed and reason == "blocked by parent rule"


def test_parent_allow_rule_names_are_allowed_on_a_learned_address():
    addr, nm = stores(["93.184.216.34"], [])
    allowed, _ = tp.decide(DomainRules([], ["example.com"]), addr, nm, "93.184.216.34", "example.com", False)
    assert allowed


def test_unlearned_address_is_refused():
    addr, nm = stores([], ["example.com"])
    allowed, reason = tp.decide(DomainRules([], []), addr, nm, "9.9.9.9", "example.com", False)
    assert not allowed and "address 9.9.9.9 not returned" in reason


def test_real_ech_with_an_advertised_config_is_refused():
    addr, nm = stores(["93.184.216.34"], ["example.com"])
    learned_ech = tp.LearnedEchConfigs()
    learned_ech.remember("7", 300)
    allowed, reason = tp.decide(DomainRules([], []), addr, nm, "93.184.216.34", "example.com", True,
                                ech_config_id=7, learned_ech=learned_ech)
    assert not allowed and "encrypted" in reason


def test_missing_server_name_is_refused():
    addr, nm = stores(["93.184.216.34"], [])
    allowed, reason = tp.decide(DomainRules([], []), addr, nm, "93.184.216.34", None, False)
    assert not allowed and reason == "no server name"


def test_learned_entries_expire_with_the_clock():
    now = [100.0]
    store = tp.LearnedAddresses(clock=lambda: now[0])
    store.remember("1.2.3.4", 60)
    assert store.allowed("1.2.3.4")
    now[0] += 61
    assert not store.allowed("1.2.3.4")


# --- connection handling over a real socket pair ----------------------------

def _serve_once(payload_reply: bytes):
    """A local 'origin' server that records what it receives and sends a fixed reply."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    received = []

    def run():
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(3)
            try:
                received.append(conn.recv(65536))
            except OSError:
                pass
            conn.sendall(payload_reply)
        listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return listener.getsockname(), received, thread


def _proxy_pair(monkeypatch, destination):
    """Returns (client_as_seen_by_proxy, client_end) connected over loopback.

    destination is the (address, port) the redirect reports, so the port picks the HTTPS or HTTP path.
    """
    monkeypatch.setattr(tp, "original_destination", lambda sock: destination)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client_end = socket.create_connection(listener.getsockname())
    proxy_end, _ = listener.accept()
    listener.close()
    return proxy_end, client_end


def _ctx(tmp_path, addresses, names, blocked=(), origin=None):
    addr, nm = stores(addresses, names)
    # Route the connection to the local origin, whatever port the redirect reported.
    connect = (lambda target, timeout: socket.create_connection(origin, timeout=timeout)) if origin else socket.create_connection
    return tp.ProxyContext(
        username="kid",
        rules=DomainRules(list(blocked), []),
        learned_addresses=addr,
        learned_names=nm,
        log=RequestLog(tmp_path / "requests.json"),
        connect=connect,
    )


def test_allowed_handshake_is_relayed_to_the_original_destination(tmp_path, monkeypatch):
    origin, received, thread = _serve_once(b"SERVER-HELLO")
    proxy_end, client_end = _proxy_pair(monkeypatch, ("127.0.0.1", 443))
    ctx = _ctx(tmp_path, ["127.0.0.1"], ["example.com"], origin=origin)

    worker = threading.Thread(target=tp.handle_connection, args=(proxy_end, ctx), daemon=True)
    worker.start()
    client_end.sendall(client_hello(sni="example.com"))
    client_end.settimeout(3)
    assert client_end.recv(64) == b"SERVER-HELLO"
    thread.join(timeout=3)
    assert received and received[0].startswith(b"\x16\x03\x01")
    client_end.close()
    worker.join(timeout=3)


def test_blocked_handshake_is_closed_and_logged(tmp_path, monkeypatch):
    origin, received, thread = _serve_once(b"SHOULD-NOT-ARRIVE")
    proxy_end, client_end = _proxy_pair(monkeypatch, ("127.0.0.1", 443))
    ctx = _ctx(tmp_path, ["127.0.0.1"], ["tiktok.com"], blocked=["tiktok.com"], origin=origin)

    worker = threading.Thread(target=tp.handle_connection, args=(proxy_end, ctx), daemon=True)
    worker.start()
    client_end.sendall(client_hello(sni="tiktok.com"))
    client_end.settimeout(3)
    assert client_end.recv(64) == b""  # closed without relaying
    worker.join(timeout=3)
    assert received == []
    ctx.log.flush()
    assert "tiktok.com" in __import__("json").loads((tmp_path / "requests.json").read_text())["kid"]
    client_end.close()


def test_http_host_is_checked_on_port_80(tmp_path, monkeypatch):
    origin, received, thread = _serve_once(b"HTTP/1.1 200 OK\r\n\r\n")
    proxy_end, client_end = _proxy_pair(monkeypatch, ("127.0.0.1", 80))
    ctx = _ctx(tmp_path, ["127.0.0.1"], [], blocked=["omegle.com"], origin=origin)

    worker = threading.Thread(target=tp.handle_connection, args=(proxy_end, ctx), daemon=True)
    worker.start()
    client_end.sendall(b"GET / HTTP/1.1\r\nHost: omegle.com\r\n\r\n")
    client_end.settimeout(3)
    assert client_end.recv(64) == b""
    worker.join(timeout=3)
    assert received == []
    client_end.close()


def test_original_destination_parsing_v4_and_v6():
    import socket as _s
    v4 = bytes([2, 0]) + (443).to_bytes(2, "big") + _s.inet_aton("93.184.216.34") + b"\0" * 8
    assert tp.parse_original_dst_v4(v4) == ("93.184.216.34", 443)
    v6 = bytes([10, 0]) + (443).to_bytes(2, "big") + b"\0" * 4 + _s.inet_pton(_s.AF_INET6, "2606:4700::6810:1") + b"\0" * 4
    assert tp.parse_original_dst_v6(v6) == ("2606:4700::6810:1", 443)


def test_ipv6_learned_addresses_and_decisions_work():
    addr, nm = stores(["2606:4700::6810:1"], ["example.com"])
    allowed, reason = tp.decide(DomainRules([], []), addr, nm, "2606:4700:0::6810:1", "example.com", False)
    assert allowed, reason


def test_grease_ech_is_not_refused_on_its_own():
    # Chrome sends a random (GREASE) ECH extension on every connection. Its outer name is the real one.
    addr, nm = stores(["93.184.216.34"], ["example.com"])
    learned_ech = tp.LearnedEchConfigs()
    learned_ech.remember("7", 300)
    allowed, reason = tp.decide(DomainRules([], []), addr, nm, "93.184.216.34", "example.com", True,
                                ech_config_id=9, learned_ech=learned_ech)
    assert allowed, reason


def test_ech_config_id_is_read_from_the_outer_extension():
    info = tp.parse_client_hello(client_hello(sni="example.com", ech=True))
    assert info.ech is True and info.ech_config_id == 7


def test_relay_survives_an_idle_pause_longer_than_the_connect_timeout(tmp_path, monkeypatch):
    """HTTP/2 keeps connections open between requests; the relay must not time out while idle."""
    import time as _time

    monkeypatch.setattr(tp, "TCP_TIMEOUT", 0.3)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    origin = listener.getsockname()

    def slow_origin():
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            _time.sleep(1.0)  # longer than the connect timeout
            conn.sendall(b"LATE-REPLY")
        listener.close()

    threading.Thread(target=slow_origin, daemon=True).start()
    proxy_end, client_end = _proxy_pair(monkeypatch, ("127.0.0.1", 443))
    ctx = _ctx(tmp_path, ["127.0.0.1"], ["example.com"], origin=origin)

    worker = threading.Thread(target=tp.handle_connection, args=(proxy_end, ctx), daemon=True)
    worker.start()
    client_end.sendall(client_hello(sni="example.com"))
    client_end.settimeout(5)
    assert client_end.recv(64) == b"LATE-REPLY"
    client_end.close()
    worker.join(timeout=5)
