"""Per-child DNS gateway: rule matching, DNS packet handling, request log, and provisioning output."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from family_linux.models import AgeTier, ChildAccount, FamilyPolicy, ParentAccount
from family_linux.security import dns_gateway as gw
from family_linux.security.adapter import SystemAdapter
from family_linux.security.web_gateway import (
    NFT_RULES_PATH, GATEWAY_CONFIG_PATH, SERVICE_PATH, WebGateway, child_ports, render_config, render_nft,
)


def make_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


class FakeForwarder:
    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply

    def __call__(self, query, upstream, tcp):
        self.calls.append(upstream)
        if self.reply is None:
            # Echo header with NOERROR and no answers.
            return query[:2] + struct.pack("!H", 0x8180) + query[4:12]
        return self.reply


def resolver(tmp_path, forward, blocked=("omegle.com", "*.adult"), allowed=("wiki.example",)):
    log = gw.RequestLog(tmp_path / "requests.json")
    return gw.ChildResolver(
        username="kid",
        rules=gw.DomainRules(list(blocked), list(allowed)),
        family_upstream="185.228.168.168",
        general_upstream="1.1.1.1",
        log=log,
        forward=forward,
    ), log


# --- rules ----------------------------------------------------------------

def test_domain_rules_match_host_and_subdomains():
    rules = gw.DomainRules(["omegle.com"], [])
    assert rules.decide("omegle.com") == "block"
    assert rules.decide("www.omegle.com") == "block"
    assert rules.decide("notomegle.com") == "default"


def test_wildcard_matches_hosts_under_a_suffix_but_not_the_bare_name():
    rules = gw.DomainRules(["*.adult"], [])
    assert rules.decide("site.adult") == "block"
    assert rules.decide("a.b.adult") == "block"
    assert rules.decide("adult") == "default"


def test_allow_rule_takes_precedence_over_block():
    rules = gw.DomainRules(["*.example"], ["ok.example"])
    assert rules.decide("ok.example") == "allow"
    assert rules.decide("other.example") == "block"


def test_rules_are_case_and_trailing_dot_insensitive():
    rules = gw.DomainRules(["Omegle.COM."], [])
    assert rules.decide("omegle.com") == "block"


# --- packets --------------------------------------------------------------

def test_parse_question_reads_name_and_type():
    name, qtype, end = gw.parse_question(make_query("WWW.Example.com", qtype=28))
    assert (name, qtype) == ("www.example.com", 28)
    assert end == len(make_query("WWW.Example.com", qtype=28))


def test_block_response_answers_a_with_zero_address_and_keeps_txid():
    reply = gw.block_response(make_query("omegle.com", qtype=1, txid=0xBEEF))
    assert reply[:2] == b"\xbe\xef"
    assert struct.unpack("!H", reply[6:8])[0] == 1  # ANCOUNT
    assert reply.endswith(b"\x00\x00\x00\x00")  # 0.0.0.0


def test_block_response_gives_aaaa_an_empty_answer():
    reply = gw.block_response(make_query("omegle.com", qtype=28))
    assert struct.unpack("!H", reply[6:8])[0] == 0  # ANCOUNT
    assert struct.unpack("!H", reply[2:4])[0] & 0x000F == 0  # NOERROR


def test_malformed_query_gets_formerr_not_an_exception(tmp_path):
    res, _ = resolver(tmp_path, FakeForwarder())
    reply = res.answer(b"\x12\x34\x01\x00")  # too short to hold a question
    assert reply[:2] == b"\x12\x34"
    assert reply[3] & 0x0F == gw.RCODE_FORMERR


# --- resolver decisions ---------------------------------------------------

def test_blocked_name_is_answered_locally_and_logged(tmp_path):
    fwd = FakeForwarder()
    res, log = resolver(tmp_path, fwd)
    reply = res.answer(make_query("www.omegle.com"))
    assert fwd.calls == []
    assert reply.endswith(b"\x00\x00\x00\x00")
    log.flush()
    recorded = gw.load_requests(tmp_path / "requests.json")["kid"]["www.omegle.com"]
    assert recorded["count"] == 1


def test_allowed_name_goes_to_unfiltered_upstream(tmp_path):
    fwd = FakeForwarder()
    res, _ = resolver(tmp_path, fwd)
    res.answer(make_query("wiki.example"))
    assert fwd.calls == ["1.1.1.1"]


def test_other_names_go_to_family_upstream(tmp_path):
    fwd = FakeForwarder()
    res, _ = resolver(tmp_path, fwd)
    res.answer(make_query("example.org"))
    assert fwd.calls == ["185.228.168.168"]


def test_nxdomain_from_family_filter_is_recorded_as_a_request(tmp_path):
    nxdomain = bytearray(FakeForwarder()(make_query("filtered.example"), "", False))
    nxdomain[3] = (nxdomain[3] & 0xF0) | gw.RCODE_NXDOMAIN
    res, log = resolver(tmp_path, FakeForwarder(reply=bytes(nxdomain)))
    res.answer(make_query("filtered.example"))
    log.flush()
    recorded = gw.load_requests(tmp_path / "requests.json")["kid"]["filtered.example"]
    assert recorded["reason"] == "not resolved by family filter"


def test_upstream_failure_returns_servfail(tmp_path):
    res, _ = resolver(tmp_path, lambda query, upstream, tcp: None)
    reply = res.answer(make_query("example.org"))
    assert reply[3] & 0x0F == gw.RCODE_SERVFAIL


# --- request log ----------------------------------------------------------

def test_request_log_counts_across_flushes_and_clears(tmp_path):
    path = tmp_path / "requests.json"
    log = gw.RequestLog(path)
    log.record("kid", "tiktok.com", "blocked by parent rule")
    log.record("kid", "tiktok.com", "blocked by parent rule")
    log.flush()
    log.record("kid", "tiktok.com", "blocked by parent rule")
    log.flush()
    assert gw.load_requests(path)["kid"]["tiktok.com"]["count"] == 3

    gw.clear_request(path, "kid", "tiktok.com")
    assert "tiktok.com" not in gw.load_requests(path).get("kid", {})


def test_request_log_survives_missing_file(tmp_path):
    assert gw.load_requests(tmp_path / "missing.json") == {}


# --- provisioning output ----------------------------------------------------

def _policy() -> FamilyPolicy:
    return FamilyPolicy(
        parent=ParentAccount("parent", "Parent Admin", password="ParentPass1!"),
        children=[
            ChildAccount.create("kid", "Kid", age_tier=AgeTier.YOUNG_CHILD, password="KidPass123!"),
            ChildAccount.create("teen", "Teen", age_tier=AgeTier.TEEN, password="TeenPass123!"),
        ],
    )


def test_each_child_gets_a_distinct_port_and_their_own_rules():
    policy = _policy()
    policy.children[1].web_filter.blocked_domains = ["games.example"]
    config = render_config(policy, "cleanbrowsing_family")
    ports = {c["username"]: c["port"] for c in config["children"]}
    assert len(set(ports.values())) == 2
    teen = next(c for c in config["children"] if c["username"] == "teen")
    assert "games.example" in teen["blocked"]
    assert config["family_upstream"] == "185.228.168.168"
    assert config["general_upstream"] == "1.1.1.1"


def test_nft_rules_redirect_dns_and_drop_dot_per_uid():
    rules = render_nft([(1002, 5301, 5401), (1003, 5302, 5402)])
    assert "meta skuid 1002 meta nfproto ipv4 udp dport 53 redirect to :5301" in rules
    assert "meta skuid 1002 meta nfproto ipv4 tcp dport 53 redirect to :5301" in rules
    assert "meta skuid 1002 meta nfproto ipv6 udp dport 53 dnat ip6 to [::1]:5301" in rules
    assert "meta skuid 1003 meta nfproto ipv4 tcp dport 53 redirect to :5302" in rules
    assert "meta skuid 1002 tcp dport 853 drop" in rules
    assert "meta skuid 1002 meta nfproto ipv4 tcp dport { 80, 443 } redirect to :5401" in rules
    assert "meta skuid 1003 meta nfproto ipv6 tcp dport { 80, 443 } dnat ip6 to [::1]:5402" in rules
    assert "meta skuid 1002 udp dport 443 drop" in rules
    assert "meta skuid 1003 udp dport 853 drop" in rules
    assert "add table inet family_linux" in rules and "delete table inet family_linux" in rules


def test_gateway_apply_writes_config_rules_and_unit_in_simulation(monkeypatch):
    import family_linux.security.web_gateway as wg

    class NoSuchUser:
        @staticmethod
        def getpwnam(name):
            raise KeyError(name)

    monkeypatch.setattr(wg, "pwd", NoSuchUser)
    adapter = SystemAdapter(dry_run=True)
    warnings = WebGateway(adapter).apply(_policy())

    assert warnings == []
    config = json.loads(adapter.simulated_files[str(GATEWAY_CONFIG_PATH)])
    assert [c["username"] for c in config["children"]] == ["kid", "teen"]
    assert str(NFT_RULES_PATH) in adapter.simulated_files
    unit = adapter.simulated_files[str(SERVICE_PATH)]
    assert "family_linux.security.dns_gateway" in unit and "Restart=on-failure" in unit
    assert ["systemctl", "enable", "--now", "family-dnsd"] in adapter.executed_commands


def test_child_ports_are_stable_in_policy_order():
    policy = _policy()
    assert child_ports(policy) == {"kid": 5301, "teen": 5302}


# --- direct-IP control: addresses from allowed answers --------------------

def _answer_reply(query: bytes, ips_ttls) -> bytes:
    """Builds a NOERROR reply whose answers are the given (ip, ttl) A records."""
    body = bytearray(query[:2] + struct.pack("!H", 0x8180) + struct.pack("!HHHH", 1, len(ips_ttls), 0, 0) + query[12:])
    for ip, ttl in ips_ttls:
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(int(x) for x in ip.split("."))
    return bytes(body)


def test_parse_answer_addresses_reads_a_and_aaaa_with_ttls():
    query = make_query("example.org")
    reply = _answer_reply(query, [("93.184.216.34", 300)])
    assert gw.parse_answer_addresses(reply) == [("93.184.216.34", 300)]

    # AAAA record with compression pointer, appended by hand
    aaaa = query[:2] + struct.pack("!H", 0x8180) + struct.pack("!HHHH", 1, 1, 0, 0) + query[12:]
    aaaa += b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 120, 16) + bytes.fromhex("20010db8000000000000000000000001")
    assert gw.parse_answer_addresses(aaaa) == [("2001:db8::1", 120)]


def test_parse_answer_addresses_ignores_errors_and_truncation():
    query = make_query("example.org")
    nx = bytearray(_answer_reply(query, [("1.2.3.4", 60)]))
    nx[3] = (nx[3] & 0xF0) | gw.RCODE_NXDOMAIN
    assert gw.parse_answer_addresses(bytes(nx)) == []
    assert gw.parse_answer_addresses(_answer_reply(query, [("1.2.3.4", 60)])[:-2]) == []


def test_allow_list_adds_each_address_with_clamped_timeout():
    calls = []
    allow = gw.AddressAllowList(1002, runner=lambda args: calls.append(args) or 0)
    assert allow.add([("93.184.216.34", 300), ("2001:db8::1", 5), ("10.0.0.1", 99999)]) == 3
    adds = [c for c in calls if c[0] == "add"]
    assert adds[0][-2] == "93.184.216.34 timeout 300s" and adds[0][4] == "allow4_1002"
    assert adds[1][-2] == "2001:db8::1 timeout 60s" and adds[1][4] == "allow6_1002"
    assert adds[2][-2] == "10.0.0.1 timeout 3600s"
    # each address is deleted before it is added, so the timeout refreshes
    assert calls[0][0] == "delete"


def test_allowed_answers_feed_the_child_allow_list_but_blocked_answers_do_not(tmp_path):
    seen = []

    class Recorder:
        def add(self, entries):
            seen.extend(entries)
            return len(entries)

    fwd = lambda query, upstream, tcp: _answer_reply(query, [("93.184.216.34", 300)])
    res, _ = resolver(tmp_path, fwd)
    res.allow_list = Recorder()
    res.answer(make_query("example.org"))
    assert seen == [("93.184.216.34", 300)]

    seen.clear()
    res.answer(make_query("www.omegle.com"))
    assert seen == []


def test_nft_rules_drop_child_traffic_except_allowed_addresses():
    rules = render_nft([(1002, 5301, 5401)])
    assert "set allow4_1002 { type ipv4_addr; flags timeout; }" in rules
    assert "meta skuid 1002 ip daddr 127.0.0.0/8 accept" in rules
    assert "meta skuid 1002 ip6 daddr ::1 accept" in rules
    assert "meta skuid 1002 ip daddr @allow4_1002 accept" in rules
    assert "meta skuid 1002 ip6 daddr @allow6_1002 accept" in rules
    # the catch-all drop must come after every accept for that UID
    last_accept = rules.rindex("@allow6_1002 accept")
    assert rules.rindex("meta skuid 1002 drop") > last_accept


def test_config_carries_uid_for_address_allow_list():
    policy = _policy()
    config = render_config(policy, "cleanbrowsing_family", {"kid": 1002})
    kid = next(c for c in config["children"] if c["username"] == "kid")
    teen = next(c for c in config["children"] if c["username"] == "teen")
    assert kid["uid"] == 1002
    assert teen["uid"] is None


def test_without_ipv6_route_children_ipv6_is_refused_and_ipv4_dns_still_redirected():
    rules = render_nft([(1002, 5301, 5401)], ipv6=False)
    assert "meta skuid 1002 meta nfproto ipv6 drop" in rules
    assert "dnat ip6" not in rules
    assert "meta skuid 1002 meta nfproto ipv4 tcp dport { 80, 443 } redirect to :5401" in rules
    assert "meta skuid 1002 drop" in rules
    assert "set allow4_1002 { type ipv4_addr; flags timeout; }" in rules


def test_ipv6_route_detection_reads_default_route(monkeypatch):
    from family_linux.security.web_gateway import has_ipv6_route

    class Result:
        def __init__(self, rc, out):
            self.returncode, self.stdout = rc, out

    class FakeAdapter:
        def __init__(self, out):
            self.out = out

        def run_command(self, cmd):
            return Result(0, self.out)

    assert has_ipv6_route(FakeAdapter("default via 2001:db8::1 dev eth0 proto ra")) is True
    assert has_ipv6_route(FakeAdapter("")) is False


def test_https_record_address_hints_are_learned():
    """Browsers connect to ipv4hint and ipv6hint addresses from an HTTPS record directly."""
    query = make_query("example.com", qtype=65)
    rdata = (
        struct.pack("!H", 1) + b"\x00"  # priority 1, target "." (root)
        + struct.pack("!HH", 1, 2) + b"h2"  # alpn
        + struct.pack("!HH", 4, 8) + bytes([104, 20, 23, 154, 172, 66, 147, 243])  # ipv4hint
        + struct.pack("!HH", 6, 16) + bytes.fromhex("2606470010000000000000006814179a")  # ipv6hint
    )
    reply = query[:2] + struct.pack("!H", 0x8180) + struct.pack("!HHHH", 1, 1, 0, 0) + query[12:]
    reply += b"\xc0\x0c" + struct.pack("!HHIH", 65, 1, 300, len(rdata)) + rdata
    assert gw.parse_answer_addresses(reply) == [
        ("104.20.23.154", 300), ("172.66.147.243", 300), ("2606:4700:1000::6814:179a", 300),
    ]


def test_ech_config_ids_are_learned_from_https_records():
    query = make_query("example.com", qtype=65)
    config_contents = b"\x2a" + b"\x00" * 6  # config_id 42, then filler
    ech_config = struct.pack("!HH", 0xFE0D, len(config_contents)) + config_contents
    ech_list = struct.pack("!H", len(ech_config)) + ech_config
    rdata = struct.pack("!H", 1) + b"\x00" + struct.pack("!HH", 5, len(ech_list)) + ech_list
    reply = query[:2] + struct.pack("!H", 0x8180) + struct.pack("!HHHH", 1, 1, 0, 0) + query[12:]
    reply += b"\xc0\x0c" + struct.pack("!HHIH", 65, 1, 300, len(rdata)) + rdata
    assert gw.parse_answer_ech_config_ids(reply) == [(42, 300)]
