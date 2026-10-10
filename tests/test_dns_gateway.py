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
    rules = render_nft([(1002, 5301), (1003, 5302)])
    assert "meta skuid 1002 udp dport 53 redirect to :5301" in rules
    assert "meta skuid 1002 tcp dport 53 redirect to :5301" in rules
    assert "meta skuid 1003 tcp dport 53 redirect to :5302" in rules
    assert "meta skuid 1002 tcp dport 853 drop" in rules
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
