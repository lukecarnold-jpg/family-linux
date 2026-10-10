"""HTTP-level tests for the parent dashboard: authentication, host and origin checks, input rules."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import pytest

from family_linux.audit.logger import AuditLogger
from family_linux.config import PolicyConfigManager
from family_linux.parent_ui.server import SESSION_COOKIE, make_handler
from family_linux.provisioner.system import SystemProvisioner
from family_linux.screentime.tracker import ScreenTimeTracker
from family_linux.security.adapter import SystemAdapter
from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount

TOKEN = "test-token-123"


@pytest.fixture
def server(tmp_path: Path):
    config = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    config.save_policy(FamilyPolicy(parent=ParentAccount("parent", "Parent Admin", "ParentPass1!")))
    adapter = SystemAdapter(dry_run=True)
    allowed: set[str] = set()
    handler = make_handler(
        config_manager=config,
        provisioner=SystemProvisioner(adapter=adapter, config_manager=config, audit_logger=AuditLogger(log_path=tmp_path / "audit.log", dry_run=False)),
        tracker=ScreenTimeTracker(usage_file=tmp_path / "usage.json"),
        audit=AuditLogger(log_path=tmp_path / "audit.log"),
        token=TOKEN,
        allowed_hosts=allowed,
    )
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    allowed.add(f"127.0.0.1:{httpd.server_port}")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd, config
    httpd.shutdown()
    httpd.server_close()


def _request(httpd, path, *, method="GET", body=None, headers=None):
    url = f"http://127.0.0.1:{httpd.server_port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read()


AUTH = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def test_api_requires_token(server):
    httpd, _ = server
    status, _, _ = _request(httpd, "/api/policy")
    assert status == 401


def test_wrong_token_is_rejected(server):
    httpd, _ = server
    status, _, _ = _request(httpd, "/api/policy", headers={"Authorization": "Bearer nope"})
    assert status == 401


def test_bearer_token_grants_access(server):
    httpd, _ = server
    status, _, body = _request(httpd, "/api/policy", headers={"Authorization": f"Bearer {TOKEN}"})
    assert status == 200
    assert json.loads(body)["parent"]["username"] == "parent"


def test_policy_api_never_returns_passwords(server):
    httpd, _ = server
    _, _, body = _request(httpd, "/api/policy", headers={"Authorization": f"Bearer {TOKEN}"})
    assert b"ParentPass1!" not in body


def test_link_token_sets_http_only_cookie_and_redirects(server):
    import http.client

    httpd, _ = server
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_port)
    conn.request("GET", f"/?token={TOKEN}", headers={"Host": f"127.0.0.1:{httpd.server_port}"})
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 303
    assert resp.getheader("Location") == "/"
    cookie = resp.getheader("Set-Cookie", "")
    assert f"{SESSION_COOKIE}={TOKEN}" in cookie
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_wrong_link_token_gets_no_cookie(server):
    import http.client

    httpd, _ = server
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_port)
    conn.request("GET", "/?token=wrong", headers={"Host": f"127.0.0.1:{httpd.server_port}"})
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 401
    assert resp.getheader("Set-Cookie") is None


def test_cookie_session_grants_access(server):
    httpd, _ = server
    status, _, _ = _request(httpd, "/api/policy", headers={"Cookie": f"{SESSION_COOKIE}={TOKEN}"})
    assert status == 200


def test_bad_host_header_is_rejected(server):
    httpd, _ = server
    status, _, _ = _request(httpd, "/api/policy", headers={"Host": "evil.example", "Authorization": f"Bearer {TOKEN}"})
    assert status == 403


def test_post_requires_json_content_type(server):
    httpd, _ = server
    status, _, _ = _request(
        httpd, "/api/web/block", method="POST", body={"domain": "x.com"},
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "text/plain"},
    )
    assert status == 415


def test_cross_origin_post_is_rejected(server):
    httpd, _ = server
    status, _, _ = _request(
        httpd, "/api/web/block", method="POST", body={"domain": "x.com"},
        headers={**AUTH, "Origin": "https://attacker.example"},
    )
    assert status == 403


def test_same_origin_post_is_accepted(server):
    httpd, _ = server
    status, _, _ = _request(
        httpd, "/api/backup", method="POST", body={},
        headers={**AUTH, "Origin": f"http://127.0.0.1:{httpd.server_port}"},
    )
    assert status == 200


def test_unauthenticated_post_changes_nothing(server):
    httpd, config = server
    status, _, _ = _request(httpd, "/api/child", method="POST", body={"username": "kid", "password": "KidPass123"},
                            headers={"Content-Type": "application/json"})
    assert status == 401
    assert [c.username for c in config.load_policy().children] == []


def test_short_child_password_is_rejected(server):
    httpd, config = server
    status, _, body = _request(httpd, "/api/child", method="POST",
                               body={"username": "kidtest", "password": "short"}, headers=AUTH)
    assert status == 400
    assert b"at least 8" in body
    assert config.load_policy().children == []


def test_invalid_json_body_is_400(server):
    httpd, _ = server
    status, _, _ = _request(httpd, "/api/backup", method="POST", headers=AUTH)
    # Empty body is treated as {} and succeeds; a malformed body must fail.
    assert status == 200
    url = f"http://127.0.0.1:{httpd.server_port}/api/backup"
    req = urllib.request.Request(url, data=b"{not json", method="POST", headers=AUTH)
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 400


def test_oversized_body_is_413(server):
    httpd, _ = server
    url = f"http://127.0.0.1:{httpd.server_port}/api/backup"
    req = urllib.request.Request(url, data=b"{}" + b" " * (70 * 1024), method="POST", headers=AUTH)
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 413


def test_requests_and_approval_endpoints(tmp_path: Path):
    import threading as _threading
    from family_linux.security.dns_gateway import RequestLog

    config = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    policy = FamilyPolicy(parent=ParentAccount("parent", "Parent Admin", "ParentPass1!"),
                          children=[ChildAccount.create("kid", "Kid", "pre_teen", password="KidPass123!")])
    config.save_policy(policy)
    requests_file = tmp_path / "web-requests.json"
    log = RequestLog(requests_file)
    log.record("kid", "tiktok.com", "blocked by parent rule")
    log.flush()

    allowed: set[str] = set()
    handler = make_handler(
        config_manager=config,
        provisioner=SystemProvisioner(adapter=SystemAdapter(dry_run=True), config_manager=config,
                                      audit_logger=AuditLogger(log_path=tmp_path / "audit.log")),
        tracker=ScreenTimeTracker(usage_file=tmp_path / "usage.json"),
        audit=AuditLogger(log_path=tmp_path / "audit.log"),
        token=TOKEN,
        allowed_hosts=allowed,
        requests_path=requests_file,
    )
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    allowed.add(f"127.0.0.1:{httpd.server_port}")
    thread = _threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = _request(httpd, "/api/web/requests", headers={"Authorization": f"Bearer {TOKEN}"})
        assert status == 200
        assert "tiktok.com" in json.loads(body)["kid"]

        status, _, _ = _request(httpd, "/api/web/approve", method="POST",
                                body={"username": "kid", "domain": "tiktok.com"}, headers=AUTH)
        assert status == 200
        kid = config.load_policy().children[0]
        assert "tiktok.com" in kid.web_filter.allowed_domains
        assert "tiktok.com" not in json.loads(requests_file.read_text()).get("kid", {})

        status, _, _ = _request(httpd, "/api/web/approve", method="POST",
                                body={"username": "nobody", "domain": "x.com"}, headers=AUTH)
        assert status == 400
    finally:
        httpd.shutdown()
        httpd.server_close()
