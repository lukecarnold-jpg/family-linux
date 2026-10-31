"""Family Controls (KDE app): the family-ctl calls behind the interface, and the CLI commands it uses.
The Qt window itself is exercised in test_kde_app_window.py."""

import argparse
import json
import subprocess

import pytest
import yaml

from family_linux.kde_app.backend import (
    BackendError,
    DemoClient,
    FamilyCtlClient,
    approved_entries_for,
    normalise_domain,
    valid_clock,
    valid_username,
)


class FakeRunner:
    def __init__(self, returncode=0, stdout="[OK] Done.\n", stderr=""):
        self.calls = []
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    def __call__(self, cmd, stdin):
        self.calls.append((cmd, stdin))
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


def test_every_call_goes_through_pkexec_and_family_ctl(monkeypatch):
    monkeypatch.delenv("FAMILY_LINUX_CTL_COMMAND", raising=False)
    runner = FakeRunner()
    FamilyCtlClient(runner).block("kid", "example.com")
    assert runner.calls[0][0] == ["/usr/bin/pkexec", "/usr/local/sbin/family-ctl", "web", "block", "example.com", "--child", "kid"]


def test_child_password_is_sent_on_stdin_not_the_command_line():
    runner = FakeRunner()
    FamilyCtlClient(runner, command=["family-ctl"]).add_child("sam", "Sam", "pre_teen", "secret-pass-1")
    cmd, stdin = runner.calls[0]
    assert "secret-pass-1" not in " ".join(cmd)
    assert "--password-stdin" in cmd
    assert stdin == "secret-pass-1\n"


@pytest.mark.parametrize("code, expected", [(126, "cancelled"), (127, "Only the parent")])
def test_polkit_refusals_are_explained(code, expected):
    result = FamilyCtlClient(FakeRunner(returncode=code, stdout=""), command=["x"]).remove_child("kid")
    assert not result.ok and expected in result.message


def test_family_ctl_errors_are_shown_without_the_prefix():
    runner = FakeRunner(returncode=1, stdout="[ERROR] Child user 'zed' not found.\n")
    result = FamilyCtlClient(runner, command=["x"]).set_enabled("zed", False)
    assert result == result.__class__(False, "Child user 'zed' not found.")


def test_state_is_parsed_and_failures_raise():
    state = {"policy": {"children": []}, "requests": {}, "usage_today": {}, "apps": []}
    assert FamilyCtlClient(FakeRunner(stdout=json.dumps(state)), command=["x"]).state() == state
    with pytest.raises(BackendError, match="cancelled"):
        FamilyCtlClient(FakeRunner(returncode=126, stdout=""), command=["x"]).state()
    with pytest.raises(BackendError):
        FamilyCtlClient(FakeRunner(stdout="not json"), command=["x"]).state()


def test_revoking_an_app_removes_every_entry_that_shows_it():
    runner = FakeRunner()
    FamilyCtlClient(runner, command=["x"]).revoke_app("kid", "firefox_firefox", ["firefox", "vlc"])
    assert [c[0][1:] for c in runner.calls] == [["app", "revoke", "kid", "firefox"]]


def test_development_override_replaces_the_command(monkeypatch):
    monkeypatch.setenv("FAMILY_LINUX_CTL_COMMAND", "python3 -m family_linux.cli.family_ctl --dry-run")
    runner = FakeRunner()
    FamilyCtlClient(runner).reset_usage("kid")
    assert runner.calls[0][0][:4] == ["python3", "-m", "family_linux.cli.family_ctl", "--dry-run"]


@pytest.mark.parametrize("typed, expected", [
    ("Example.com", "example.com"),
    ("https://www.YouTube.com/watch?v=1", "www.youtube.com"),
    ("*.games.example", "*.games.example"),
    ("not a site", None),
    ("localhost", None),
    ("", None),
])
def test_typed_websites_are_normalised(typed, expected):
    assert normalise_domain(typed) == expected


def test_input_checks():
    assert valid_username("sam") and not valid_username("Sam") and not valid_username("x")
    assert valid_clock("20:30") and valid_clock("07:00") and not valid_clock("8pm") and not valid_clock("24:00")
    assert approved_entries_for("org.kde.kcalc", ["org.kde.kcalc", "vlc"]) == ["org.kde.kcalc"]


def test_demo_client_serves_the_file_and_accepts_changes(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"policy": {"children": []}}))
    demo = DemoClient(path)
    assert demo.state()["policy"]["children"] == []
    assert demo.block("kid", "example.com").ok


# CLI commands the app depends on

# test_ctl fixture: tests/conftest.py


def test_state_command_prints_json_without_passwords(test_ctl, capsys):
    test_ctl.cmd_state()
    state = json.loads(capsys.readouterr().out)
    assert [c["username"] for c in state["policy"]["children"]] == ["alice"]
    assert set(state) == {"policy", "requests", "usage_today", "apps"}
    assert "password" not in json.dumps(state["policy"])
    assert state["usage_today"] == {"alice": 0}


def test_add_child_reads_the_password_from_stdin(test_ctl, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin-123\n"))
    args = argparse.Namespace(user_action="add", username="sam", name="Sam", tier="teen", password=None, password_stdin=True)
    test_ctl.cmd_user(args)
    assert any(c.username == "sam" for c in test_ctl.config_manager.load_policy().children)


def test_web_remove_clears_both_lists(test_ctl):
    test_ctl.cmd_web(argparse.Namespace(web_action="block", domain="games.example", child="alice"))
    test_ctl.cmd_web(argparse.Namespace(web_action="remove", domain="games.example", child="alice"))
    alice = test_ctl.config_manager.load_policy().children[0]
    assert "games.example" not in alice.web_filter.blocked_domains
    assert "games.example" not in alice.web_filter.allowed_domains


def test_the_app_is_installed_and_never_shown_to_children():
    from family_linux.models import ALWAYS_BLOCKED_COMMANDS, ChildAccount, FamilyPolicy, ParentAccount
    from family_linux.provisioner.preseed import PACKAGES, DebianPreseedGenerator
    from family_linux.security.app_guard import AppGuard
    from family_linux.security.adapter import SystemAdapter

    script = DebianPreseedGenerator(FamilyPolicy(parent=ParentAccount("parent", "P", password="Correct-Horse-42-Battery"))).generate_late_script()
    assert {"python3-pyqt6"} <= set(PACKAGES)
    for target in ("/usr/local/bin/family-linux-parent", "/usr/share/applications/org.familylinux.Parent.desktop",
                   "/usr/share/polkit-1/actions/org.familylinux.manage.policy"):
        assert target in script

    assert "org.familylinux.parent" in ALWAYS_BLOCKED_COMMANDS
    child = ChildAccount.create("kid", "Kid", "teen")
    child.app_policy.approved_apps.append("org.familylinux.Parent")  # even if a parent approves it
    assert not AppGuard(SystemAdapter(dry_run=True)).is_app_allowed(child, "org.familylinux.Parent.desktop")


def test_app_store_is_visible_to_children_and_approved_by_default():
    from family_linux.models import ALWAYS_BLOCKED_COMMANDS, DEFAULT_APPROVED_APPS, AgeTier

    assert "org.kde.discover" not in ALWAYS_BLOCKED_COMMANDS
    for tier in AgeTier:
        assert "org.kde.discover" in DEFAULT_APPROVED_APPS[tier.value]


@pytest.mark.parametrize("desktop_id", ["org.kde.konsole", "org.kde.yakuake", "org.kde.systemsettings", "konsole"])
def test_terminals_and_settings_cannot_be_approved_for_a_child(desktop_id):
    # The always-blocked list holds the Debian and KDE desktop IDs for terminals and settings.
    from family_linux.models import ChildAccount
    from family_linux.security.app_guard import AppGuard
    from family_linux.security.adapter import SystemAdapter

    child = ChildAccount.create("kid", "Kid", "teen")
    child.app_policy.approved_apps.append(desktop_id)
    assert not AppGuard(SystemAdapter(dry_run=True)).is_app_allowed(child, desktop_id + ".desktop")


