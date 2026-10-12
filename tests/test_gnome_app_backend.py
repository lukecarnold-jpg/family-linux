"""Family Controls (GNOME app): the family-ctl calls behind the interface, and the CLI commands it uses.
The GTK interface itself is exercised in an Ubuntu container (see DEV_HIST)."""

import argparse
import json
import subprocess

import pytest
import yaml

from family_linux.gnome_app.backend import (
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
    assert approved_entries_for("org.gnome.Calculator", ["org.gnome.Calculator", "vlc"]) == ["org.gnome.Calculator"]


def test_demo_client_serves_the_file_and_accepts_changes(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"policy": {"children": []}}))
    demo = DemoClient(path)
    assert demo.state()["policy"]["children"] == []
    assert demo.block("kid", "example.com").ok


# CLI commands the app depends on

from tests.test_cli import test_ctl  # noqa: E402,F401  (fixture)


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
    from family_linux.provisioner.autoinstall import SubiquityAutoinstallGenerator
    from family_linux.security.app_guard import AppGuard
    from family_linux.security.adapter import SystemAdapter

    text = SubiquityAutoinstallGenerator(FamilyPolicy(parent=ParentAccount("parent", "P", password="Correct-Horse-42-Battery"))).generate_user_data(locale="en_US.UTF-8", keyboard_layout="us")
    auto = yaml.safe_load(text.split("\n", 1)[1])["autoinstall"]
    assert {"python3-gi", "gir1.2-gtk-4.0", "gir1.2-adw-1"} <= set(auto["packages"])
    # App Centre from apt. Firefox is a snap, installed by the first-boot apply (not the apt list).
    assert {"gnome-software", "gnome-software-plugin-snap"} <= set(auto["packages"])
    assert "firefox" not in auto["packages"]
    commands = "\n".join(auto["late-commands"])
    for target in ("/usr/local/bin/family-linux-parent", "/usr/share/applications/org.familylinux.Parent.desktop",
                   "/usr/share/polkit-1/actions/org.familylinux.manage.policy"):
        assert target in commands

    assert "org.familylinux.parent" in ALWAYS_BLOCKED_COMMANDS
    child = ChildAccount.create("kid", "Kid", "teen")
    child.app_policy.approved_apps.append("org.familylinux.Parent")  # even if a parent approves it
    assert not AppGuard(SystemAdapter(dry_run=True)).is_app_allowed(child, "org.familylinux.Parent.desktop")


def test_app_centre_is_visible_to_children_and_approved_by_default():
    from family_linux.models import ALWAYS_BLOCKED_COMMANDS, DEFAULT_APPROVED_APPS, AgeTier

    assert "org.gnome.Software" not in ALWAYS_BLOCKED_COMMANDS
    for tier in AgeTier:
        assert "org.gnome.Software" in DEFAULT_APPROVED_APPS[tier.value]


@pytest.mark.parametrize("desktop_id", ["org.gnome.Terminal", "org.gnome.Settings", "snap-store_snap-store"])
def test_ubuntu_system_tools_cannot_be_approved_for_a_child(desktop_id):
    # The always-blocked list held command names; Ubuntu 24.04 menus use these desktop IDs.
    from family_linux.models import ChildAccount
    from family_linux.security.app_guard import AppGuard
    from family_linux.security.adapter import SystemAdapter

    child = ChildAccount.create("kid", "Kid", "teen")
    child.app_policy.approved_apps.append(desktop_id)
    assert not AppGuard(SystemAdapter(dry_run=True)).is_app_allowed(child, desktop_id + ".desktop")


UBUNTU_RELEASE_UPGRADES = """[DEFAULT]
# Default prompting and upgrade behavior, valid options:
#  never  - Never check for, or allow upgrading to, a new release.
Prompt=lts
"""


def test_release_upgrade_notice_is_turned_off_keeping_the_rest_of_the_file(tmp_path):
    # Seen in VirtualBox: "Ubuntu 26.04.1 LTS Upgrade Available" opened on the desktop.
    from family_linux.security.adapter import SystemAdapter
    from family_linux.security.release_upgrades import disable_release_upgrade_prompt, prompt_is_off, with_prompt_never

    path = tmp_path / "release-upgrades"
    path.write_text(UBUNTU_RELEASE_UPGRADES)
    adapter = SystemAdapter(dry_run=True)
    disable_release_upgrade_prompt(adapter, path)
    written = adapter.simulated_files[str(path)]
    assert prompt_is_off(written) and "Prompt=lts" not in written
    assert "# Default prompting" in written

    path.write_text(written)
    adapter = SystemAdapter(dry_run=True)
    disable_release_upgrade_prompt(adapter, path)
    assert str(path) not in adapter.simulated_files  # already off: no rewrite
    assert prompt_is_off(with_prompt_never(""))
    assert not prompt_is_off(UBUNTU_RELEASE_UPGRADES)
