"""Tests for family-ctl administration command-line interface."""

import argparse
import json
import platform
from pathlib import Path
import pytest

from family_linux.audit.logger import AuditLogger
from family_linux.cli.family_ctl import FamilyCtl
from family_linux.config import PolicyConfigManager
from family_linux.models import FamilyPolicy, ParentAccount, ChildAccount, AgeTier
from family_linux.screentime.tracker import ScreenTimeTracker




def test_cli_status(test_ctl: FamilyCtl, capsys):
    test_ctl.cmd_status()
    captured = capsys.readouterr().out
    assert "FAMILY LINUX SYSTEM STATUS" in captured
    assert "parent" in captured
    assert "alice" in captured


@pytest.mark.skipif(platform.system() == "Linux", reason="live checks run on Linux; this test covers other hosts")
def test_cli_verify_is_incomplete_off_linux(test_ctl: FamilyCtl, capsys):
    test_ctl.cmd_verify()
    captured = capsys.readouterr().out
    assert "[INCOMPLETE]" in captured
    assert "[SUCCESS]" not in captured
    assert "[SKIP]" in captured


def test_cli_user_add_disable_enable(test_ctl: FamilyCtl):
    # Add child
    args_add = argparse.Namespace(
        user_action="add",
        username="benny",
        name="Benny Arnold",
        tier="pre_teen",
        password="PassWord1",
    )
    test_ctl.cmd_user(args_add)
    policy = test_ctl.config_manager.load_policy()
    assert any(c.username == "benny" for c in policy.children)

    # Disable child
    args_dis = argparse.Namespace(user_action="disable", username="benny")
    test_ctl.cmd_user(args_dis)
    policy = test_ctl.config_manager.load_policy()
    benny = next(c for c in policy.children if c.username == "benny")
    assert benny.enabled is False

    # Enable child
    args_en = argparse.Namespace(user_action="enable", username="benny")
    test_ctl.cmd_user(args_en)
    policy = test_ctl.config_manager.load_policy()
    benny = next(c for c in policy.children if c.username == "benny")
    assert benny.enabled is True


def test_cli_app_approve_and_revoke(test_ctl: FamilyCtl):
    args_appr = argparse.Namespace(app_action="approve", username="alice", app="blender")
    test_ctl.cmd_app(args_appr)

    policy = test_ctl.config_manager.load_policy()
    alice = next(c for c in policy.children if c.username == "alice")
    assert "blender" in alice.app_policy.approved_apps

    args_rev = argparse.Namespace(app_action="revoke", username="alice", app="blender")
    test_ctl.cmd_app(args_rev)

    policy = test_ctl.config_manager.load_policy()
    alice = next(c for c in policy.children if c.username == "alice")
    assert "blender" not in alice.app_policy.approved_apps


def test_cli_web_block_and_allow(test_ctl: FamilyCtl):
    args_blk = argparse.Namespace(web_action="block", domain="distraction.net", child=None)
    test_ctl.cmd_web(args_blk)

    policy = test_ctl.config_manager.load_policy()
    alice = policy.children[0]
    assert "distraction.net" in alice.web_filter.blocked_domains

    args_alw = argparse.Namespace(web_action="allow", domain="distraction.net", child=None)
    test_ctl.cmd_web(args_alw)

    policy = test_ctl.config_manager.load_policy()
    alice = policy.children[0]
    assert "distraction.net" in alice.web_filter.allowed_domains
    assert "distraction.net" not in alice.web_filter.blocked_domains


def test_cli_time_set(test_ctl: FamilyCtl):
    args_time = argparse.Namespace(
        time_action="set",
        username="alice",
        daily_limit=45,
        bedtime_weekday="19:30",
        bedtime_weekend=None,
        wake_time=None,
    )
    test_ctl.cmd_time(args_time)

    policy = test_ctl.config_manager.load_policy()
    alice = policy.children[0]
    assert alice.time_limits.daily_limit_minutes == 45
    assert alice.time_limits.bedtime_weekday == "19:30"


def test_cli_web_rules_can_target_one_child(test_ctl: FamilyCtl, capsys):
    policy = test_ctl.config_manager.load_policy()
    policy.children.append(ChildAccount.create("bob", "Bob", age_tier=AgeTier.TEEN, password="BobPass123"))
    test_ctl.config_manager.save_policy(policy)

    test_ctl.cmd_web(argparse.Namespace(web_action="block", domain="games.example", child="bob"))
    policy = test_ctl.config_manager.load_policy()
    alice = next(c for c in policy.children if c.username == "alice")
    bob = next(c for c in policy.children if c.username == "bob")
    assert "games.example" in bob.web_filter.blocked_domains
    assert "games.example" not in alice.web_filter.blocked_domains


def test_cli_web_approve_allows_request_for_one_child(test_ctl: FamilyCtl, tmp_path, monkeypatch):
    import family_linux.cli.family_ctl as family_ctl_module
    from family_linux.security.dns_gateway import RequestLog

    requests_file = tmp_path / "web-requests.json"
    monkeypatch.setattr(family_ctl_module, "REQUESTS_PATH", requests_file)

    log = RequestLog(requests_file)
    log.record("alice", "omegle.com", "blocked by parent rule")
    log.flush()

    test_ctl.cmd_web(argparse.Namespace(web_action="approve", child="alice", domain="omegle.com"))

    policy = test_ctl.config_manager.load_policy()
    alice = policy.children[0]
    assert "omegle.com" in alice.web_filter.allowed_domains
    assert "omegle.com" not in alice.web_filter.blocked_domains
    assert "omegle.com" not in json.loads(requests_file.read_text()).get("alice", {})


def test_cli_web_requests_lists_pending(test_ctl: FamilyCtl, tmp_path, monkeypatch, capsys):
    import family_linux.cli.family_ctl as family_ctl_module
    from family_linux.security.dns_gateway import RequestLog

    requests_file = tmp_path / "web-requests.json"
    monkeypatch.setattr(family_ctl_module, "REQUESTS_PATH", requests_file)
    log = RequestLog(requests_file)
    log.record("alice", "tiktok.com", "blocked by parent rule")
    log.flush()

    test_ctl.cmd_web(argparse.Namespace(web_action="requests"))
    out = capsys.readouterr().out
    assert "tiktok.com" in out and "alice" in out


def test_cli_remove_signs_out_deletes_and_reapplies_rules(test_ctl: FamilyCtl):
    test_ctl.cmd_user(argparse.Namespace(user_action="remove", username="alice"))

    cmds = test_ctl.adapter.executed_commands
    lock = cmds.index(["usermod", "-L", "alice"])
    stop = cmds.index(["loginctl", "terminate-user", "alice"])
    delete = cmds.index(["userdel", "alice"])
    assert lock < stop < delete
    # The web filter is rewritten without the child, so no stale rule names their UID
    assert any(c[:2] == ["nft", "-f"] for c in cmds[delete:])
    assert not test_ctl.config_manager.load_policy().children


def test_cli_remove_keeps_a_child_that_could_not_be_deleted(test_ctl: FamilyCtl, capsys):
    # Before the fix, a failed userdel (the child still signed in) was ignored: the child left the
    # policy, and the next web apply dropped their filter while the account still worked.
    from family_linux.security.adapter import CommandResult

    real_run = test_ctl.adapter.run_command

    def run(cmd, check=False):
        if cmd[0] == "userdel":
            test_ctl.adapter.executed_commands.append(cmd)
            return CommandResult(command=cmd, returncode=8, stdout="", stderr="user alice is currently used by process 42")
        return real_run(cmd, check)

    test_ctl.adapter.run_command = run
    with pytest.raises(SystemExit):
        test_ctl.cmd_user(argparse.Namespace(user_action="remove", username="alice"))
    assert [c.username for c in test_ctl.config_manager.load_policy().children] == ["alice"]
    assert "Could not delete" in capsys.readouterr().err
