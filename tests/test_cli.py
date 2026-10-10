"""Tests for family-ctl administration command-line interface."""

import argparse
from pathlib import Path
import pytest

from family_linux.cli.family_ctl import FamilyCtl
from family_linux.config import PolicyConfigManager
from family_linux.models import FamilyPolicy, ParentAccount, ChildAccount, AgeTier


@pytest.fixture
def test_ctl(tmp_path: Path):
    cfg_file = tmp_path / "policy.yaml"
    mgr = PolicyConfigManager(config_path=cfg_file)
    parent = ParentAccount(username="parent", full_name="Parent Admin", sudo_access=True)
    child = ChildAccount.create("alice", "Alice", age_tier=AgeTier.YOUNG_CHILD)
    policy = FamilyPolicy(parent=parent, children=[child])
    mgr.save_policy(policy)

    return FamilyCtl(config_path=str(cfg_file), dry_run=False)


def test_cli_status(test_ctl: FamilyCtl, capsys):
    test_ctl.cmd_status()
    captured = capsys.readouterr().out
    assert "FAMILY LINUX SYSTEM STATUS" in captured
    assert "parent" in captured
    assert "alice" in captured


def test_cli_verify(test_ctl: FamilyCtl, capsys):
    test_ctl.cmd_verify()
    captured = capsys.readouterr().out
    assert "[SUCCESS] System complies 100%" in captured


def test_cli_user_add_disable_enable(test_ctl: FamilyCtl):
    # Add child
    args_add = argparse.Namespace(
        user_action="add",
        username="benny",
        name="Benny Arnold",
        tier="pre_teen",
        password="Pass",
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
    args_blk = argparse.Namespace(web_action="block", domain="distraction.net")
    test_ctl.cmd_web(args_blk)

    policy = test_ctl.config_manager.load_policy()
    alice = policy.children[0]
    assert "distraction.net" in alice.web_filter.blocked_domains

    args_alw = argparse.Namespace(web_action="allow", domain="distraction.net")
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
