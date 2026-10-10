"""Tests for Family Linux screen time tracking and curfew enforcement."""

from datetime import datetime
from pathlib import Path
import pytest

from family_linux.models import ChildAccount, TimeLimitPolicy
from family_linux.screentime.tracker import ScreenTimeTracker
from family_linux.screentime.daemon import ScreenTimeDaemon
from family_linux.security.adapter import SystemAdapter
from family_linux.audit.logger import AuditLogger
from family_linux.config import PolicyConfigManager
from family_linux.models import FamilyPolicy, ParentAccount


def test_tracker_increments_and_resets(tmp_path: Path):
    usage_file = tmp_path / "screentime.json"
    tracker = ScreenTimeTracker(usage_file=usage_file)

    now = datetime(2026, 10, 10, 14, 0, 0)  # 2:00 PM
    assert tracker.get_minutes_used("alice", now=now) == 0

    tracker.add_minutes_used("alice", 30, now=now)
    assert tracker.get_minutes_used("alice", now=now) == 30

    tracker.add_minutes_used("alice", 45, now=now)
    assert tracker.get_minutes_used("alice", now=now) == 75

    tracker.reset_usage("alice")
    assert tracker.get_minutes_used("alice", now=now) == 0


def test_tracker_evaluates_curfew_and_quota(tmp_path: Path):
    usage_file = tmp_path / "screentime.json"
    tracker = ScreenTimeTracker(usage_file=usage_file)

    child = ChildAccount.create("alice", "Alice")
    child.time_limits.daily_limit_minutes = 60
    child.time_limits.bedtime_weekday = "20:00"
    child.time_limits.wake_time = "07:00"

    # Daytime with remaining quota: allowed
    daytime = datetime(2026, 10, 12, 15, 0, 0)  # Monday 3:00 PM
    allowed, reason, remaining = tracker.evaluate_limits(child, now=daytime)
    assert allowed is True
    assert remaining == 60

    # Exhaust quota
    tracker.add_minutes_used("alice", 60, now=daytime)
    allowed, reason, remaining = tracker.evaluate_limits(child, now=daytime)
    assert allowed is False
    assert "limit reached" in reason.lower()

    # Past bedtime curfew
    nighttime = datetime(2026, 10, 12, 21, 0, 0)  # Monday 9:00 PM
    allowed, reason, remaining = tracker.evaluate_limits(child, now=nighttime)
    assert allowed is False
    assert "curfew active" in reason.lower()


def test_daemon_one_shot_cycle(tmp_path: Path):
    cfg_file = tmp_path / "policy.yaml"
    usage_file = tmp_path / "screentime.json"
    audit_file = tmp_path / "audit.log"

    cfg_mgr = PolicyConfigManager(config_path=cfg_file)
    tracker = ScreenTimeTracker(usage_file=usage_file)
    audit = AuditLogger(log_path=audit_file)
    adapter = SystemAdapter(dry_run=True)

    parent = ParentAccount(username="parent", full_name="Parent", sudo_access=True)
    child = ChildAccount.create("bobby", "Bobby")
    child.time_limits.daily_limit_minutes = 10
    policy = FamilyPolicy(parent=parent, children=[child])
    cfg_mgr.save_policy(policy)

    daemon = ScreenTimeDaemon(config_manager=cfg_mgr, tracker=tracker, adapter=adapter, audit_logger=audit)

    # Mock logged in user Bobby
    daemon.get_logged_in_users = lambda: ["bobby"]

    # First cycle adds 5 mins
    daemon.check_and_enforce_cycle(active_minutes_step=5)
    assert tracker.get_minutes_used("bobby") == 5

    # Second cycle adds 6 mins (total 11 > 10 quota) -> should terminate user session
    daemon.check_and_enforce_cycle(active_minutes_step=6)
    assert tracker.get_minutes_used("bobby") == 11

    cmds = [" ".join(c) for c in adapter.executed_commands]
    assert any("terminate-user bobby" in c for c in cmds)
