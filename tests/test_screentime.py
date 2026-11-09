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


def _child_with_bedtime(bedtime: str) -> ChildAccount:
    child = ChildAccount.create("alice", "Alice")
    child.time_limits.daily_limit_minutes = 600
    child.time_limits.bedtime_weekday = bedtime
    child.time_limits.bedtime_weekend = bedtime
    child.time_limits.wake_time = "07:00"
    return child


def test_bedtime_after_midnight_allows_the_evening(tmp_path: Path):
    # Before the fix, a 00:30 bedtime locked the child out all day ("00:30 to 07:00" read as all day).
    tracker = ScreenTimeTracker(usage_file=tmp_path / "usage.json")
    child = _child_with_bedtime("00:30")

    allowed, _, _ = tracker.evaluate_limits(child, now=datetime(2026, 10, 12, 15, 0))  # Monday afternoon
    assert allowed is True
    allowed, _, remaining = tracker.evaluate_limits(child, now=datetime(2026, 10, 12, 23, 50))
    assert allowed is True and remaining == 40
    # Just after midnight: still last evening, 20 minutes until bedtime
    allowed, _, remaining = tracker.evaluate_limits(child, now=datetime(2026, 10, 13, 0, 10))
    assert allowed is True and remaining == 20
    for hour, minute in ((0, 30), (3, 0), (6, 59)):
        allowed, reason, _ = tracker.evaluate_limits(child, now=datetime(2026, 10, 13, hour, minute))
        assert allowed is False and "curfew" in reason.lower()
    allowed, _, _ = tracker.evaluate_limits(child, now=datetime(2026, 10, 13, 7, 0))
    assert allowed is True


def test_bedtime_before_midnight_counts_down_and_locks_until_wake(tmp_path: Path):
    tracker = ScreenTimeTracker(usage_file=tmp_path / "usage.json")
    child = _child_with_bedtime("20:00")
    allowed, _, remaining = tracker.evaluate_limits(child, now=datetime(2026, 10, 12, 19, 45))
    assert allowed is True and remaining == 15
    for when in (datetime(2026, 10, 12, 20, 0), datetime(2026, 10, 13, 0, 10), datetime(2026, 10, 13, 6, 59)):
        assert tracker.evaluate_limits(child, now=when)[0] is False


def test_weekend_bedtime_applies_to_friday_night_after_midnight(tmp_path: Path):
    tracker = ScreenTimeTracker(usage_file=tmp_path / "usage.json")
    child = _child_with_bedtime("21:00")
    child.time_limits.bedtime_weekend = "01:00"
    # Saturday 00:30 belongs to Friday night, which uses the weekend bedtime
    assert tracker.evaluate_limits(child, now=datetime(2026, 10, 17, 0, 30))[0] is True
    # Monday 00:30 belongs to Sunday night, which uses the weekday bedtime (21:00)
    assert tracker.evaluate_limits(child, now=datetime(2026, 10, 19, 0, 30))[0] is False


@pytest.mark.parametrize("field,value", [
    ("bedtime_weekday", "25:99"),
    ("bedtime_weekend", "banana"),
    ("wake_time", "7:00"),
    ("daily_limit_minutes", -5),
    ("daily_limit_minutes", 2000),
    ("warning_minutes", [0]),
])
def test_invalid_time_limits_are_not_saved(tmp_path: Path, field, value):
    cfg_mgr = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    child = ChildAccount.create("bobby", "Bobby")
    setattr(child.time_limits, field, value)
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True), children=[child])
    assert policy.validate()
    with pytest.raises(ValueError):
        cfg_mgr.save_policy(policy)


def _daemon_for(tmp_path: Path, policy: FamilyPolicy):
    cfg_mgr = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    cfg_mgr.load_policy = lambda: policy  # an invalid policy cannot be saved, so hand it over directly
    tracker = ScreenTimeTracker(usage_file=tmp_path / "usage.json")
    adapter = SystemAdapter(dry_run=True)
    daemon = ScreenTimeDaemon(
        config_manager=cfg_mgr, tracker=tracker, adapter=adapter, audit_logger=AuditLogger(log_path=tmp_path / "audit.log")
    )
    return daemon, tracker, adapter


def test_one_childs_bad_bedtime_does_not_stop_the_others(tmp_path: Path):
    # Before the fix, "25:99" raised ValueError and the whole cycle stopped, so the next child
    # was never counted or signed out. Validation now refuses such values; this policy skips it.
    broken = ChildAccount.create("alice", "Alice")
    broken.time_limits.wake_time = "banana"
    sibling = ChildAccount.create("bobby", "Bobby")
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True), children=[broken, sibling])
    daemon, tracker, _ = _daemon_for(tmp_path, policy)
    daemon.get_logged_in_users = lambda: ["alice", "bobby"]

    daemon.check_and_enforce_cycle(active_minutes_step=1)

    assert tracker.get_minutes_used("bobby") == 1
    assert any(r.event_type == "TIME_CHECK_FAILED" and r.user == "alice" for r in daemon.audit.get_records())


def test_notification_reaches_the_childs_session_without_a_shell(tmp_path: Path, monkeypatch):
    # Children have /usr/sbin/nologin, so `su - child -c notify-send` never ran.
    from types import SimpleNamespace
    from family_linux.screentime import daemon as daemon_module

    monkeypatch.setattr(daemon_module.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1001))
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True))
    daemon, _, adapter = _daemon_for(tmp_path, policy)

    daemon.send_notification("bobby", "Title", 'Text with "quotes" and $(sign)', urgency="critical")

    cmd = adapter.executed_commands[-1]
    assert cmd[:4] == ["runuser", "-u", "bobby", "--"]
    assert "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus" in cmd
    assert cmd[-2:] == ["Title", 'Text with "quotes" and $(sign)']  # passed as one argument, no shell
    assert "su" not in cmd


def test_warnings_are_given_again_on_a_new_day(tmp_path: Path):
    child = ChildAccount.create("bobby", "Bobby")
    child.time_limits.daily_limit_minutes = 10
    child.time_limits.warning_minutes = [15]
    # Allowed all day (bedtime at the wake time counts as midnight), so the result does not depend
    # on when the test runs (it failed in CI at 04:27 UTC, inside the default bedtime).
    child.time_limits.wake_time = child.time_limits.bedtime_weekday = child.time_limits.bedtime_weekend = "00:00"
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True), children=[child])
    daemon, _, _ = _daemon_for(tmp_path, policy)
    daemon.get_logged_in_users = lambda: ["bobby"]
    sent = []
    daemon.send_notification = lambda *args, **kwargs: sent.append(args)

    daemon.check_and_enforce_cycle()
    daemon.check_and_enforce_cycle()
    assert len(sent) == 1
    from datetime import date
    daemon._warned_day = date(2000, 1, 1)  # as if the last check was on an earlier day
    daemon.check_and_enforce_cycle()
    assert len(sent) == 2


def test_screen_time_service_is_installed_and_started():
    # Before the fix nothing installed family-policyd, so limits were never enforced on an installed system.
    from family_linux.provisioner.system import ALL_LAYERS
    from family_linux.screentime.service import SERVICE_PATH, ScreenTimeService, render_service

    assert "screentime" in ALL_LAYERS
    adapter = SystemAdapter(dry_run=True)
    assert ScreenTimeService(adapter).apply() == []
    assert str(SERVICE_PATH) in adapter.simulated_files
    assert ["systemctl", "enable", "--now", "family-policyd"] in adapter.executed_commands
    unit = render_service("/usr/bin/python3")
    assert "ExecStart=/usr/bin/python3 -m family_linux.screentime.daemon --interval 60" in unit
    assert "WantedBy=multi-user.target" in unit


def test_sign_in_gate_refuses_bedtime_limit_and_turned_off(tmp_path: Path):
    from family_linux.screentime import gate

    cfg = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    tracker = ScreenTimeTracker(usage_file=tmp_path / "usage.json")
    child = ChildAccount.create("bobby", "Bobby")
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True), children=[child])
    cfg.save_policy(policy)

    allowed, _ = gate.check("bobby", cfg, tracker)
    expected, _, _ = tracker.evaluate_limits(child)
    assert allowed is expected  # same answer as the screen time service
    assert gate.check("parent", cfg, tracker)[0] is True

    child.time_limits.daily_limit_minutes = 0
    cfg.save_policy(policy)
    assert gate.check("bobby", cfg, tracker)[0] is False

    child.time_limits.daily_limit_minutes = 600
    child.enabled = False
    cfg.save_policy(policy)
    assert gate.check("bobby", cfg, tracker) == (False, "account turned off by the parent")


def test_sign_in_gate_fails_closed(monkeypatch):
    from family_linux.screentime import gate

    def broken(username):
        raise OSError("policy unreadable")

    monkeypatch.setattr(gate, "check", broken)
    assert gate.pam_main({"PAM_USER": "bobby"}) == 1
    assert gate.pam_main({}) == 1


def test_sddm_pam_gets_the_sign_in_gate():
    from family_linux.security.desktop_lockdown import lockdown_in_place, render_child_kdeglobals, with_pam_block

    pam = with_pam_block("#%PAM-1.0\n@include common-account\n@include common-session\n", python="/usr/bin/python3")
    lines = pam.splitlines()
    gate_line = lines.index("account required pam_exec.so quiet /usr/bin/python3 -m family_linux.screentime.gate")
    assert "notingroup family-children" in lines[gate_line - 1] and lines[gate_line - 1].startswith("account")
    assert gate_line > lines.index("@include common-account")
    assert with_pam_block(pam, python="/usr/bin/python3") == pam


def test_time_is_not_counted_while_the_screen_is_locked(tmp_path: Path):
    child = ChildAccount.create("bobby", "Bobby")
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True), children=[child])
    daemon, tracker, _ = _daemon_for(tmp_path, policy)
    daemon.get_logged_in_users = lambda: ["bobby"]

    daemon.get_active_users = lambda: set()  # signed in, screen locked
    daemon.check_and_enforce_cycle(active_minutes_step=5)
    assert tracker.get_minutes_used("bobby") == 0

    daemon.get_active_users = lambda: {"bobby"}
    daemon.check_and_enforce_cycle(active_minutes_step=5)
    assert tracker.get_minutes_used("bobby") == 5


def test_active_users_reads_logind_sessions(tmp_path: Path):
    from family_linux.security.adapter import CommandResult

    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True))
    daemon, _, adapter = _daemon_for(tmp_path, policy)
    sessions = {
        "2": "Name=bobby\nActive=yes\nLockedHint=no\nClass=user\n",
        "3": "Name=amy\nActive=yes\nLockedHint=yes\nClass=user\n",
        "4": "Name=sddm\nActive=no\nLockedHint=no\nClass=greeter\n",
    }

    def run(cmd, check=False):
        if cmd[:2] == ["loginctl", "list-sessions"]:
            return CommandResult(cmd, 0, "2 1001 bobby seat0 tty2\n3 1002 amy seat0 tty3\n4 105 sddm seat0 tty1\n", "")
        return CommandResult(cmd, 0, sessions[cmd[2]], "")

    adapter.run_command = run
    assert daemon.get_active_users() == {"bobby"}


def test_sign_out_asks_plasma_first_then_forces_and_restores_the_sign_in_screen(tmp_path: Path, monkeypatch):
    # loginctl terminate-user also killed SDDM's helper, which left a black screen (seen in the VM).
    from types import SimpleNamespace
    from family_linux.screentime import daemon as daemon_module

    monkeypatch.setattr(daemon_module.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1001))
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True))
    daemon, _, adapter = _daemon_for(tmp_path, policy)
    daemon.get_logged_in_users = lambda: ["bobby", "sddm"]

    daemon.lock_or_terminate_user("bobby", "Curfew active")
    cmds = adapter.executed_commands
    assert any("org.kde.Shutdown.logout" in c for c in cmds)
    assert ["loginctl", "terminate-user", "bobby"] not in cmds

    # Still signed in at the next check: forced, and the sign-in screen restarted (only sddm left)
    daemon.lock_or_terminate_user("bobby", "Curfew active")
    assert ["loginctl", "terminate-user", "bobby"] in cmds
    assert ["systemctl", "restart", "display-manager"] in cmds


def test_forced_sign_out_leaves_the_sign_in_screen_alone_when_a_parent_is_signed_in(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace
    from family_linux.screentime import daemon as daemon_module

    monkeypatch.setattr(daemon_module.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=1001))
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True))
    daemon, _, adapter = _daemon_for(tmp_path, policy)
    daemon.get_logged_in_users = lambda: ["bobby", "parent"]
    daemon.request_logout = lambda username: False  # Plasma not answering
    daemon.lock_or_terminate_user("bobby", "Curfew active")
    assert ["loginctl", "terminate-user", "bobby"] in adapter.executed_commands
    assert ["systemctl", "restart", "display-manager"] not in adapter.executed_commands


def test_one_warning_when_two_thresholds_pass_at_once(tmp_path: Path):
    # Seen in the VM: with 1 minute left, the 5- and 1-minute warnings were both sent together.
    child = ChildAccount.create("bobby", "Bobby")
    child.time_limits.daily_limit_minutes = 2
    child.time_limits.warning_minutes = [15, 5, 1]
    # Allowed all day (bedtime at the wake time counts as midnight), so the result does not depend
    # on when the test runs (it failed in CI at 04:27 UTC, inside the default bedtime).
    child.time_limits.wake_time = child.time_limits.bedtime_weekday = child.time_limits.bedtime_weekend = "00:00"
    policy = FamilyPolicy(parent=ParentAccount(username="parent", full_name="Parent", sudo_access=True), children=[child])
    daemon, _, _ = _daemon_for(tmp_path, policy)
    daemon.get_logged_in_users = lambda: ["bobby"]
    sent = []
    daemon.send_notification = lambda username, title, message, urgency="normal": sent.append(title)
    daemon.check_and_enforce_cycle()
    assert sent == ["Family Linux: Screen Time Warning"]
    daemon.check_and_enforce_cycle()  # limit reached: the sign-out notice, no more warnings
    assert sent[1:] == ["Family Linux: Session Ended"]
