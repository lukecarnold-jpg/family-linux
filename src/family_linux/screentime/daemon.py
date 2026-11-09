"""Screen time and curfew enforcement daemon for Family Linux.

Polls active sessions, tracks usage minutes, issues desktop notifications
before limits expire, and terminates sessions when limits or curfews are reached.
"""

from __future__ import annotations

import argparse
import pwd
import sys
import time
from datetime import date, datetime
from typing import List, Optional, Set

from family_linux.config import PolicyConfigManager
from family_linux.models import FamilyPolicy, ChildAccount
from family_linux.screentime.tracker import ScreenTimeTracker
from family_linux.security.adapter import SystemAdapter
from family_linux.audit.logger import AuditLogger


# Plasma 6 (org.kde.Shutdown), then the older session manager interface. --print-reply waits for the
# answer: org.kde.Shutdown is started on demand, and a call sent without waiting was lost while it
# started (seen on Debian 13). Waiting also makes a failed call return non-zero.
PLASMA_LOGOUT_COMMANDS = (
    ["dbus-send", "--session", "--print-reply", "--type=method_call", "--dest=org.kde.Shutdown", "/Shutdown",
     "org.kde.Shutdown.logout"],
    ["dbus-send", "--session", "--print-reply", "--type=method_call", "--dest=org.kde.ksmserver", "/KSMServer",
     "org.kde.KSMServerInterface.logout", "int32:0", "int32:0", "int32:0"],
)
# Accounts with a logind session that are not people (the sign-in screen itself).
SYSTEM_SESSION_USERS = frozenset({"sddm", "root"})


class ScreenTimeDaemon:
    """Enforcement daemon for Family Linux session and time policies."""

    def __init__(
        self,
        config_manager: Optional[PolicyConfigManager] = None,
        tracker: Optional[ScreenTimeTracker] = None,
        adapter: Optional[SystemAdapter] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.config_manager = config_manager or PolicyConfigManager()
        self.tracker = tracker or ScreenTimeTracker()
        self.adapter = adapter or SystemAdapter()
        self.audit = audit_logger or AuditLogger()
        self._warned_thresholds: dict[str, Set[int]] = {}
        self._warned_day: Optional[date] = None
        self._logout_requested: Set[str] = set()

    def get_logged_in_users(self) -> List[str]:
        """Detects active users logged into the system."""
        res = self.adapter.run_command(["loginctl", "list-users", "--no-legend"])
        if res.returncode == 0 and res.stdout:
            users = []
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    users.append(parts[1])
            return users

        # Fallback to 'who' command
        who_res = self.adapter.run_command(["who"])
        if who_res.returncode == 0 and who_res.stdout:
            users = set()
            for line in who_res.stdout.strip().splitlines():
                parts = line.split()
                if parts:
                    users.add(parts[0])
            return list(users)

        return []

    def get_active_users(self) -> Optional[Set[str]]:
        """Users with a session in use: active on the seat and not locked. Time is counted only
        for these, so a locked screen or a session left on another seat does not use up the day.
        None when logind cannot say, and then every signed-in child is counted, as before."""
        res = self.adapter.run_command(["loginctl", "list-sessions", "--no-legend"])
        if res.returncode != 0 or not res.stdout or res.stdout.startswith("[SIMULATED]"):
            return None
        active: Set[str] = set()
        for line in res.stdout.strip().splitlines():
            parts = line.split()
            if not parts:
                continue
            info = self.adapter.run_command(
                ["loginctl", "show-session", parts[0], "-p", "Name", "-p", "Active", "-p", "LockedHint", "-p", "Class"]
            )
            if info.returncode != 0:
                continue
            props = dict(item.split("=", 1) for item in info.stdout.splitlines() if "=" in item)
            if props.get("Class") == "user" and props.get("Active") == "yes" and props.get("LockedHint") != "yes":
                active.add(props.get("Name", ""))
        return active

    def send_notification(self, username: str, title: str, message: str, urgency: str = "normal") -> None:
        """Shows a desktop notification in the child's session.

        Children have no login shell, so `su -` cannot run anything for them. runuser starts
        notify-send as the child, pointed at the session bus that systemd-logind gives every
        signed-in user. Arguments are passed as a list, so names in the text are not parsed by a shell.
        """
        self._run_in_session(username, ["notify-send", "-u", urgency, "-a", "Family Linux", title, message])

    def _run_in_session(self, username: str, command: List[str]) -> bool:
        """Runs a command as the user, on their session bus. True if it succeeded."""
        try:
            uid = pwd.getpwnam(username).pw_uid
        except KeyError:
            return False
        result = self.adapter.run_command([
            "runuser", "-u", username, "--",
            "env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus", *command,
        ])
        return result.returncode == 0

    def request_logout(self, username: str) -> bool:
        """Asks Plasma to sign the user out, as if they chose Log Out (no confirmation)."""
        for command in PLASMA_LOGOUT_COMMANDS:
            if self._run_in_session(username, command):
                return True
        return False

    def lock_or_terminate_user(self, username: str, reason: str) -> None:
        """Ends the child's session when a limit or bedtime is reached, or the account is off.

        The first time, Plasma is asked to sign the child out, which SDDM handles cleanly. Ending the
        session from outside (loginctl terminate-user) also kills SDDM's helper for it, and SDDM then
        left a black screen instead of the sign-in screen (seen on Debian 13 in VirtualBox). So that
        is only done if the child is still signed in at the next check, and the sign-in screen is
        then restarted if nobody else is signed in.
        """
        if username not in self._logout_requested:
            self.send_notification(
                username,
                "Family Linux: Session Ended",
                f"Your screen time has ended: {reason}. Logging out now.",
                urgency="critical",
            )
            self.audit.log(
                event_type="TIME_CURFEW",
                user=username,
                severity="NOTICE",
                details={"action": "sign_out", "reason": reason},
            )
            self._logout_requested.add(username)
            if self.request_logout(username):
                return
        # Still signed in a cycle later, or Plasma could not be asked: end the session.
        self.audit.log(
            event_type="TIME_CURFEW",
            user=username,
            severity="NOTICE",
            details={"action": "terminate_session", "reason": reason},
        )
        self.adapter.run_command(["loginctl", "terminate-user", username])
        self._logout_requested.discard(username)
        others = [u for u in self.get_logged_in_users() if u != username and u not in SYSTEM_SESSION_USERS]
        if not others:
            self.adapter.run_command(["systemctl", "restart", "display-manager"])

    def check_and_enforce_cycle(self, active_minutes_step: int = 1) -> None:
        """Executes one policy enforcement check across all active child sessions."""
        policy: FamilyPolicy = self.config_manager.load_policy()
        child_map = {c.username: c for c in policy.children}
        active_users = self.get_logged_in_users()
        in_use = self.get_active_users()

        # Warnings are given once per threshold per day.
        today = datetime.now().date()
        if today != self._warned_day:
            self._warned_thresholds.clear()
            self._warned_day = today

        self._logout_requested &= set(active_users)
        for username in active_users:
            if username not in child_map:
                continue
            # One child's problem must not stop the checks for the others.
            try:
                counted = in_use is None or username in in_use
                self._enforce_child(child_map[username], active_minutes_step if counted else 0)
            except Exception as exc:  # noqa: BLE001 - logged, and the next child is still checked
                print(f"[Family Linux] Screen time check failed for '{username}': {exc}", file=sys.stderr)
                self.audit.log(
                    event_type="TIME_CHECK_FAILED",
                    user=username,
                    severity="ERROR",
                    details={"error": str(exc)},
                )

    def _enforce_child(self, child: ChildAccount, active_minutes_step: int) -> None:
        username = child.username
        if not child.enabled:
            self.lock_or_terminate_user(username, "Account disabled by parent")
            return

        # Increment usage (0 while the screen is locked or the session is in the background)
        if active_minutes_step:
            self.tracker.add_minutes_used(username, active_minutes_step)

        allowed, reason, remaining = self.tracker.evaluate_limits(child)

        if not allowed:
            self.lock_or_terminate_user(username, reason)
            return

        # Check warning alerts: one message per check, for the smallest threshold passed (when the
        # time left drops past two thresholds at once, both used to be sent together)
        warned = self._warned_thresholds.setdefault(username, set())
        crossed = [w for w in child.time_limits.warning_minutes if remaining <= w and w not in warned]
        if crossed:
            warn_min = min(crossed)
            self.send_notification(
                username,
                "Family Linux: Screen Time Warning",
                f"You have {remaining} minute(s) of screen time remaining today.",
                urgency="normal" if warn_min > 5 else "critical",
            )
            warned.update(crossed)
            self.audit.log(
                event_type="TIME_WARNING",
                user=username,
                severity="INFO",
                details={"remaining_minutes": remaining, "warning_threshold": warn_min},
            )

    def run_loop(self, poll_interval_seconds: int = 60) -> None:
        """Runs the daemon loop."""
        print(f"[Family Linux] Screen time daemon started (interval: {poll_interval_seconds}s)")
        try:
            while True:
                try:
                    self.check_and_enforce_cycle(active_minutes_step=poll_interval_seconds // 60 or 1)
                except Exception as exc:  # noqa: BLE001 - e.g. a policy file being replaced; retry next cycle
                    print(f"[Family Linux] Screen time cycle failed: {exc}", file=sys.stderr)
                time.sleep(poll_interval_seconds)
        except KeyboardInterrupt:
            print("[Family Linux] Screen time daemon stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Family Linux Screen Time & Policy Daemon")
    parser.add_argument("--one-shot", action="store_true", help="Run a single enforcement cycle and exit")
    parser.add_argument("--interval", type=int, default=60, help="Check interval in seconds (default: 60)")
    parser.add_argument("--config", type=str, help="Custom policy file path")
    args = parser.parse_args()

    cfg_mgr = PolicyConfigManager(config_path=args.config) if args.config else None
    daemon = ScreenTimeDaemon(config_manager=cfg_mgr)

    if args.one_shot:
        daemon.check_and_enforce_cycle()
        print("Completed one-shot policy enforcement check.")
    else:
        daemon.run_loop(poll_interval_seconds=args.interval)


if __name__ == "__main__":
    main()
