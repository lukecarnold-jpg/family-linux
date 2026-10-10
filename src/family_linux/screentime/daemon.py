"""Screen time and curfew enforcement daemon for Family Linux.

Polls active sessions, tracks usage minutes, issues desktop notifications
before limits expire, and terminates sessions when limits or curfews are reached.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from typing import List, Optional, Set

from family_linux.config import PolicyConfigManager
from family_linux.models import FamilyPolicy, ChildAccount
from family_linux.screentime.tracker import ScreenTimeTracker
from family_linux.security.adapter import SystemAdapter
from family_linux.audit.logger import AuditLogger


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

    def send_notification(self, username: str, title: str, message: str, urgency: str = "normal") -> None:
        """Sends a desktop notification to the child user."""
        # Using notify-send / su
        cmd = [
            "su", "-", username, "-c",
            f'notify-send -u {urgency} -a "Family Linux" "{title}" "{message}"'
        ]
        self.adapter.run_command(cmd)

    def lock_or_terminate_user(self, username: str, reason: str) -> None:
        """Terminates or locks the child session upon curfew or limit expiration."""
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
            details={"action": "terminate_session", "reason": reason},
        )
        # Terminate user session
        self.adapter.run_command(["loginctl", "terminate-user", username])

    def check_and_enforce_cycle(self, active_minutes_step: int = 1) -> None:
        """Executes one policy enforcement check across all active child sessions."""
        policy: FamilyPolicy = self.config_manager.load_policy()
        child_map = {c.username: c for c in policy.children}
        active_users = self.get_logged_in_users()

        for username in active_users:
            if username not in child_map:
                continue

            child = child_map[username]
            if not child.enabled:
                self.lock_or_terminate_user(username, "Account disabled by parent")
                continue

            # Increment usage
            self.tracker.add_minutes_used(username, active_minutes_step)

            allowed, reason, remaining = self.tracker.evaluate_limits(child)

            if not allowed:
                self.lock_or_terminate_user(username, reason)
                if username in self._warned_thresholds:
                    self._warned_thresholds[username].clear()
                continue

            # Check warning alerts
            if username not in self._warned_thresholds:
                self._warned_thresholds[username] = set()

            for warn_min in child.time_limits.warning_minutes:
                if remaining <= warn_min and warn_min not in self._warned_thresholds[username]:
                    self.send_notification(
                        username,
                        "Family Linux: Screen Time Warning",
                        f"You have {remaining} minute(s) of screen time remaining today.",
                        urgency="normal" if warn_min > 5 else "critical",
                    )
                    self._warned_thresholds[username].add(warn_min)
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
                self.check_and_enforce_cycle(active_minutes_step=poll_interval_seconds // 60 or 1)
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
