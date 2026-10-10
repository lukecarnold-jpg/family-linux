"""Screen time usage tracker and curfew evaluation for Family Linux.

Calculates remaining screen time, bedtime curfews, and determines
when to send user warnings or lock child sessions.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, time as dtime
from pathlib import Path
from typing import Dict, Optional, Tuple, Any

from family_linux.models import ChildAccount, TimeLimitPolicy

DEFAULT_USAGE_FILE = Path("/var/lib/family-linux/screentime.json")


class ScreenTimeTracker:
    """Tracks daily active minutes for children and evaluates curfew restrictions."""

    def __init__(self, usage_file: Optional[Path | str] = None, dry_run: bool = False):
        if usage_file:
            self.usage_file = Path(usage_file)
        else:
            if os.path.exists(DEFAULT_USAGE_FILE) or os.access("/var/lib", os.W_OK):
                self.usage_file = DEFAULT_USAGE_FILE
            else:
                user_home = Path.home()
                self.usage_file = user_home / ".local" / "share" / "family-linux" / "screentime.json"

        self.dry_run = dry_run

    def _load_data(self) -> Dict[str, Any]:
        if not self.usage_file.exists():
            return {}
        try:
            with open(self.usage_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_data(self, data: Dict[str, Any]) -> None:
        if self.dry_run:
            return
        self.usage_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.usage_file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.usage_file)

    def get_today_str(self, now: Optional[datetime] = None) -> str:
        dt = now or datetime.now()
        return dt.strftime("%Y-%m-%d")

    def get_minutes_used(self, username: str, now: Optional[datetime] = None) -> int:
        """Returns total screen time consumed today in minutes."""
        data = self._load_data()
        today = self.get_today_str(now)
        user_data = data.get(username, {})
        if user_data.get("date") == today:
            return int(user_data.get("minutes", 0))
        return 0

    def add_minutes_used(self, username: str, minutes: int, now: Optional[datetime] = None) -> int:
        """Increments consumed minutes for today."""
        data = self._load_data()
        today = self.get_today_str(now)
        user_data = data.get(username, {})
        if user_data.get("date") == today:
            current = int(user_data.get("minutes", 0))
        else:
            current = 0

        new_total = current + minutes
        data[username] = {
            "date": today,
            "minutes": new_total,
            "updated_at": (now or datetime.now()).isoformat(),
        }
        self._save_data(data)
        return new_total

    def reset_usage(self, username: str) -> None:
        """Resets today's consumed screen time for a user."""
        data = self._load_data()
        if username in data:
            data[username]["minutes"] = 0
            self._save_data(data)

    def evaluate_limits(
        self, child: ChildAccount, now: Optional[datetime] = None
    ) -> Tuple[bool, str, int]:
        """
        Evaluates whether a child is currently permitted to be logged in.
        Returns:
            (allowed: bool, reason: str, remaining_minutes: int)
        """
        policy = child.time_limits
        if not policy.enabled:
            return True, "Limits disabled", 9999

        dt = now or datetime.now()
        current_clock = dt.time()

        # Parse wake time
        wake_h, wake_m = [int(p) for p in policy.wake_time.split(":")]
        wake = dtime(wake_h, wake_m)

        # Parse bedtime based on weekday (Monday=0 ... Sunday=6)
        is_weekend = dt.weekday() in (4, 5)  # Friday and Saturday nights
        curfew_str = policy.bedtime_weekend if is_weekend else policy.bedtime_weekday
        bed_h, bed_m = [int(p) for p in curfew_str.split(":")]
        bed = dtime(bed_h, bed_m)

        # Check bedtime curfew
        if current_clock >= bed or current_clock < wake:
            return False, f"Curfew active ({curfew_str} to {policy.wake_time})", 0

        # Calculate minutes until bedtime
        minutes_to_bed = (bed_h * 60 + bed_m) - (current_clock.hour * 60 + current_clock.minute)

        # Check daily quota
        used_today = self.get_minutes_used(child.username, dt)
        remaining_quota = max(0, policy.daily_limit_minutes - used_today)

        if remaining_quota <= 0:
            return False, f"Daily limit reached ({policy.daily_limit_minutes} minutes)", 0

        # Effective remaining time is minimum of quota and curfew
        effective_remaining = min(remaining_quota, max(0, minutes_to_bed))
        if effective_remaining <= 0:
            return False, f"Curfew reached ({curfew_str})", 0

        return True, "Within allowed hours and quota", effective_remaining
