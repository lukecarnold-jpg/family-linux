"""Sign-in check for children: refuses a sign-in at bedtime, after the day's limit, or when the
parent has turned the account off.

SDDM runs it as root through pam_exec in its account stack (see security/desktop_lockdown.py), for
members of family-children only. Without it a child signed out at bedtime could sign straight back
in and use the computer until the screen time service's next check, up to a minute each time.
"""

from __future__ import annotations

import os
import sys
from typing import Optional, Tuple

from family_linux.config import PolicyConfigManager
from family_linux.screentime.tracker import ScreenTimeTracker


def check(username: str, config: Optional[PolicyConfigManager] = None, tracker: Optional[ScreenTimeTracker] = None) -> Tuple[bool, str]:
    """(allowed, reason) for a sign-in by this account now."""
    policy = (config or PolicyConfigManager()).load_policy()
    child = next((c for c in policy.children if c.username == username), None)
    if child is None:
        return True, "not a child account in the policy"
    if not child.enabled:
        return False, "account turned off by the parent"
    allowed, reason, _ = (tracker or ScreenTimeTracker()).evaluate_limits(child)
    return allowed, reason


def pam_main(environ: Optional[dict] = None) -> int:
    """Exit status for pam_exec: 0 lets the child sign in."""
    env = os.environ if environ is None else environ
    username = env.get("PAM_USER", "")
    if not username:
        return 1
    try:
        allowed, reason = check(username)
    except Exception as exc:  # noqa: BLE001 - a child is refused rather than let in unchecked
        print(f"family-linux: sign-in check failed for {username}: {exc}", file=sys.stderr)
        return 1
    if not allowed:
        print(f"family-linux: sign-in refused for {username}: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(pam_main())
