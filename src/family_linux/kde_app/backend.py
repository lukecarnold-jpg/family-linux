"""The Family Controls app's link to family-ctl. No Qt here, so it can be tested anywhere.

Every call runs `pkexec family-ctl ...`. polkit asks for the parent's password (the action
org.familylinux.manage, remembered for a few minutes), so the app never runs as root and all
changes go through the same validated code as the command line.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

PKEXEC = "/usr/bin/pkexec"
FAMILY_CTL = "/usr/local/sbin/family-ctl"
# pkexec exit codes
AUTH_DISMISSED = 126
NOT_AUTHORISED = 127

USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{2,31}$")
CLOCK = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
DOMAIN = re.compile(r"^(\*\.)?([a-z0-9-]+\.)*[a-z0-9-]+$")


@dataclass
class Result:
    ok: bool
    message: str


class BackendError(Exception):
    """A call that the app cannot continue without (reading the state) failed."""


Runner = Callable[[List[str], Optional[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(cmd: List[str], stdin: Optional[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True)


def valid_username(name: str) -> bool:
    return bool(USERNAME.match(name))


def valid_clock(value: str) -> bool:
    return bool(CLOCK.match(value))


def normalise_domain(value: str) -> Optional[str]:
    """Lower-cases and strips a typed website ("https://Example.com/page" -> "example.com")."""
    text = value.strip().lower()
    text = re.sub(r"^[a-z]+://", "", text).split("/", 1)[0].split(":", 1)[0]
    return text if text and DOMAIN.match(text) and "." in text.lstrip("*.") else None


def approved_entries_for(app_id: str, approved: Sequence[str]) -> List[str]:
    """The approved-list entries that make this app visible, using AppGuard's matching rule."""
    clean = app_id.lower().replace(".desktop", "")
    return [a for a in approved if a.lower() in clean or clean in a.lower()]


class FamilyCtlClient:
    """Runs family-ctl through pkexec. FAMILY_LINUX_CTL_COMMAND replaces the command for development."""

    def __init__(self, runner: Runner = _default_runner, command: Optional[Sequence[str]] = None):
        self.runner = runner
        override = os.environ.get("FAMILY_LINUX_CTL_COMMAND")
        if command is not None:
            self.command = list(command)
        elif override:
            self.command = shlex.split(override)
        else:
            self.command = [PKEXEC, FAMILY_CTL]

    def _run(self, args: Sequence[str], stdin: Optional[str] = None) -> Result:
        try:
            proc = self.runner(self.command + list(args), stdin)
        except OSError as exc:
            return Result(False, f"Could not run family-ctl: {exc}")
        if proc.returncode == AUTH_DISMISSED:
            return Result(False, "Authentication was cancelled.")
        if proc.returncode == NOT_AUTHORISED:
            return Result(False, "Only the parent account can change Family Linux settings.")
        lines = [line.strip() for line in (proc.stdout or "").splitlines() + (proc.stderr or "").splitlines() if line.strip()]
        if proc.returncode != 0:
            errors = [line for line in lines if line.startswith("[ERROR]")]
            message = (errors or lines or ["family-ctl failed."])[-1]
            return Result(False, message.replace("[ERROR] ", ""))
        done = [line for line in lines if line.startswith("[OK]")]
        return Result(True, (done or lines or ["Done."])[-1].replace("[OK] ", ""))

    # Reading

    def state(self) -> dict:
        try:
            proc = self.runner(self.command + ["state"], None)
        except OSError as exc:
            raise BackendError(f"Could not run family-ctl: {exc}") from exc
        if proc.returncode == AUTH_DISMISSED:
            raise BackendError("Authentication was cancelled.")
        if proc.returncode == NOT_AUTHORISED:
            raise BackendError("Only the parent account can open Family Controls.")
        if proc.returncode != 0:
            raise BackendError((proc.stderr or proc.stdout or "family-ctl failed.").strip().splitlines()[-1])
        try:
            return json.loads(proc.stdout)
        except ValueError as exc:
            raise BackendError("family-ctl returned an unreadable state.") from exc

    # Accounts

    def add_child(self, username: str, full_name: str, tier: str, password: str) -> Result:
        # The password goes on standard input, never on the command line.
        return self._run(["user", "add", username, "--name", full_name, "--tier", tier, "--password-stdin"], stdin=password + "\n")

    def set_enabled(self, username: str, enabled: bool) -> Result:
        return self._run(["user", "enable" if enabled else "disable", username])

    def remove_child(self, username: str) -> Result:
        return self._run(["user", "remove", username])

    # Screen time

    def set_time(self, username: str, daily_limit: int, bedtime_weekday: str, bedtime_weekend: str, wake_time: str) -> Result:
        return self._run([
            "time", "set", username,
            "--daily-limit", str(daily_limit),
            "--bedtime-weekday", bedtime_weekday,
            "--bedtime-weekend", bedtime_weekend,
            "--wake-time", wake_time,
        ])

    def reset_usage(self, username: str) -> Result:
        return self._run(["time", "reset-usage", username])

    # Apps

    def approve_app(self, username: str, app_id: str) -> Result:
        return self._run(["app", "approve", username, app_id])

    def revoke_app(self, username: str, app_id: str, approved: Sequence[str]) -> Result:
        entries = approved_entries_for(app_id, approved) or [app_id]
        result = Result(True, "")
        for entry in entries:
            result = self._run(["app", "revoke", username, entry])
            if not result.ok:
                return result
        return result

    # Websites

    def block(self, username: str, domain: str) -> Result:
        return self._run(["web", "block", domain, "--child", username])

    def allow(self, username: str, domain: str) -> Result:
        return self._run(["web", "allow", domain, "--child", username])

    def remove_rule(self, username: str, domain: str) -> Result:
        return self._run(["web", "remove", domain, "--child", username])

    def approve_request(self, username: str, domain: str) -> Result:
        return self._run(["web", "approve", username, domain])

    def deny_request(self, username: str, domain: str) -> Result:
        return self._run(["web", "deny", username, domain])


class DemoClient:
    """Serves a fixed state from a JSON file and accepts every change. For screenshots and design work:
    FAMILY_LINUX_DEMO_STATE=/path/to/state.json."""

    def __init__(self, path: Path):
        self.path = path

    def state(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def __getattr__(self, name: str):
        return lambda *args, **kwargs: Result(True, f"{name.replace('_', ' ').capitalize()} (demo).")


def make_client():
    demo = os.environ.get("FAMILY_LINUX_DEMO_STATE")
    return DemoClient(Path(demo)) if demo else FamilyCtlClient()
