"""Keeps child app menus in step with what is installed.

A systemd path unit watches the places where installs add or remove desktop entries (apt and PackageKit). When one changes, it runs this module, which re-applies each child's app approvals. A new
app therefore stays hidden from the child until the parent approves it, without waiting for the next
full apply.

Installing an app is authorised separately (see package_gate). Authorising an install does not approve
the app.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from family_linux.config import PolicyConfigManager
from family_linux.security.adapter import SystemAdapter
from family_linux.security.apparmor import AppArmorManager
from family_linux.security.app_guard import SYSTEM_APP_DIRS, AppGuard

PATH_UNIT_NAME = "family-appguard.path"
SERVICE_UNIT_NAME = "family-appguard.service"
PATH_UNIT_PATH = Path(f"/etc/systemd/system/{PATH_UNIT_NAME}")
SERVICE_UNIT_PATH = Path(f"/etc/systemd/system/{SERVICE_UNIT_NAME}")
# Directories that change when apps are installed or removed. Each one must exist for the path unit.
WATCHED_DIRS: List[Path] = list(SYSTEM_APP_DIRS)


def render_path_unit() -> str:
    watches = "\n".join(f"PathChanged={directory}" for directory in WATCHED_DIRS)
    return (
        "[Unit]\n"
        "Description=Family Linux: refresh child app menus when apps are installed or removed\n"
        "\n"
        "[Path]\n"
        f"{watches}\n"
        f"Unit={SERVICE_UNIT_NAME}\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def render_service_unit(python: str = sys.executable) -> str:
    return (
        "[Unit]\n"
        "Description=Family Linux: re-apply child app approvals to the desktop menu\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={python} -m family_linux.security.desktop_refresh\n"
        "User=root\n"
        "Group=root\n"
    )


def refresh(adapter: SystemAdapter, config_path=None) -> List[str]:
    """Re-applies every child's app approvals. Returns one summary line per child."""
    policy = PolicyConfigManager(config_path, dry_run=adapter.dry_run).load_policy()
    confine = AppArmorManager(adapter).is_available()
    guard = AppGuard(adapter)
    lines = []
    for child in policy.children:
        hidden, confined = guard.apply_child_desktop_filters(child, confine=confine)
        lines.append(f"{child.username}: {hidden} hidden, {confined} confined")
    return lines


def main(argv: List[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Re-apply child app approvals to the desktop menu")
    parser.add_argument("--config", type=Path, default=None, help="Policy file (default: system policy)")
    args = parser.parse_args(argv)
    for line in refresh(SystemAdapter(), args.config):
        print(line)


if __name__ == "__main__":
    main()
