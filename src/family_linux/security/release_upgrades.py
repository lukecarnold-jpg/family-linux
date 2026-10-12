"""Turns off Ubuntu's new-release upgrade notice.

Ubuntu checks for the next LTS release and opens "Upgrade Available" in every desktop session,
children's included. A child cannot upgrade (it needs an administrator), but the notice is
confusing and invites the parent to make a large change from any account. Security updates are
unaffected: they come from unattended-upgrades. The parent can still upgrade on purpose with
`sudo do-release-upgrade -f DistUpgradeViewGtk3` after setting Prompt back to lts.
"""

from __future__ import annotations

import re
from pathlib import Path

from family_linux.security.adapter import SystemAdapter

RELEASE_UPGRADES_PATH = Path("/etc/update-manager/release-upgrades")


def with_prompt_never(current: str) -> str:
    """Returns the file with Prompt=never, keeping its comments and other keys."""
    if re.search(r"^Prompt=.*$", current, flags=re.MULTILINE):
        return re.sub(r"^Prompt=.*$", "Prompt=never", current, count=1, flags=re.MULTILINE)
    if "[DEFAULT]" in current:
        return current.replace("[DEFAULT]", "[DEFAULT]\nPrompt=never", 1)
    return "[DEFAULT]\nPrompt=never\n" + current


def prompt_is_off(content: str) -> bool:
    match = re.search(r"^Prompt=(.*)$", content, flags=re.MULTILINE)
    return bool(match and match.group(1).strip() == "never")


def disable_release_upgrade_prompt(adapter: SystemAdapter, path: Path = RELEASE_UPGRADES_PATH) -> None:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    updated = with_prompt_never(current)
    if updated != current:
        adapter.write_system_file(path, updated, mode=0o644)
