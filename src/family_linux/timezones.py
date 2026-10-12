"""Time zone names for the installer and policy.

Curfews and bedtimes are evaluated in the system's local time, so the installed system must use the
family's time zone. Ubuntu otherwise defaults to UTC.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - Python 3.9 has zoneinfo; kept for safety
    ZoneInfo = None  # type: ignore[assignment]
    ZoneInfoNotFoundError = KeyError  # type: ignore[assignment,misc]

# Area/Location names only: they are written to the policy file, the autoinstall and timedatectl.
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$")
DEFAULT_TIMEZONE = "UTC"


def is_valid_timezone(name: Optional[str]) -> bool:
    """True for an IANA time zone name such as "Australia/Sydney" or "UTC"."""
    if not name or not _NAME.match(name) or ".." in name:
        return False
    if ZoneInfo is None:
        return True
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


def detect_host_timezone(localtime: Path = Path("/etc/localtime")) -> str:
    """The time zone of the machine running the installer or build, or UTC if it cannot be read.

    Reads TZ, then the /etc/localtime link (Linux: /usr/share/zoneinfo/..., macOS:
    /var/db/timezone/zoneinfo/...).
    """
    env = os.environ.get("TZ", "").lstrip(":")
    if is_valid_timezone(env):
        return env
    try:
        target = os.path.realpath(localtime)
    except OSError:
        return DEFAULT_TIMEZONE
    marker = "zoneinfo/"
    if marker in target:
        name = target.split(marker, 1)[1]
        if is_valid_timezone(name):
            return name
    return DEFAULT_TIMEZONE
