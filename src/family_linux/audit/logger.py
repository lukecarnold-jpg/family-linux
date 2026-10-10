"""Audit logging for Family Linux.

Records security, policy, account, and runtime enforcement events
to an append-only audit log.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any

DEFAULT_AUDIT_LOG_PATH = Path("/var/log/family-linux/audit.log")


@dataclass
class AuditRecord:
    timestamp: str
    event_type: str
    user: str
    severity: str
    details: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, line: str) -> Optional[AuditRecord]:
        try:
            data = json.loads(line.strip())
            return cls(
                timestamp=data.get("timestamp", ""),
                event_type=data.get("event_type", "UNKNOWN"),
                user=data.get("user", "system"),
                severity=data.get("severity", "INFO"),
                details=data.get("details", {}),
            )
        except Exception:
            return None


class AuditLogger:
    """Manages audit log recording and querying."""

    def __init__(self, log_path: Optional[Path | str] = None, dry_run: bool = False):
        if log_path:
            self.log_path = Path(log_path)
        else:
            if os.path.exists(DEFAULT_AUDIT_LOG_PATH) or os.access("/var/log", os.W_OK):
                self.log_path = DEFAULT_AUDIT_LOG_PATH
            else:
                user_home = Path.home()
                self.log_path = user_home / ".local" / "share" / "family-linux" / "audit.log"

        self.dry_run = dry_run

    def _ensure_log_file(self) -> None:
        if not self.dry_run:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.log_path.exists():
                self.log_path.touch(mode=0o640)

    def log(
        self,
        event_type: str,
        user: str = "system",
        severity: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Appends a new audit record."""
        record = AuditRecord(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            event_type=event_type,
            user=user,
            severity=severity,
            details=details or {},
        )

        if not self.dry_run:
            try:
                self._ensure_log_file()
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(record.to_json() + "\n")
            except OSError:
                pass  # Avoid crashing caller if logging has permission issues

        return record

    def get_records(
        self,
        limit: int = 100,
        filter_user: Optional[str] = None,
        filter_type: Optional[str] = None,
    ) -> List[AuditRecord]:
        """Reads recent audit records in reverse chronological order."""
        if not self.log_path.exists():
            return []

        records: List[AuditRecord] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in reversed(lines):
                if not line.strip():
                    continue
                rec = AuditRecord.from_json(line)
                if not rec:
                    continue
                if filter_user and rec.user != filter_user:
                    continue
                if filter_type and rec.event_type != filter_type:
                    continue
                records.append(rec)
                if len(records) >= limit:
                    break
        except OSError:
            return []

        return records
