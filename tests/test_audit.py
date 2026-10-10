"""Tests for Family Linux audit logging system."""

from pathlib import Path
import pytest
from family_linux.audit.logger import AuditLogger, AuditRecord


def test_audit_logger_records_and_retrieves(tmp_path: Path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_file)

    rec1 = logger.log(
        event_type="POLICY_CHANGE",
        user="parent_admin",
        severity="NOTICE",
        details={"field": "daily_limit", "value": 120},
    )
    rec2 = logger.log(
        event_type="APP_BLOCKED",
        user="child1",
        severity="WARNING",
        details={"app": "gnome-terminal"},
    )
    rec3 = logger.log(
        event_type="TIME_CURFEW",
        user="child2",
        severity="NOTICE",
        details={"action": "terminate"},
    )

    records = logger.get_records(limit=10)
    assert len(records) == 3
    # Reverse chronological order
    assert records[0].event_type == "TIME_CURFEW"
    assert records[1].event_type == "APP_BLOCKED"
    assert records[2].event_type == "POLICY_CHANGE"


def test_audit_logger_filters(tmp_path: Path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_file)

    logger.log("APP_BLOCKED", user="child1", details={"app": "sh"})
    logger.log("APP_BLOCKED", user="child2", details={"app": "bash"})
    logger.log("TIME_WARNING", user="child1", details={"mins": 5})

    child1_records = logger.get_records(filter_user="child1")
    assert len(child1_records) == 2
    assert all(r.user == "child1" for r in child1_records)

    warning_records = logger.get_records(filter_type="TIME_WARNING")
    assert len(warning_records) == 1
    assert warning_records[0].event_type == "TIME_WARNING"
