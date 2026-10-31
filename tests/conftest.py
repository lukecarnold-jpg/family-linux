"""Shared fixtures for the test suite."""

from pathlib import Path

import pytest

from family_linux.audit.logger import AuditLogger
from family_linux.cli.family_ctl import FamilyCtl
from family_linux.config import PolicyConfigManager
from family_linux.models import AgeTier, ChildAccount, FamilyPolicy, ParentAccount
from family_linux.screentime.tracker import ScreenTimeTracker


@pytest.fixture
def test_ctl(tmp_path: Path):
    cfg_file = tmp_path / "policy.yaml"
    mgr = PolicyConfigManager(config_path=cfg_file)
    parent = ParentAccount(username="parent", full_name="Parent Admin", sudo_access=True)
    child = ChildAccount.create("alice", "Alice", age_tier=AgeTier.YOUNG_CHILD)
    policy = FamilyPolicy(parent=parent, children=[child])
    mgr.save_policy(policy)

    ctl = FamilyCtl(config_path=str(cfg_file), dry_run=False)
    # Keep tests off the real system even when run as root on Linux: simulate system
    # commands and file writes, and send usage and audit data to the temp directory.
    ctl.adapter.dry_run = True
    ctl.tracker = ScreenTimeTracker(usage_file=tmp_path / "usage.json")
    audit = AuditLogger(log_path=tmp_path / "audit.log")
    ctl.audit = audit
    ctl.provisioner.audit = audit
    ctl.provisioner.app_guard.audit = audit
    return ctl
