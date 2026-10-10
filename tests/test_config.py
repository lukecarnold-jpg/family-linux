"""Tests for Family Linux policy configuration manager."""

import pytest
from pathlib import Path
from family_linux.config import PolicyConfigManager
from family_linux.models import FamilyPolicy, ParentAccount, ChildAccount


def test_load_and_save_policy(tmp_path: Path):
    cfg_file = tmp_path / "policy.yaml"
    mgr = PolicyConfigManager(config_path=cfg_file)

    parent = ParentAccount(username="parent_admin", full_name="Parent Administrator", sudo_access=True)
    child = ChildAccount.create("timmy", "Timmy Arnold")
    policy = FamilyPolicy(parent=parent, children=[child])

    saved = mgr.save_policy(policy, reason="Initial save")
    assert saved.exists()

    # Load back
    loaded = mgr.load_policy()
    assert loaded.parent.username == "parent_admin"
    assert len(loaded.children) == 1
    assert loaded.children[0].username == "timmy"


def test_backup_and_restore(tmp_path: Path):
    cfg_file = tmp_path / "policy.yaml"
    mgr = PolicyConfigManager(config_path=cfg_file)

    parent = ParentAccount(username="parent_admin", full_name="Parent Administrator", sudo_access=True)
    policy_v1 = FamilyPolicy(parent=parent, children=[ChildAccount.create("child1", "Child 1")])
    mgr.save_policy(policy_v1, reason="Version 1")

    # Make a backup
    backup_path = mgr.create_backup("v1_snapshot")
    assert backup_path.exists()

    # Save version 2
    policy_v2 = FamilyPolicy(parent=parent, children=[
        ChildAccount.create("child1", "Child 1"),
        ChildAccount.create("child2", "Child 2"),
    ])
    mgr.save_policy(policy_v2, reason="Version 2")
    assert len(mgr.load_policy().children) == 2

    # Restore from v1 backup
    restored = mgr.restore_backup(backup_path)
    assert len(restored.children) == 1
    assert mgr.load_policy().children[0].username == "child1"


def test_save_invalid_policy_raises(tmp_path: Path):
    cfg_file = tmp_path / "policy.yaml"
    mgr = PolicyConfigManager(config_path=cfg_file)

    bad_parent = ParentAccount(username="admin", full_name="", sudo_access=False)
    bad_policy = FamilyPolicy(parent=bad_parent)

    with pytest.raises(ValueError, match="Policy validation failed"):
        mgr.save_policy(bad_policy)
