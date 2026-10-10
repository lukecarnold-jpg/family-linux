"""Passwords must be usable for provisioning but never written to disk or shown in reprs."""

from __future__ import annotations

import yaml

from family_linux.config import PolicyConfigManager
from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount


def _policy() -> FamilyPolicy:
    return FamilyPolicy(
        parent=ParentAccount("parent", "Parent Admin", password="ParentPass1!"),
        children=[ChildAccount.create("kid", "Kid", "pre_teen", password="KidPass123!")],
    )


def test_passwords_are_not_serialised():
    data = _policy().to_dict()
    assert "password" not in data["parent"]
    assert "password" not in data["children"][0]


def test_saved_policy_file_contains_no_plaintext(tmp_path):
    manager = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    manager.save_policy(_policy())
    text = (tmp_path / "policy.yaml").read_text()
    assert "ParentPass1!" not in text
    assert "KidPass123!" not in text
    assert "password" not in yaml.safe_load(text)["parent"]


def test_legacy_plaintext_is_loaded_then_dropped_on_next_save(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"parent": {"username": "parent", "full_name": "P", "password": "OldPass123"}}))
    manager = PolicyConfigManager(config_path=path)

    loaded = manager.load_policy()
    assert loaded.parent.password == "OldPass123"  # still available for provisioning

    manager.save_policy(loaded)
    assert "OldPass123" not in path.read_text()


def test_password_not_shown_in_repr():
    parent = ParentAccount("parent", "Parent Admin", password="ParentPass1!")
    assert "ParentPass1!" not in repr(parent)
