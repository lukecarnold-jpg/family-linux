"""Apply ordering: the policy is recorded before system changes, and failures say how to recover."""

from __future__ import annotations

import pytest

from family_linux.audit.logger import AuditLogger
from family_linux.config import PolicyConfigManager
from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount
from family_linux.provisioner.system import ProvisioningError, SystemProvisioner
from family_linux.security.adapter import SystemAdapter


def _policy() -> FamilyPolicy:
    return FamilyPolicy(
        parent=ParentAccount("parent", "Parent Admin", password="ParentPass1!"),
        children=[ChildAccount.create("kid", "Kid", "pre_teen", password="KidPass123!")],
    )


def test_policy_is_saved_even_when_a_later_layer_fails(tmp_path, monkeypatch):
    config = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    provisioner = SystemProvisioner(
        adapter=SystemAdapter(dry_run=True),
        config_manager=config,
        audit_logger=AuditLogger(log_path=tmp_path / "audit.log"),
    )

    def broken_firewall(*_args, **_kwargs):
        raise RuntimeError("ufw exploded")

    monkeypatch.setattr(provisioner.firewall, "configure_baseline", broken_firewall)

    with pytest.raises(ProvisioningError) as exc:
        provisioner.apply_policy(_policy(), reason="test")

    message = str(exc.value)
    assert "ufw exploded" in message
    assert "Child account 'kid' provisioned" in message  # names the last completed step
    assert "run the apply again" in message
    assert [c.username for c in config.load_policy().children] == ["kid"]


def test_successful_apply_reports_actions_and_audits(tmp_path):
    config = PolicyConfigManager(config_path=tmp_path / "policy.yaml")
    audit = AuditLogger(log_path=tmp_path / "audit.log")
    provisioner = SystemProvisioner(adapter=SystemAdapter(dry_run=True), config_manager=config, audit_logger=audit)

    results = provisioner.apply_policy(_policy(), reason="test")

    assert results["actions"][0].startswith("Policy saved to")
    assert any("AppArmor" in a for a in results["actions"])
    assert any(r.event_type == "SYSTEM_PROVISIONED" for r in audit.get_records())


def test_a_website_rule_reapplies_only_the_web_filter(tmp_path):
    from family_linux.config import PolicyConfigManager
    from family_linux.models import ChildAccount, FamilyPolicy, ParentAccount
    from family_linux.provisioner.system import WEB_LAYERS, SystemProvisioner
    from family_linux.security.adapter import SystemAdapter

    adapter = SystemAdapter(dry_run=True)
    policy = FamilyPolicy(parent=ParentAccount("parent", "P"), children=[ChildAccount.create("kid", "Kid", "teen")])
    results = SystemProvisioner(adapter=adapter, config_manager=PolicyConfigManager(tmp_path / "p.yaml")).apply_policy(
        policy, reason="test", layers=WEB_LAYERS
    )
    commands = [" ".join(c) for c in adapter.executed_commands]
    assert any("Per-child web filter" in a for a in results["actions"])
    assert not any(c.startswith(("ufw", "useradd", "usermod", "apparmor_parser", "timedatectl")) for c in commands)


def test_unknown_layer_names_are_refused(tmp_path):
    import pytest
    from family_linux.config import PolicyConfigManager
    from family_linux.models import FamilyPolicy, ParentAccount
    from family_linux.provisioner.system import SystemProvisioner
    from family_linux.security.adapter import SystemAdapter

    provisioner = SystemProvisioner(adapter=SystemAdapter(dry_run=True), config_manager=PolicyConfigManager(tmp_path / "p.yaml"))
    with pytest.raises(ValueError):
        provisioner.apply_policy(FamilyPolicy(parent=ParentAccount("parent", "P")), layers=("firewal",))
