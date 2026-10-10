"""System provisioning and configuration application engine for Family Linux.

Orchestrates user management, sudoers policy, firewall, DNS filter,
browser configuration, AppArmor, and desktop menu restrictions.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from pathlib import Path

from family_linux.models import FamilyPolicy
from family_linux.security.adapter import SystemAdapter
from family_linux.security.users import UserManager
from family_linux.security.firewall import FirewallManager
from family_linux.security.dns_filter import DNSFilterManager
from family_linux.security.browser import BrowserPolicyManager
from family_linux.security.apparmor import AppArmorManager
from family_linux.security.app_guard import AppGuard
from family_linux.config import PolicyConfigManager
from family_linux.audit.logger import AuditLogger


class ProvisioningError(RuntimeError):
    """Raised when applying a policy fails partway through the system layers."""


class SystemProvisioner:
    """Applies a complete Family Linux policy to the underlying system."""

    def __init__(
        self,
        adapter: Optional[SystemAdapter] = None,
        config_manager: Optional[PolicyConfigManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.adapter = adapter or SystemAdapter()
        # Dry-run must reach every writer, or simulated runs still touch real policy and audit files.
        self.config_manager = config_manager or PolicyConfigManager(dry_run=self.adapter.dry_run)
        self.audit = audit_logger or AuditLogger(dry_run=self.adapter.dry_run)

        self.users = UserManager(self.adapter)
        self.firewall = FirewallManager(self.adapter)
        self.dns_filter = DNSFilterManager(self.adapter)
        self.browser = BrowserPolicyManager(self.adapter)
        self.apparmor = AppArmorManager(self.adapter)
        self.app_guard = AppGuard(self.adapter, self.audit)

    def apply_policy(self, policy: FamilyPolicy, reason: str = "Provisioning baseline") -> Dict[str, Any]:
        """Validates, records, and applies the policy across all system layers.

        The policy is saved before any system change, so a failed apply leaves the intended
        state on disk. Every step is idempotent, so running the apply again converges.
        """
        # 1. Validation pass
        validation_errors = policy.validate()
        if validation_errors:
            raise ValueError(f"Policy validation failed: {'; '.join(validation_errors)}")

        results: Dict[str, Any] = {
            "success": True,
            "actions": [],
            "warnings": [],
        }

        # 2. Record intent before touching the system (no-op in dry-run)
        saved_path = self.config_manager.save_policy(policy, reason=reason)
        results["actions"].append(f"Policy saved to {saved_path}")

        try:
            self._apply_system_layers(policy, results)
        except Exception as exc:
            last = results["actions"][-1]
            raise ProvisioningError(
                f"Apply stopped after '{last}': {exc}. The policy is saved; run the apply again to finish."
            ) from exc

        self.audit.log(
            event_type="SYSTEM_PROVISIONED",
            user=policy.parent.username,
            severity="NOTICE",
            details={"actions_count": len(results["actions"]), "children_count": len(policy.children)},
        )

        return results

    def _apply_system_layers(self, policy: FamilyPolicy, results: Dict[str, Any]) -> None:
        """Applies each system layer in order, appending to results."""
        # Setup user privilege boundaries
        self.users.setup_security_groups()
        results["actions"].append("Security groups configured (family-parent, family-children)")

        # Provision parent
        self.users.provision_parent(policy.parent)
        results["actions"].append(f"Parent account '{policy.parent.username}' provisioned with sudo")

        # Provision children
        for child in policy.children:
            self.users.provision_child(child)
            results["actions"].append(f"Child account '{child.username}' provisioned (non-admin, home locked)")

        # 3. Apply Firewall baseline
        fw_actions = self.firewall.configure_baseline(policy.security)
        results["actions"].extend(fw_actions)

        # 4. Apply DNS and Host filtering
        # Use first child's DNS provider or default
        dns_prov = policy.children[0].web_filter.dns_provider if policy.children else "cleanbrowsing_family"
        dns_servers = self.dns_filter.configure_provider(dns_prov)
        results["actions"].append(f"DNS filter configured ({dns_prov}: {', '.join(dns_servers)})")

        all_blocked_domains: set[str] = set()
        for child in policy.children:
            all_blocked_domains.update(child.web_filter.blocked_domains)
        self.dns_filter.update_hosts_blocklist(list(all_blocked_domains))
        results["actions"].append(f"Domain blocklist updated ({len(all_blocked_domains)} domains)")

        # 5. Apply Managed Browser policies
        # Use strictest child policy or default
        if policy.children:
            ref_child = policy.children[0]
            self.browser.apply_browser_policies(ref_child.web_filter)
            results["actions"].append("Managed browser security policies deployed for Firefox & Chromium")

        # 6. Apply AppArmor profile. Always write it so it is ready once AppArmor is active.
        self.apparmor.install_profile()
        results["actions"].append("AppArmor child confinement profile installed")
        if not (self.apparmor.is_available() or self.adapter.dry_run):
            results["warnings"].append("AppArmor not active on this kernel; profile installed but not enforced")

        # 6b. Security updates: the policy requires them, so enable unattended upgrades.
        if policy.security.regular_security_updates:
            if self.adapter.run_command(["dpkg", "-s", "unattended-upgrades"]).returncode != 0:
                self.adapter.run_command(["apt-get", "install", "-y", "-q", "unattended-upgrades"])
            enable = self.adapter.run_command(["systemctl", "enable", "--now", "unattended-upgrades"])
            if enable.returncode == 0:
                results["actions"].append("Unattended security upgrades enabled")
            else:
                results["warnings"].append(
                    "Could not enable unattended-upgrades (is the package installed?); security updates may not run"
                )

        # 7. Apply desktop launcher restrictions
        # Approved apps are launched through the confinement profile only when AppArmor is active;
        # otherwise aa-exec would fail and the apps would not start.
        confine = self.apparmor.is_available()
        for child in policy.children:
            hidden, confined = self.app_guard.apply_child_desktop_filters(child, confine=confine)
            results["actions"].append(
                f"Child desktop menu filtered for '{child.username}' ({hidden} apps hidden, {confined} confined)"
            )

