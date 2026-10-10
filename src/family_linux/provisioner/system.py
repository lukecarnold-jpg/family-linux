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


class SystemProvisioner:
    """Applies a complete Family Linux policy to the underlying system."""

    def __init__(
        self,
        adapter: Optional[SystemAdapter] = None,
        config_manager: Optional[PolicyConfigManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.adapter = adapter or SystemAdapter()
        self.config_manager = config_manager or PolicyConfigManager()
        self.audit = audit_logger or AuditLogger()

        self.users = UserManager(self.adapter)
        self.firewall = FirewallManager(self.adapter)
        self.dns_filter = DNSFilterManager(self.adapter)
        self.browser = BrowserPolicyManager(self.adapter)
        self.apparmor = AppArmorManager(self.adapter)
        self.app_guard = AppGuard(self.adapter, self.audit)

    def apply_policy(self, policy: FamilyPolicy, reason: str = "Provisioning baseline") -> Dict[str, Any]:
        """Validates and applies the policy across all system layers."""
        # 1. Validation pass
        validation_errors = policy.validate()
        if validation_errors:
            raise ValueError(f"Policy validation failed: {'; '.join(validation_errors)}")

        results: Dict[str, Any] = {
            "success": True,
            "actions": [],
            "warnings": [],
        }

        # 2. Setup user privilege boundaries
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

        # 6. Apply AppArmor profile
        if self.apparmor.is_available() or self.adapter.dry_run:
            self.apparmor.install_profile()
            results["actions"].append("AppArmor child confinement profile installed")
        else:
            results["warnings"].append("AppArmor not active on this kernel; profile written but not enforced")

        # 7. Apply desktop launcher restrictions
        for child in policy.children:
            hidden = self.app_guard.apply_child_desktop_filters(child)
            results["actions"].append(f"Child desktop menu filtered for '{child.username}' ({hidden} apps hidden)")

        # 8. Save policy & audit
        saved_path = self.config_manager.save_policy(policy, reason=reason)
        results["actions"].append(f"Policy saved to {saved_path}")

        self.audit.log(
            event_type="SYSTEM_PROVISIONED",
            user=policy.parent.username,
            severity="NOTICE",
            details={"actions_count": len(results["actions"]), "children_count": len(policy.children)},
        )

        return results
