"""System provisioning and configuration application engine for Family Linux.

Orchestrates user management, sudoers policy, firewall, DNS filter,
browser configuration, AppArmor, PackageKit install gate, and desktop menu restrictions.
"""

from __future__ import annotations

from typing import Dict, Any, Iterable, List, Optional
from pathlib import Path

from family_linux.models import FamilyPolicy, MIN_PARENT_PASSWORD_LENGTH, WebFilterPolicy
from family_linux.security.adapter import SystemAdapter
from family_linux.security.users import UserManager
from family_linux.security.firewall import FirewallManager
from family_linux.security.dns_filter import DNSFilterManager
from family_linux.security.browser import BrowserPolicyManager
from family_linux.security.apparmor import AppArmorManager
from family_linux.security.password_policy import ParentPasswordRules
from family_linux.security.package_gate import PackageInstallGate
from family_linux.security.desktop_refresh import PATH_UNIT_NAME, WATCHED_DIRS, PATH_UNIT_PATH, SERVICE_UNIT_PATH, render_path_unit, render_service_unit
from family_linux.security.app_guard import AppGuard
from family_linux.security.desktop_lockdown import DesktopLockdown
from family_linux.security.child_startup import ChildStartupLock
from family_linux.security.web_gateway import WebGateway
from family_linux.config import PolicyConfigManager
from family_linux.audit.logger import AuditLogger


# The system layers, in the order a full apply runs them. A change made in Family Controls or
# family-ctl re-applies only the layers it affects (see cli/family_ctl.py).
ALL_LAYERS = ("timezone", "accounts", "firewall", "web", "browsers", "apparmor", "updates", "desktop", "apps")
# A new child needs the accounts, the rules that name children (PAM, polkit, web filter, desktop
# lockdown) and a menu. Turning sign-in on or off only locks or unlocks the account.
CHILD_ADDED_LAYERS = ("accounts", "web", "desktop", "apps")
CHILD_SIGN_IN_LAYERS = ("accounts",)
APP_LAYERS = ("apps",)
WEB_LAYERS = ("web",)


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
        self.parent_password_rules = ParentPasswordRules(self.adapter)
        self.package_gate = PackageInstallGate(self.adapter)
        self.app_guard = AppGuard(self.adapter, self.audit)
        self.web_gateway = WebGateway(self.adapter)

    def apply_policy(
        self,
        policy: FamilyPolicy,
        reason: str = "Provisioning baseline",
        layers: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Validates, records, and applies the policy across the system layers (all of them by default).

        The policy is saved before any system change, so a failed apply leaves the intended
        state on disk. Every step is idempotent, so running the apply again converges.
        """
        selected = set(ALL_LAYERS if layers is None else layers)
        unknown = selected - set(ALL_LAYERS)
        if unknown:
            raise ValueError(f"Unknown layers: {', '.join(sorted(unknown))}")
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
            self._apply_system_layers(policy, results, selected)
        except Exception as exc:
            last = results["actions"][-1]
            raise ProvisioningError(
                f"Apply stopped after '{last}': {exc}. The policy is saved; run the apply again to finish."
            ) from exc

        self.audit.log(
            event_type="SYSTEM_PROVISIONED",
            user=policy.parent.username,
            severity="NOTICE",
            details={
                "actions_count": len(results["actions"]),
                "children_count": len(policy.children),
                "layers": [name for name in ALL_LAYERS if name in selected],
            },
        )

        return results

    def _install_menu_refresh_units(self, results: Dict[str, Any]) -> None:
        for directory in WATCHED_DIRS:
            self.adapter.run_command(["mkdir", "-p", str(directory)])
        self.adapter.write_system_file(SERVICE_UNIT_PATH, render_service_unit(), mode=0o644)
        self.adapter.write_system_file(PATH_UNIT_PATH, render_path_unit(), mode=0o644)
        self.adapter.run_command(["systemctl", "daemon-reload"])
        enabled = self.adapter.run_command(["systemctl", "enable", "--now", PATH_UNIT_NAME])
        if enabled.returncode == 0:
            results["actions"].append("Child app menus refresh when apps are installed or removed")
        else:
            results["warnings"].append(f"{PATH_UNIT_NAME} could not be enabled; new apps stay visible until the next apply")

    def _apply_system_layers(self, policy: FamilyPolicy, results: Dict[str, Any], layers: set) -> None:
        """Applies the selected system layers in order, appending to results."""
        if "timezone" in layers:
            self._apply_timezone(policy, results)
        if "accounts" in layers:
            self._apply_accounts(policy, results)
        if "firewall" in layers:
            results["actions"].extend(self.firewall.configure_baseline(policy.security))
        if "web" in layers:
            self._apply_web(policy, results)
        if "browsers" in layers:
            # Security settings only; URL rules are per child (web layer). Written even with no
            # children, so the browsers are configured before the first account exists.
            ref_web_filter = policy.children[0].web_filter if policy.children else WebFilterPolicy()
            self.browser.apply_browser_policies(ref_web_filter)
            results["actions"].append("Managed browser security policies deployed for Firefox & Chromium")
        if "apparmor" in layers:
            # Always write the profile so it is ready once AppArmor is active.
            self.apparmor.install_profile()
            results["actions"].append("AppArmor child confinement profile installed")
            if not (self.apparmor.is_available() or self.adapter.dry_run):
                results["warnings"].append("AppArmor not active on this kernel; profile installed but not enforced")
        if "updates" in layers:
            self._apply_updates(policy, results)
        if "desktop" in layers and policy.children:
            self._apply_desktop(policy, results)
        if "apps" in layers:
            # Approved apps are launched through the confinement profile only when AppArmor is active;
            # otherwise aa-exec would fail and the apps would not start.
            confine = self.apparmor.is_available()
            for child in policy.children:
                hidden, confined = self.app_guard.apply_child_desktop_filters(child, confine=confine)
                results["actions"].append(
                    f"Child desktop menu filtered for '{child.username}' ({hidden} apps hidden, {confined} confined)"
                )
            # Keep menus in step with installs and removals between full applies
            self._install_menu_refresh_units(results)

    def _apply_timezone(self, policy: FamilyPolicy, results: Dict[str, Any]) -> None:
        # Curfews and bedtimes are evaluated in local time.
        if policy.timezone:
            tz = self.adapter.run_command(["timedatectl", "set-timezone", policy.timezone])
            if tz.returncode == 0:
                results["actions"].append(f"Time zone set to {policy.timezone}")
            else:
                results["warnings"].append(f"Could not set the time zone to {policy.timezone}; curfews use the system's current time zone")

    def _apply_accounts(self, policy: FamilyPolicy, results: Dict[str, Any]) -> None:
        # Groups, the parent, then the rules that name the children, then the children.
        self.users.setup_security_groups()
        results["actions"].append("Security groups configured (family-parent, family-children)")

        self.users.provision_parent(policy.parent)
        results["actions"].append(f"Parent account '{policy.parent.username}' provisioned with sudo")

        # Parent password rules apply to every later password change (passwd, sudo passwd, desktop dialogs)
        for warning in self.parent_password_rules.apply([child.username for child in policy.children]):
            results["warnings"].append(warning)
        results["actions"].append(f"Parent password rules ({MIN_PARENT_PASSWORD_LENGTH}+ chars, mixed classes) enforced on password changes")

        # Software: every install, removal or update by a child account needs the parent's password
        for warning in self.package_gate.apply([child.username for child in policy.children]):
            results["warnings"].append(warning)
        results["actions"].append("Software changes by child accounts require the parent's password on every attempt")

        for child in policy.children:
            self.users.provision_child(child)
            results["actions"].append(f"Child account '{child.username}' provisioned (non-admin, home locked)")

    def _apply_web(self, policy: FamilyPolicy, results: Dict[str, Any]) -> None:
        # Family DNS for the machine, using the first child's provider or the default
        dns_prov = policy.children[0].web_filter.dns_provider if policy.children else "cleanbrowsing_family"
        dns_servers = self.dns_filter.configure_provider(dns_prov)
        results["actions"].append(f"DNS filter configured ({dns_prov}: {', '.join(dns_servers)})")

        # Per-child web rules are enforced by the DNS gateway. Clear any machine-wide hosts block
        # left by earlier versions, because it would also block the parent.
        self.dns_filter.update_hosts_blocklist([])

        # Per-child DNS gateway: blocks, allows, and request logging for each child
        for warning in self.web_gateway.apply(policy):
            results["warnings"].append(warning)
        results["actions"].append(f"Per-child web filter applied to {len(policy.children)} child account(s)")

    def _apply_updates(self, policy: FamilyPolicy, results: Dict[str, Any]) -> None:
        # Security updates: the policy requires them, so enable unattended upgrades.
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

        # The web browser. The preseed installs firefox-esr; this only reinstalls it if it was
        # removed, so children always have a browser that reads the managed policy.
        if self.adapter.run_command(["dpkg", "-s", "firefox-esr"]).returncode != 0:
            install = self.adapter.run_command(["apt-get", "install", "-y", "-q", "firefox-esr"])
            if install.returncode == 0:
                results["actions"].append("Firefox ESR installed (apt)")
            else:
                results["warnings"].append("Could not install Firefox ESR; children have no browser until it is installed")

    def _apply_desktop(self, policy: FamilyPolicy, results: Dict[str, Any]) -> None:
        # Lock the desktop entry points that AppArmor cannot confine (shell, Alt+F2 run dialog)
        for warning in DesktopLockdown(self.adapter).apply():
            results["warnings"].append(warning)
        results["actions"].append("Desktop lockdown applied for children (Alt+F2 run dialog and shell access locked)")
        # Without this a child could undo the lockdown, or start a shell, from a sign-in script.
        startup_lock = ChildStartupLock(self.adapter, self.audit)
        for child in policy.children:
            results["warnings"].extend(startup_lock.apply(child))
        results["actions"].append("Children's sign-in startup files locked (profile, autostart, Plasma env, systemd user units)")

