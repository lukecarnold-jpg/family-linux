"""Tests for Family Linux security components."""

import json
import pytest
from pathlib import Path
from family_linux.models import ParentAccount, ChildAccount, WebFilterPolicy, SecurityPolicy, AgeTier
from family_linux.security.adapter import SystemAdapter
from family_linux.security.users import UserManager, SUDOERS_FILE
from family_linux.security.firewall import FirewallManager
from family_linux.security.dns_filter import DNSFilterManager
from family_linux.security.browser import BrowserPolicyManager
from family_linux.security.app_guard import AppGuard
from family_linux.audit.logger import AuditLogger


def test_user_manager_provisions_parent_with_sudo():
    adapter = SystemAdapter(dry_run=True)
    mgr = UserManager(adapter)
    parent = ParentAccount(username="parent_dan", full_name="Dan Admin", sudo_access=True)

    mgr.provision_parent(parent)

    # Check sudoers file was written
    assert SUDOERS_FILE in adapter.simulated_files
    sudoers_content = adapter.simulated_files[SUDOERS_FILE]
    assert "parent_dan ALL=(ALL:ALL) ALL" in sudoers_content
    assert "%family-children ALL=(ALL:ALL) !ALL" in sudoers_content


def test_user_manager_provisions_child_without_sudo():
    adapter = SystemAdapter(dry_run=True)
    mgr = UserManager(adapter)
    child = ChildAccount.create("child_sam", "Sam Child")

    mgr.provision_child(child)

    # Check useradd command
    commands_str = [" ".join(cmd) for cmd in adapter.executed_commands]
    assert any("useradd" in c and "child_sam" in c for c in commands_str)
    # Check deletion from sudo group
    assert any("gpasswd -d child_sam sudo" in c for c in commands_str)


def test_firewall_manager_baseline_defaults():
    adapter = SystemAdapter(dry_run=True)
    fw = FirewallManager(adapter)
    actions = fw.configure_baseline()

    cmds = [" ".join(c) for c in adapter.executed_commands]
    assert any("ufw --force default deny incoming" in c for c in cmds)
    assert any("ufw --force default allow outgoing" in c for c in cmds)
    assert any("ufw --force enable" in c for c in cmds)


def test_dns_filter_configures_cleanbrowsing():
    adapter = SystemAdapter(dry_run=True)
    dns_mgr = DNSFilterManager(adapter)
    servers = dns_mgr.configure_provider("cleanbrowsing_family")

    assert "185.228.168.168" in servers
    resolved_file = "/etc/systemd/resolved.conf.d/family-linux-dns.conf"
    assert resolved_file in adapter.simulated_files
    assert "DNS=185.228.168.168" in adapter.simulated_files[resolved_file]


def test_browser_policy_generation():
    adapter = SystemAdapter(dry_run=True)
    bp = BrowserPolicyManager(adapter)
    web_filter = WebFilterPolicy(
        safe_search_enforced=True,
        block_incognito=True,
        disable_developer_tools=True,
        blocked_domains=["distracting.com"],
        allowed_domains=["wikipedia.org"],
    )

    ff = bp.generate_firefox_policy(web_filter)
    assert ff["policies"]["DisablePrivateBrowsing"] is True
    assert ff["policies"]["DisableDeveloperTools"] is True
    assert ff["policies"]["Preferences"]["browser.safesearch.enabled"] is True

    chromium = bp.generate_chromium_policy(web_filter)
    assert chromium["IncognitoModeAvailability"] == 1
    assert chromium["DeveloperToolsAvailability"] == 2
    assert chromium["ForceGoogleSafeSearch"] is True
    assert "https://distracting.com" in chromium["URLBlocklist"]


def test_app_guard_blocks_blacklisted_and_unapproved():
    adapter = SystemAdapter(dry_run=True)
    audit = AuditLogger(dry_run=True)
    guard = AppGuard(adapter, audit)

    child = ChildAccount.create("timmy", "Timmy", age_tier=AgeTier.YOUNG_CHILD)
    # Should allow approved app
    assert guard.is_app_allowed(child, "tuxpaint") is True

    # Should block dangerous terminal
    assert guard.is_app_allowed(child, "gnome-terminal") is False
    assert guard.is_app_allowed(child, "bash") is False
    assert guard.is_app_allowed(child, "sudo") is False

    # Should block unapproved application in allow-list mode
    assert guard.is_app_allowed(child, "steam") is False


def test_dry_run_propagates_to_policy_and_audit_writers():
    """A simulated provisioner must not write policy or audit files, even on a real Linux host."""
    from family_linux.provisioner.system import SystemProvisioner

    provisioner = SystemProvisioner(adapter=SystemAdapter(dry_run=True))
    assert provisioner.config_manager.dry_run is True
    assert provisioner.audit.dry_run is True
    assert provisioner.app_guard.audit.dry_run is True
