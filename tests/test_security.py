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
    # URL rules are per child and enforced by the DNS gateway, not machine-wide browser policy.
    assert "URLBlocklist" not in chromium
    assert "WebsiteFilter" not in ff["policies"]

    # Brave: same settings, its own secure DNS off, and no Tor windows (the gateway cannot check them)
    brave = bp.generate_brave_policy(web_filter)
    assert brave["DnsOverHttpsMode"] == "off" and brave["IncognitoModeAvailability"] == 1
    assert brave["TorDisabled"] is True


def test_browser_policies_are_written_for_every_supported_browser():
    from family_linux.security.browser import (
        BRAVE_POLICY_PATH, CHROME_POLICY_PATH, CHROMIUM_POLICY_PATH, EDGE_POLICY_PATH, FIREFOX_POLICY_PATH,
    )

    adapter = SystemAdapter(dry_run=True)
    BrowserPolicyManager(adapter).apply_browser_policies(WebFilterPolicy())
    for path in (FIREFOX_POLICY_PATH, CHROMIUM_POLICY_PATH, CHROME_POLICY_PATH, EDGE_POLICY_PATH, BRAVE_POLICY_PATH):
        assert str(path) in adapter.simulated_files


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


def test_confined_profile_name_matches_desktop_wrapper():
    from family_linux.security.apparmor import CHILD_SESSION_PROFILE, PROFILE_NAME
    from family_linux.security.app_guard import AA_EXEC_PREFIX

    assert f"profile {PROFILE_NAME} " in CHILD_SESSION_PROFILE
    assert AA_EXEC_PREFIX == f"aa-exec -p {PROFILE_NAME} -- "


def test_child_desktop_filters_hide_unapproved_and_confine_approved(tmp_path):
    from family_linux.security.app_guard import AppGuard

    system_apps = tmp_path / "usr-share-applications"
    system_apps.mkdir()
    (system_apps / "tuxpaint.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=Tux Paint\nExec=tuxpaint %F\nIcon=tuxpaint\n"
    )
    (system_apps / "xterm.desktop").write_text("[Desktop Entry]\nType=Application\nName=XTerm\nExec=xterm\n")

    child = ChildAccount.create("kid", "Kid", age_tier="young_child", password="KidPass123!")
    adapter = SystemAdapter(dry_run=True)
    hidden, confined = AppGuard(adapter).apply_child_desktop_filters(
        child, confine=True, home_root=tmp_path / "home", app_dirs=[system_apps]
    )

    assert (hidden, confined) == (1, 1)
    home_apps = tmp_path / "home" / "kid" / ".local/share/applications"
    tux = adapter.simulated_files[str(home_apps / "tuxpaint.desktop")]
    assert "Exec=aa-exec -p family-linux-child -- tuxpaint %F" in tux
    assert "Name=Tux Paint" in tux
    xterm = adapter.simulated_files[str(home_apps / "xterm.desktop")]
    assert "NoDisplay=true" in xterm


def test_child_desktop_filters_do_not_confine_when_apparmor_inactive(tmp_path):
    from family_linux.security.app_guard import AppGuard

    system_apps = tmp_path / "apps"
    system_apps.mkdir()
    (system_apps / "tuxpaint.desktop").write_text("[Desktop Entry]\nName=Tux Paint\nExec=tuxpaint\n")
    child = ChildAccount.create("kid", "Kid", age_tier="young_child", password="KidPass123!")
    adapter = SystemAdapter(dry_run=True)

    hidden, confined = AppGuard(adapter).apply_child_desktop_filters(
        child, confine=False, home_root=tmp_path / "home", app_dirs=[system_apps]
    )
    assert (hidden, confined) == (0, 0)
    assert not adapter.simulated_files


def test_desktop_lockdown_applies_the_kiosk_to_children_only(tmp_path):
    from family_linux.security.desktop_lockdown import (
        CHILD_KDEGLOBALS_PATH, ENV_CONF_PATH, DesktopLockdown, lockdown_in_place, render_pam_block,
    )

    pam = tmp_path / "sddm"
    adapter = SystemAdapter(dry_run=True)
    assert DesktopLockdown(adapter, pam_path=pam, system_kdeglobals=tmp_path / "kdeglobals").apply() == []
    kiosk = adapter.simulated_files[str(CHILD_KDEGLOBALS_PATH)]
    assert "[KDE Action Restrictions][$i]" in kiosk
    for restriction in ("shell_access=false", "run_command=false", "action/run_command=false", "custom_config=false"):
        assert restriction in kiosk
    assert "XDG_CONFIG_DIRS\tOVERRIDE=/etc/xdg/family-linux-children:/etc/xdg" in adapter.simulated_files[str(ENV_CONF_PATH)]
    written_pam = adapter.simulated_files[str(pam)]
    assert "pam_succeed_if.so quiet user notingroup family-children" in written_pam
    # The skip must come straight before the pam_env line, or it would skip the wrong rule.
    block = render_pam_block()
    assert block[1].startswith("session [success=1 default=ignore]") and "pam_env.so" in block[2]
    assert lockdown_in_place(kiosk, written_pam)


def test_pam_block_keeps_sddms_own_rules_and_applies_once():
    from family_linux.security.desktop_lockdown import with_pam_block

    sddm = "#%PAM-1.0\n@include common-auth\nsession required pam_limits.so\n@include common-session\n"
    once = with_pam_block(sddm)
    assert once.startswith(sddm.rstrip("\n"))
    assert with_pam_block(once) == once
    assert once.count("pam_env.so") == 1


def test_lockdown_removes_the_old_system_wide_block_so_the_parent_gets_a_terminal_back(tmp_path):
    from family_linux.security.desktop_lockdown import BEGIN_MARKER, END_MARKER, without_system_block

    old = "[General]\nBrowserApplication=firefox-esr.desktop\n\n" + "\n".join(
        [BEGIN_MARKER, "[KDE Action Restrictions][$i]", "shell_access=false", END_MARKER]) + "\n"
    cleaned = without_system_block(old)
    assert "shell_access" not in cleaned and "BrowserApplication=firefox-esr.desktop" in cleaned


def test_lockdown_check_fails_when_the_pam_rule_is_missing():
    from family_linux.security.desktop_lockdown import lockdown_in_place, render_child_kdeglobals

    assert not lockdown_in_place(render_child_kdeglobals(), "@include common-session\n")


def test_terminal_programs_are_blocked_for_children():
    from family_linux.models import ALWAYS_BLOCKED_COMMANDS, DEFAULT_APPROVED_APPS

    for tier_apps in DEFAULT_APPROVED_APPS.values():
        for app in tier_apps:
            assert app.lower() not in ALWAYS_BLOCKED_COMMANDS
    for name in ("konsole", "org.kde.konsole", "yakuake", "xterm", "bash", "systemsettings"):
        assert name in ALWAYS_BLOCKED_COMMANDS


def test_hosts_blocklist_skips_wildcards_and_reports_them(tmp_path, monkeypatch):
    from family_linux.security.dns_filter import DNSFilterManager

    adapter = SystemAdapter(dry_run=True)
    skipped = DNSFilterManager(adapter).update_hosts_blocklist(["*.porn", "omegle.com"])
    assert skipped == ["*.porn"]
    hosts = adapter.simulated_files["/etc/hosts"]
    assert "0.0.0.0 omegle.com" in hosts
    assert "porn" not in hosts


DEBIAN_NSSWITCH = (
    "passwd:         files systemd\n"
    "hosts:          files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns\n"
    "networks:       files\n"
)


def test_lookups_are_routed_through_dns_so_the_child_gateway_sees_them():
    from family_linux.security.dns_filter import hosts_without_nss_resolve, lookups_use_dns

    assert not lookups_use_dns(DEBIAN_NSSWITCH)
    fixed = hosts_without_nss_resolve(DEBIAN_NSSWITCH)
    hosts = next(line for line in fixed.splitlines() if line.startswith("hosts:"))
    assert hosts.split()[1:] == ["files", "myhostname", "mdns4_minimal", "[NOTFOUND=return]", "dns"]
    assert lookups_use_dns(fixed)
    assert "passwd:         files systemd" in fixed  # other lines untouched
    assert hosts_without_nss_resolve(fixed) == fixed


def test_web_layer_removes_and_pins_nss_resolve(tmp_path):
    from family_linux.security.dns_filter import NSS_RESOLVE_PIN_PATH, DNSFilterManager

    adapter = SystemAdapter(dry_run=True)
    DNSFilterManager(adapter).route_lookups_through_dns(nsswitch_path=tmp_path / "missing")
    assert ["apt-get", "purge", "-y", "-q", "libnss-resolve"] in adapter.executed_commands
    assert "Pin-Priority: -1" in adapter.simulated_files[str(NSS_RESOLVE_PIN_PATH)]


def test_child_profile_lets_desktop_apps_run_but_still_denies_shells():
    from family_linux.security.apparmor import CHILD_SESSION_PROFILE as profile

    # Firefox: its own binary in /usr/lib, profile-folder locks, network, display, its sandbox
    for rule in ("/usr/lib/** mrix,", "owner @{HOME}/** rwkl,", "network inet stream,",
                 "#include <abstractions/wayland>", "userns,", "dbus,"):
        assert rule in profile, rule
    for rule in ("deny /{,usr/}bin/{,ba,da,z,fi}sh x,", "deny /usr/bin/pkexec x,", "deny /usr/bin/sudo x,",
                 "deny network inet raw,"):
        assert rule in profile, rule


def test_chrome_policy_keeps_the_childs_filter_able_to_see_site_names():
    from family_linux.models import WebFilterPolicy
    from family_linux.security.browser import BrowserPolicyManager

    manager = BrowserPolicyManager(SystemAdapter(dry_run=True))
    chrome = manager.generate_chromium_policy(WebFilterPolicy())
    assert chrome["EncryptedClientHelloEnabled"] is False
    assert chrome["DnsOverHttpsMode"] == "off"
    assert chrome["BrowserGuestModeEnabled"] is False and chrome["IncognitoModeAvailability"] == 1
    assert chrome["ForceYouTubeRestrict"] == 2 and chrome["ForceGoogleSafeSearch"] is True
    firefox = manager.generate_firefox_policy(WebFilterPolicy())["policies"]["Preferences"]
    assert firefox["network.dns.echconfig.enabled"] is False and firefox["network.trr.mode"] == 5


def test_chrome_can_run_for_a_child_and_is_approved_where_chromium_is():
    from family_linux.models import DEFAULT_APPROVED_APPS, AgeTier
    from family_linux.security.apparmor import CHILD_SESSION_PROFILE

    assert "/opt/** mrix," in CHILD_SESSION_PROFILE
    for tier in (AgeTier.PRE_TEEN, AgeTier.TEEN):
        assert "google-chrome" in DEFAULT_APPROVED_APPS[tier.value]
