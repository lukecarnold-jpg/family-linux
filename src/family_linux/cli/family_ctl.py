"""Command-line administration utility for Family Linux (family-ctl).

Allows parents to manage child accounts, application approvals, screen time limits,
web filtering, audit logs, and security verification.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from family_linux.config import PolicyConfigManager
from family_linux.models import (
    MIN_PASSWORD_LENGTH,
    MIN_PARENT_PASSWORD_LENGTH,
    FamilyPolicy,
    ChildAccount,
    AgeTier,
    DNSProvider,
    DEFAULT_APPROVED_APPS,
)
from family_linux.provisioner.system import SystemProvisioner
from family_linux.screentime.tracker import ScreenTimeTracker
from family_linux.audit.logger import AuditLogger
from family_linux.security.adapter import SystemAdapter
from family_linux.security.apparmor import PROFILE_PATH
from family_linux.security.browser import CHROMIUM_POLICY_PATH, FIREFOX_POLICY_PATH
from family_linux.security.password_policy import PAM_PASSWD_PATH, block_in_place
from family_linux.security.snap_policy import SnapInstallGate
from family_linux.security.users import SUDOERS_FILE
from family_linux.security.dns_gateway import clear_request, load_requests
from family_linux.security.web_gateway import REQUESTS_PATH


def format_table(headers: List[str], rows: List[List[str]]) -> str:
    """Formats a clean CLI text table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            if idx < len(col_widths):
                col_widths[idx] = max(col_widths[idx], len(str(val)))

    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_line = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    lines = [sep, header_line, sep]
    for row in rows:
        r_line = "| " + " | ".join(str(row[i]).ljust(col_widths[i]) if i < len(row) else "".ljust(col_widths[i]) for i in range(len(col_widths))) + " |"
        lines.append(r_line)
    lines.append(sep)
    return "\n".join(lines)


def _probe(cmd: List[str]) -> Optional[subprocess.CompletedProcess]:
    """Runs a read-only check command. Returns None when the tool is not installed."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return None


class FamilyCtl:
    """Core CLI command implementation."""

    def __init__(self, config_path: Optional[str] = None, dry_run: bool = False):
        self.config_manager = PolicyConfigManager(config_path=config_path, dry_run=dry_run)
        self.adapter = SystemAdapter(dry_run=dry_run)
        self.audit = AuditLogger(dry_run=dry_run)
        self.provisioner = SystemProvisioner(adapter=self.adapter, config_manager=self.config_manager, audit_logger=self.audit)
        self.tracker = ScreenTimeTracker(dry_run=dry_run)

    def cmd_status(self) -> None:
        policy = self.config_manager.load_policy()
        print("=" * 60)
        print("                FAMILY LINUX SYSTEM STATUS")
        print("=" * 60)
        print(f"Parent Administrator: {policy.parent.username} ({policy.parent.full_name})")
        print(f"Sudo Access:          Reserved exclusively for '{policy.parent.username}'")
        print(f"Total Child Accounts: {len(policy.children)}")
        print(f"Firewall Baseline:    Default Incoming: {policy.security.firewall_default.upper()}")
        print(f"Audit Logging:        {'ACTIVE' if policy.audit_logging else 'DISABLED'}")
        print("=" * 60)

        if policy.children:
            headers = ["Username", "Full Name", "Age Tier", "Daily Limit", "Curfew", "Used Today", "Status"]
            rows = []
            for c in policy.children:
                used = self.tracker.get_minutes_used(c.username)
                allowed, reason, remaining = self.tracker.evaluate_limits(c)
                status_str = "ACTIVE" if c.enabled and allowed else ("CURFEW" if not allowed else "DISABLED")
                rows.append([
                    c.username,
                    c.full_name,
                    c.age_tier,
                    f"{c.time_limits.daily_limit_minutes}m",
                    f"{c.time_limits.bedtime_weekday}",
                    f"{used}m",
                    status_str,
                ])
            print("\nCHILD ACCOUNTS:")
            print(format_table(headers, rows))
        else:
            print("\nNo child accounts created yet. Use 'family-ctl user add' to create one.")

    def cmd_user(self, args: argparse.Namespace) -> None:
        policy = self.config_manager.load_policy()

        if args.user_action == "list":
            headers = ["Role", "Username", "Full Name", "Age Tier", "Sudo", "Status"]
            rows = [
                ["Parent", policy.parent.username, policy.parent.full_name, "N/A", "YES", "ACTIVE"]
            ]
            for c in policy.children:
                rows.append([
                    "Child",
                    c.username,
                    c.full_name,
                    c.age_tier,
                    "NO (Blocked)",
                    "ENABLED" if c.enabled else "DISABLED",
                ])
            print(format_table(headers, rows))

        elif args.user_action == "add":
            if args.password is not None and len(args.password) < MIN_PASSWORD_LENGTH:
                print(f"[ERROR] Password must be at least {MIN_PASSWORD_LENGTH} characters.")
                sys.exit(1)
            tier = args.tier or AgeTier.PRE_TEEN.value
            child = ChildAccount.create(
                username=args.username,
                full_name=args.name or args.username.capitalize(),
                age_tier=tier,
                password=args.password,
            )
            policy.children.append(child)
            self.provisioner.apply_policy(policy, reason=f"Added child {args.username}")
            print(f"[OK] Child account '{args.username}' created successfully with {tier} tier preset.")

        elif args.user_action == "disable":
            found = False
            for c in policy.children:
                if c.username == args.username:
                    c.enabled = False
                    found = True
                    break
            if not found:
                print(f"[ERROR] Child user '{args.username}' not found.")
                sys.exit(1)
            self.provisioner.apply_policy(policy, reason=f"Disabled child {args.username}")
            print(f"[OK] Child account '{args.username}' disabled.")

        elif args.user_action == "enable":
            found = False
            for c in policy.children:
                if c.username == args.username:
                    c.enabled = True
                    found = True
                    break
            if not found:
                print(f"[ERROR] Child user '{args.username}' not found.")
                sys.exit(1)
            self.provisioner.apply_policy(policy, reason=f"Enabled child {args.username}")
            print(f"[OK] Child account '{args.username}' enabled.")

        elif args.user_action == "remove":
            orig_len = len(policy.children)
            policy.children = [c for c in policy.children if c.username != args.username]
            if len(policy.children) == orig_len:
                print(f"[ERROR] Child user '{args.username}' not found.")
                sys.exit(1)
            self.provisioner.users.delete_child(args.username)
            self.config_manager.save_policy(policy, reason=f"Removed child {args.username}")
            print(f"[OK] Child account '{args.username}' removed.")

    def cmd_app(self, args: argparse.Namespace) -> None:
        policy = self.config_manager.load_policy()

        if args.app_action == "presets":
            print("Default Approved Application Presets by Age Tier:")
            for tier, apps in DEFAULT_APPROVED_APPS.items():
                print(f"\n[{tier.upper()}]:")
                for app in apps:
                    print(f"  - {app}")

        elif args.app_action == "list":
            child = next((c for c in policy.children if c.username == args.username), None)
            if not child:
                print(f"[ERROR] Child user '{args.username}' not found.")
                sys.exit(1)
            print(f"Approved Applications for '{child.username}' (Tier: {child.age_tier}):")
            for a in child.app_policy.approved_apps:
                print(f"  [APPROVED] {a}")
            print(f"\nBlocked Applications/Binaries:")
            for b in child.app_policy.blocked_apps:
                print(f"  [BLOCKED]  {b}")

        elif args.app_action == "approve":
            child = next((c for c in policy.children if c.username == args.username), None)
            if not child:
                print(f"[ERROR] Child user '{args.username}' not found.")
                sys.exit(1)
            if args.app not in child.app_policy.approved_apps:
                child.app_policy.approved_apps.append(args.app)
                self.provisioner.apply_policy(policy, reason=f"Approved {args.app} for {child.username}")
                print(f"[OK] Approved application '{args.app}' for '{child.username}'.")
            else:
                print(f"Application '{args.app}' is already approved for '{child.username}'.")

        elif args.app_action == "revoke":
            child = next((c for c in policy.children if c.username == args.username), None)
            if not child:
                print(f"[ERROR] Child user '{args.username}' not found.")
                sys.exit(1)
            if args.app in child.app_policy.approved_apps:
                child.app_policy.approved_apps.remove(args.app)
                self.provisioner.apply_policy(policy, reason=f"Revoked {args.app} for {child.username}")
                print(f"[OK] Revoked application '{args.app}' for '{child.username}'.")
            else:
                print(f"Application '{args.app}' was not in the approved list for '{child.username}'.")

    def cmd_time(self, args: argparse.Namespace) -> None:
        policy = self.config_manager.load_policy()
        child = next((c for c in policy.children if c.username == args.username), None)
        if not child:
            print(f"[ERROR] Child user '{args.username}' not found.")
            sys.exit(1)

        if args.time_action == "show":
            used = self.tracker.get_minutes_used(child.username)
            allowed, reason, remaining = self.tracker.evaluate_limits(child)
            print(f"Screen Time & Curfew Policy for '{child.username}':")
            print(f"  Enabled:          {child.time_limits.enabled}")
            print(f"  Daily Quota:      {child.time_limits.daily_limit_minutes} minutes")
            print(f"  Used Today:       {used} minutes")
            print(f"  Remaining:        {remaining} minutes")
            print(f"  Bedtime (Week):   {child.time_limits.bedtime_weekday}")
            print(f"  Bedtime (End):    {child.time_limits.bedtime_weekend}")
            print(f"  Wake Time:        {child.time_limits.wake_time}")
            print(f"  Current Status:   {'ALLOWED' if allowed else 'LOCKED (' + reason + ')'}")

        elif args.time_action == "reset-usage":
            self.tracker.reset_usage(child.username)
            print(f"[OK] Reset screen time usage for '{child.username}' to 0 minutes for today.")

        elif args.time_action == "set":
            if args.daily_limit is not None:
                child.time_limits.daily_limit_minutes = args.daily_limit
            if args.bedtime_weekday is not None:
                child.time_limits.bedtime_weekday = args.bedtime_weekday
            if args.bedtime_weekend is not None:
                child.time_limits.bedtime_weekend = args.bedtime_weekend
            if args.wake_time is not None:
                child.time_limits.wake_time = args.wake_time
            self.config_manager.save_policy(policy, reason=f"Updated time limits for {child.username}")
            print(f"[OK] Updated screen time policy for '{child.username}'.")

    def cmd_web(self, args: argparse.Namespace) -> None:
        policy = self.config_manager.load_policy()

        if args.web_action == "status":
            prov = policy.children[0].web_filter.dns_provider if policy.children else "cleanbrowsing_family"
            print("Web Safety & DNS Protection:")
            print(f"  DNS Provider:     {prov}")
            safe = bool(policy.children) and all(c.web_filter.safe_search_enforced for c in policy.children)
            incognito = bool(policy.children) and all(c.web_filter.block_incognito for c in policy.children)
            devtools = bool(policy.children) and all(c.web_filter.disable_developer_tools for c in policy.children)
            print(f"  SafeSearch:       {'ENFORCED' if safe else 'NOT ENFORCED'} (Google, Bing, DuckDuckGo, YouTube)")
            print(f"  Incognito Mode:   {'BLOCKED' if incognito else 'ALLOWED'}")
            print(f"  Browser DevTools: {'DISABLED' if devtools else 'ENABLED'}")
            all_blocked = set()
            for c in policy.children:
                all_blocked.update(c.web_filter.blocked_domains)
            print(f"  Blocked Domains:  {len(all_blocked)} rules configured")
            for d in sorted(all_blocked)[:10]:
                print(f"    - {d}")
            if len(all_blocked) > 10:
                print(f"    ... and {len(all_blocked) - 10} more")

        elif args.web_action == "block":
            targets = self._web_targets(policy, args.child)
            for c in targets:
                if args.domain not in c.web_filter.blocked_domains:
                    c.web_filter.blocked_domains.append(args.domain)
            self.provisioner.apply_policy(policy, reason=f"Blocked domain {args.domain}")
            print(f"[OK] Blocked '{args.domain}' for {self._describe(targets)}.")

        elif args.web_action == "allow":
            targets = self._web_targets(policy, args.child)
            for c in targets:
                if args.domain not in c.web_filter.allowed_domains:
                    c.web_filter.allowed_domains.append(args.domain)
                if args.domain in c.web_filter.blocked_domains:
                    c.web_filter.blocked_domains.remove(args.domain)
            self.provisioner.apply_policy(policy, reason=f"Allowed domain {args.domain}")
            print(f"[OK] Allowed '{args.domain}' for {self._describe(targets)}.")

        elif args.web_action == "requests":
            requests = load_requests(REQUESTS_PATH)
            rows = []
            for child, names in sorted(requests.items()):
                for name, info in sorted(names.items()):
                    rows.append([child, name, str(info.get("count", 0)), str(info.get("reason", "")), str(info.get("last_seen", ""))])
            if not rows:
                print("No pending web requests.")
                return
            print(format_table(["Child", "Domain", "Attempts", "Reason", "Last seen"], rows))
            print("Approve with: family-ctl web approve CHILD DOMAIN   Dismiss with: family-ctl web deny CHILD DOMAIN")

        elif args.web_action == "approve":
            child = self._require_child(policy, args.child)
            if args.domain not in child.web_filter.allowed_domains:
                child.web_filter.allowed_domains.append(args.domain)
            if args.domain in child.web_filter.blocked_domains:
                child.web_filter.blocked_domains.remove(args.domain)
            self.provisioner.apply_policy(policy, reason=f"Approved {args.domain} for {child.username}")
            clear_request(REQUESTS_PATH, child.username, args.domain)
            print(f"[OK] Approved '{args.domain}' for '{child.username}'.")

        elif args.web_action == "deny":
            child = self._require_child(policy, args.child)
            clear_request(REQUESTS_PATH, child.username, args.domain)
            print(f"[OK] Dismissed request for '{args.domain}' from '{child.username}'. It stays blocked.")

    def _web_targets(self, policy: FamilyPolicy, username: Optional[str]) -> List[ChildAccount]:
        if username is None:
            return list(policy.children)
        return [self._require_child(policy, username)]

    def _require_child(self, policy: FamilyPolicy, username: str) -> ChildAccount:
        child = next((c for c in policy.children if c.username == username), None)
        if child is None:
            print(f"[ERROR] Child user '{username}' not found.")
            sys.exit(1)
        return child

    @staticmethod
    def _describe(targets: List[ChildAccount]) -> str:
        if len(targets) == 1:
            return f"'{targets[0].username}'"
        return f"{len(targets)} child account(s)"

    def cmd_audit(self, args: argparse.Namespace) -> None:
        records = self.audit.get_records(
            limit=args.limit,
            filter_user=args.user,
            filter_type=args.type,
        )
        if not records:
            print("No audit records matching criteria.")
            return

        headers = ["Timestamp", "Severity", "Event", "User", "Details"]
        rows = []
        for r in records:
            details_str = ", ".join(f"{k}={v}" for k, v in r.details.items())
            rows.append([r.timestamp, r.severity, r.event_type, r.user, details_str[:50]])
        print(format_table(headers, rows))

    def cmd_backup(self, args: argparse.Namespace) -> None:
        if args.backup_action == "create":
            label = args.label or "manual"
            path = self.config_manager.create_backup(label)
            print(f"[OK] Created policy backup at: {path}")

        elif args.backup_action == "list":
            backups = self.config_manager.list_backups()
            if not backups:
                print("No backups found.")
                return
            print(f"Found {len(backups)} backups:")
            for b in backups:
                print(f"  - {b.name} ({b.stat().st_size} bytes)")

        elif args.backup_action == "restore":
            restored = self.config_manager.restore_backup(args.file)
            self.provisioner.apply_policy(restored, reason=f"Restored from {args.file}")
            print(f"[OK] Successfully restored policy from {args.file}")

    def cmd_verify(self) -> None:
        """Checks the baseline. Live checks read real system state on Linux and are SKIPPED elsewhere."""
        policy = self.config_manager.load_policy()
        print("Auditing Family Linux Security Baseline...")

        results: List[Tuple[str, str, str]] = []  # (check name, PASS | FAIL | SKIP, note)

        def record(name: str, ok: bool, note: str) -> None:
            results.append((name, "PASS" if ok else "FAIL", note))

        def skip(name: str, note: str) -> None:
            results.append((name, "SKIP", note))

        # Policy model checks (always available)
        errors = policy.validate()
        record("Architecture policy model validation", not errors, "; ".join(errors) or "one parent, non-admin children")
        child_sudo = [c.username for c in policy.children if c.sudo_access]
        record("Child accounts barred from sudo privileges", not child_sudo, f"Violations: {child_sudo}" if child_sudo else "none")
        record(
            "Firewall default incoming deny (policy)",
            policy.security.firewall_default == "deny_incoming",
            policy.security.firewall_default,
        )

        # Live checks: only meaningful on the machine the policy is applied to
        if platform.system() != "Linux":
            for name in (
                "Parent sudoers drop-in present and valid",
                "UFW active with deny incoming",
                "Firefox managed policy installed",
                "Chromium managed policy installed",
                "AppArmor child profile loaded in enforce mode",
                "Unattended security updates enabled",
                "Parent password rules enforced by PAM",
                "Snap installs need the parent's password (polkit rule)",
            ):
                skip(name, "live check runs only on Linux")
        else:
            sudoers = Path(SUDOERS_FILE)
            sudoers_ok = sudoers.exists() and f"{policy.parent.username} ALL" in sudoers.read_text()
            record("Parent sudoers drop-in present", sudoers_ok, str(sudoers))
            if sudoers.exists():
                syntax = _probe(["visudo", "-cf", str(sudoers)])
                if syntax is None:
                    record("Sudoers drop-in syntax valid", False, "visudo not installed")
                else:
                    record("Sudoers drop-in syntax valid", syntax.returncode == 0, (syntax.stderr or syntax.stdout).strip())
            else:
                skip("Sudoers drop-in syntax valid", "drop-in missing")

            ufw = _probe(["ufw", "status", "verbose"])
            ufw_ok = bool(ufw and ufw.returncode == 0 and "Status: active" in ufw.stdout and "deny (incoming)" in ufw.stdout)
            record("UFW active with deny incoming", ufw_ok, "ufw status verbose" if ufw else "ufw not installed")

            for label, path in (("Firefox", FIREFOX_POLICY_PATH), ("Chromium", CHROMIUM_POLICY_PATH)):
                record(f"{label} managed policy installed", path.exists(), str(path))

            # Loaded and enforcing, as reported by the kernel, not just present on disk.
            aa = _probe(["aa-status"])
            if aa is None:
                record("AppArmor child profile loaded in enforce mode", False, "aa-status not installed")
            elif aa.returncode != 0:
                record("AppArmor child profile loaded in enforce mode", False, "AppArmor not active (aa-status failed)")
            else:
                enforce_section = aa.stdout.split("complain mode", 1)[0]
                loaded = "family-linux-child" in enforce_section
                record(
                    "AppArmor child profile loaded in enforce mode",
                    loaded,
                    "active in enforce mode" if loaded else "not loaded in enforce mode",
                )

            pam_text = PAM_PASSWD_PATH.read_text(encoding="utf-8") if PAM_PASSWD_PATH.exists() else ""
            record(
                "Parent password rules enforced by PAM",
                block_in_place(pam_text),
                f"{PAM_PASSWD_PATH}: pam_pwquality minlen={MIN_PARENT_PASSWORD_LENGTH} for parent accounts",
            )

            snap_gate = SnapInstallGate()
            record(
                "Snap installs need the parent's password (polkit rule)",
                snap_gate.is_in_place([c.username for c in policy.children]),
                str(snap_gate.rule_path),
            )

            updates = _probe(["systemctl", "is-enabled", "unattended-upgrades"])
            if updates is None:
                record("Unattended security updates enabled", False, "systemctl not available")
            else:
                state = updates.stdout.strip() or "not enabled"
                record("Unattended security updates enabled", state == "enabled", state)

        for name, status, note in results:
            print(f"  [{status}] {name}: {note}")

        failed = [r for r in results if r[1] == "FAIL"]
        skipped = [r for r in results if r[1] == "SKIP"]
        if failed:
            print(f"\n[FAIL] {len(failed)} baseline check(s) failed.")
            sys.exit(1)
        if skipped:
            print(f"\n[INCOMPLETE] All checks that ran passed; {len(skipped)} live check(s) were skipped on this host.")
        else:
            print("\n[SUCCESS] All baseline checks passed.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="family-ctl", description="Family Linux Parent Administration Tool")
    parser.add_argument("--config", type=str, help="Custom policy file path")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without system modification")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # status
    subparsers.add_parser("status", help="Show system status and child account limits")

    # verify
    subparsers.add_parser("verify", help="Audit security baseline compliance")

    # user
    user_p = subparsers.add_parser("user", help="Manage parent and child accounts")
    user_sp = user_p.add_subparsers(dest="user_action", required=True)
    user_sp.add_parser("list", help="List all accounts")

    add_p = user_sp.add_parser("add", help="Add a new child account")
    add_p.add_argument("username", help="Child username")
    add_p.add_argument("--name", help="Child full name")
    add_p.add_argument("--tier", choices=["young_child", "pre_teen", "teen"], default="pre_teen", help="Age preset tier")
    add_p.add_argument("--password", help="Account password")

    dis_p = user_sp.add_parser("disable", help="Disable child login")
    dis_p.add_argument("username", help="Child username")

    en_p = user_sp.add_parser("enable", help="Enable child login")
    en_p.add_argument("username", help="Child username")

    rm_p = user_sp.add_parser("remove", help="Delete child account")
    rm_p.add_argument("username", help="Child username")

    # app
    app_p = subparsers.add_parser("app", help="Manage application approvals")
    app_sp = app_p.add_subparsers(dest="app_action", required=True)
    app_sp.add_parser("presets", help="Show default app tiers")

    app_list_p = app_sp.add_parser("list", help="List approved apps for child")
    app_list_p.add_argument("username", help="Child username")

    app_appr_p = app_sp.add_parser("approve", help="Approve app for child")
    app_appr_p.add_argument("username", help="Child username")
    app_appr_p.add_argument("app", help="Application name or desktop entry")

    app_rev_p = app_sp.add_parser("revoke", help="Revoke app for child")
    app_rev_p.add_argument("username", help="Child username")
    app_rev_p.add_argument("app", help="Application name or desktop entry")

    # time
    time_p = subparsers.add_parser("time", help="Manage screen time and curfew")
    time_sp = time_p.add_subparsers(dest="time_action", required=True)

    time_show_p = time_sp.add_parser("show", help="Show screen time policy for child")
    time_show_p.add_argument("username", help="Child username")

    time_set_p = time_sp.add_parser("set", help="Configure screen time limits")
    time_set_p.add_argument("username", help="Child username")
    time_set_p.add_argument("--daily-limit", type=int, help="Daily screen time limit in minutes")
    time_set_p.add_argument("--bedtime-weekday", type=str, help="Weekday curfew (HH:MM)")
    time_set_p.add_argument("--bedtime-weekend", type=str, help="Weekend curfew (HH:MM)")
    time_set_p.add_argument("--wake-time", type=str, help="Morning wake time (HH:MM)")

    time_reset_p = time_sp.add_parser("reset-usage", help="Reset today's consumed screen time")
    time_reset_p.add_argument("username", help="Child username")

    # web
    web_p = subparsers.add_parser("web", help="Manage web filtering and DNS safety")
    web_sp = web_p.add_subparsers(dest="web_action", required=True)
    web_sp.add_parser("status", help="Show web filtering settings")

    web_blk_p = web_sp.add_parser("block", help="Add domain to a child's blocklist")
    web_blk_p.add_argument("domain", help="Domain name (e.g. example.com, or *.example for any host under example)")
    web_blk_p.add_argument("--child", help="Only this child (default: all children)")

    web_alw_p = web_sp.add_parser("allow", help="Add domain to a child's allowlist")
    web_alw_p.add_argument("domain", help="Domain name")
    web_alw_p.add_argument("--child", help="Only this child (default: all children)")

    web_sp.add_parser("requests", help="List blocked lookups waiting for a parent decision")

    web_apr_p = web_sp.add_parser("approve", help="Allow a requested domain for one child")
    web_apr_p.add_argument("child", help="Child username")
    web_apr_p.add_argument("domain", help="Requested domain")

    web_den_p = web_sp.add_parser("deny", help="Dismiss a requested domain (it stays blocked)")
    web_den_p.add_argument("child", help="Child username")
    web_den_p.add_argument("domain", help="Requested domain")

    # audit
    audit_p = subparsers.add_parser("audit", help="View security and policy audit logs")
    audit_p.add_argument("--limit", type=int, default=25, help="Number of records to show")
    audit_p.add_argument("--user", type=str, help="Filter by user")
    audit_p.add_argument("--type", type=str, help="Filter by event type")

    # backup
    bkp_p = subparsers.add_parser("backup", help="Manage policy backups and recovery")
    bkp_sp = bkp_p.add_subparsers(dest="backup_action", required=True)
    bkp_sp.add_parser("list", help="List available backups")
    bkp_create_p = bkp_sp.add_parser("create", help="Create a backup snapshot")
    bkp_create_p.add_argument("--label", help="Optional backup label")
    bkp_rst_p = bkp_sp.add_parser("restore", help="Restore policy from backup file")
    bkp_rst_p.add_argument("file", help="Path to backup YAML file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    ctl = FamilyCtl(config_path=args.config, dry_run=args.dry_run)

    if args.command == "status":
        ctl.cmd_status()
    elif args.command == "verify":
        ctl.cmd_verify()
    elif args.command == "user":
        ctl.cmd_user(args)
    elif args.command == "app":
        ctl.cmd_app(args)
    elif args.command == "time":
        ctl.cmd_time(args)
    elif args.command == "web":
        ctl.cmd_web(args)
    elif args.command == "audit":
        ctl.cmd_audit(args)
    elif args.command == "backup":
        ctl.cmd_backup(args)


if __name__ == "__main__":
    main()
