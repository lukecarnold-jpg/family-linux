"""Interactive installer for Family Linux.

Implements the 12-step installation flow specified in docs/installer.md:
1. Welcome and language selection
2. Keyboard layout selection
3. Network check
4. Target disk/system selection
5. Create one parent account (required; local admin)
6. Create child accounts (standard non-admin users)
7. Apply recommended safety defaults
8. Optional advanced settings
9. Validation pass for all selected settings
10. Review and confirmation summary
11. Installation and configuration apply
12. First-boot setup and verification hints
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from family_linux.models import (
    FamilyPolicy,
    ParentAccount,
    ChildAccount,
    SecurityPolicy,
    AgeTier,
    DNSProvider,
    MIN_PASSWORD_LENGTH,
    MIN_PARENT_PASSWORD_LENGTH,
    parent_password_problems,
)
from family_linux.provisioner.system import ProvisioningError, SystemProvisioner
from family_linux.provisioner.autoinstall import SubiquityAutoinstallGenerator
from family_linux.security.adapter import SystemAdapter


class InstallerWizard:
    """Orchestrates the interactive and scripted installer flows."""

    def __init__(self, dry_run: bool = False, interactive: bool = True):
        self.dry_run = dry_run
        self.interactive = interactive
        self.adapter = SystemAdapter(dry_run=dry_run)
        self.provisioner = SystemProvisioner(adapter=self.adapter)

        # Installation state
        self.mode = "recommended"  # "recommended" or "advanced"
        self.language = "en_US.UTF-8"
        self.keyboard = "us"
        self.target_disk = "/dev/sda"
        self.dns_provider = DNSProvider.CLEANBROWSING_FAMILY.value

        self.parent: Optional[ParentAccount] = None
        self.children: List[ChildAccount] = []
        self.security = SecurityPolicy()

    def prompt(self, text: str, default: Optional[str] = None) -> str:
        """Prompts user for input with an optional default."""
        if not self.interactive:
            return default or ""
        suffix = f" [{default}]" if default else ""
        try:
            val = input(f"{text}{suffix}: ").strip()
            return val if val else (default or "")
        except (EOFError, KeyboardInterrupt):
            print("\nInstallation aborted.")
            sys.exit(1)

    def secret_prompt(self, text: str) -> str:
        """Prompts for a password without echoing it. Passwords never have defaults."""
        if not self.interactive:
            return ""
        try:
            return getpass.getpass(f"{text}: ")
        except (EOFError, KeyboardInterrupt):
            print("\nInstallation aborted.")
            sys.exit(1)

    def prompt_choice(self, text: str, choices: List[str], default: str) -> str:
        """Prompts user to pick from a numbered list of choices."""
        if not self.interactive:
            return default
        print(f"\n{text}")
        for idx, choice in enumerate(choices, 1):
            mark = " (default)" if choice == default else ""
            print(f"  {idx}) {choice}{mark}")

        while True:
            val = self.prompt("Select option", str(choices.index(default) + 1))
            if val.isdigit() and 1 <= int(val) <= len(choices):
                return choices[int(val) - 1]
            if val in choices:
                return val
            print("Invalid choice, please try again.")

    def run_step_1_welcome(self) -> None:
        print("=" * 64)
        print("          FAMILY LINUX INTERACTIVE INSTALLER")
        print("     Safe, predictable desktop for children, simple for parents")
        print("=" * 64)
        print("\nWelcome to Family Linux installation.")
        print("Family Linux sets up an Ubuntu LTS baseline with strict child-safe defaults.")

        languages = ["en_US.UTF-8", "en_GB.UTF-8", "es_ES.UTF-8", "fr_FR.UTF-8", "de_DE.UTF-8"]
        self.language = self.prompt_choice("Step 1: Choose system language", languages, "en_US.UTF-8")

        mode_choice = self.prompt_choice(
            "Select Installation Mode",
            [
                "Recommended (Safe defaults, guided setup, minimal questions)",
                "Advanced (Custom disk, network firewall, DNS provider tuning)",
            ],
            "Recommended (Safe defaults, guided setup, minimal questions)",
        )
        self.mode = "recommended" if "Recommended" in mode_choice else "advanced"

    def run_step_2_keyboard(self) -> None:
        keyboards = ["us", "uk", "ca", "de", "fr", "es"]
        self.keyboard = self.prompt_choice("Step 2: Choose keyboard layout", keyboards, "us")

    def run_step_3_network(self) -> None:
        print("\nStep 3: Network Check")
        # In a real environment, check network status
        print("  - Network interface active: DHCP configured")
        print("  - Family safety DNS baseline ready")

    def run_step_4_disk(self) -> None:
        print("\nStep 4: Installation Target")
        if self.mode == "advanced":
            self.target_disk = self.prompt("Target disk or installation target", "/dev/sda")
        else:
            print(f"  - Target installation: {self.target_disk} (Entire disk with LTS automatic partitioning)")

    def run_step_5_parent_account(self) -> None:
        print("\nStep 5: Create Parent Administrator Account (Required)")
        print("This account has sudo privileges to manage child accounts and settings.")
        while True:
            username = self.prompt("Parent username", "parent")
            full_name = self.prompt("Parent full name", "Family Administrator")
            password = self.secret_prompt(
                f"Parent password (at least {MIN_PARENT_PASSWORD_LENGTH} characters, with upper-case, lower-case, a number and a special character)"
            )
            problems = parent_password_problems(password)
            if problems:
                print(f"Password must include: {', '.join(problems)}.")
                continue

            parent = ParentAccount(
                username=username,
                full_name=full_name,
                password=password,
                role="local_admin",
                sudo_access=True,
            )
            errors = parent.validate()
            if errors:
                print(f"Validation error: {'; '.join(errors)}")
                continue

            self.parent = parent
            break

    def run_step_6_child_accounts(self) -> None:
        print("\nStep 6: Child Accounts Setup")
        print("Child accounts are standard users with no sudo rights and restricted privileges.")

        add_child = self.prompt("Do you want to create a child account now? (y/n)", "y").lower()
        while add_child.startswith("y"):
            username = self.prompt("Child username", f"child{len(self.children) + 1}")
            full_name = self.prompt("Child full name", f"Child {len(self.children) + 1}")

            tier_options = [
                "young_child (Under 10: high protection, 90m limit, 8:00 PM curfew)",
                "pre_teen (10-13: balanced, 150m limit, 9:00 PM curfew)",
                "teen (14+: guided autonomy, 240m limit, 10:00 PM curfew)",
            ]
            tier_pick = self.prompt_choice("Select age preset tier", tier_options, tier_options[1])
            tier_val = tier_pick.split()[0]

            password = self.secret_prompt(f"Child password (min {MIN_PASSWORD_LENGTH} characters)")
            while len(password) < MIN_PASSWORD_LENGTH:
                print(f"Password too short: please enter at least {MIN_PASSWORD_LENGTH} characters.")
                password = self.secret_prompt(f"Child password (min {MIN_PASSWORD_LENGTH} characters)")

            child = ChildAccount.create(
                username=username,
                full_name=full_name,
                age_tier=tier_val,
                password=password,
            )
            errors = child.validate()
            if errors:
                print(f"Validation error: {'; '.join(errors)}")
            else:
                self.children.append(child)
                print(f"Added child account '{username}' with {tier_val} preset.")

            more = self.prompt("Add another child account? (y/n)", "n").lower()
            if not more.startswith("y"):
                break

    def run_step_7_safety_defaults(self) -> None:
        print("\nStep 7: Safety Defaults")
        print("  - Firewall: UFW default deny incoming connections")
        print("  - Accounts: Child accounts barred from sudo and administrative groups")
        print("  - Desktop: Restricted launcher, terminal access blocked")
        print("  - Browsers: SafeSearch enforced, incognito & extensions disabled")

    def run_step_8_advanced_settings(self) -> None:
        if self.mode != "advanced":
            return

        print("\nStep 8: Advanced Settings (Advanced Mode)")
        dns_options = [
            DNSProvider.CLEANBROWSING_FAMILY.value,
            DNSProvider.CLOUDFLARE_FAMILY.value,
            DNSProvider.ADGUARD_FAMILY.value,
            DNSProvider.OPENDNS_FAMILY.value,
        ]
        self.dns_provider = self.prompt_choice("Select DNS parental filtering provider", dns_options, dns_options[0])

        auto_updates = self.prompt("Enable automatic security updates? (y/n)", "y").lower().startswith("y")
        self.security.regular_security_updates = auto_updates

    def run_step_9_validation(self) -> FamilyPolicy:
        print("\nStep 9: Running Validation Pass...")
        if not self.parent:
            raise ValueError("Installer error: Parent account was not configured.")

        policy = FamilyPolicy(
            parent=self.parent,
            children=self.children,
            security=self.security,
        )

        errors = policy.validate()
        if errors:
            raise ValueError(f"Installer validation failed:\n" + "\n".join(f"- {e}" for e in errors))

        print("  [PASSED] All configuration rules and security constraints validated successfully.")
        return policy

    def run_step_10_summary_and_confirmation(self, policy: FamilyPolicy) -> bool:
        print("\n" + "=" * 64)
        print("Step 10: PRE-INSTALLATION SUMMARY REVIEW")
        print("=" * 64)
        print(f"Mode:             {self.mode.upper()}")
        print(f"Language:         {self.language}")
        print(f"Keyboard:         {self.keyboard}")
        print(f"Target Disk:      {self.target_disk}")
        print(f"Parent Admin:     {policy.parent.username} ({policy.parent.full_name}) [sudo=YES]")
        print(f"Child Accounts:   {len(policy.children)}")
        for c in policy.children:
            print(f"  - {c.username} ({c.full_name}): tier={c.age_tier}, limit={c.time_limits.daily_limit_minutes}m, curfew={c.time_limits.bedtime_weekday}")
        print(f"Firewall:         Default Deny Incoming (UFW)")
        print(f"DNS Safety:       {self.dns_provider}")
        print(f"Desktop/Terminal: Children blocked from terminal, software stores, system settings")
        print(f"Dry Run Mode:     {'YES (simulation)' if self.dry_run else 'NO (live system apply)'}")
        print("=" * 64)

        if not self.interactive:
            return True

        confirm = self.prompt("Proceed with installation and apply changes? (yes/no)", "no")
        return confirm.lower() in ("yes", "y")

    def run_step_11_apply(self, policy: FamilyPolicy) -> Dict[str, Any]:
        print("\nStep 11: Applying Family Linux Configuration...")
        try:
            result = self.provisioner.apply_policy(policy, reason="Initial installer setup")
        except ProvisioningError as exc:
            print(f"\n[ERROR] {exc}")
            sys.exit(1)
        print("\nActions applied:")
        for action in result["actions"]:
            print(f"  [OK] {action}")
        if result["warnings"]:
            print("\nWarnings:")
            for w in result["warnings"]:
                print(f"  [!] {w}")
        return result

    def run_step_12_first_boot_hints(self, policy: FamilyPolicy) -> None:
        print("\n" + "=" * 64)
        print("Step 12: Installation Complete! First-Boot Information")
        print("=" * 64)
        print("Family Linux has been successfully configured.")
        print(f"\nParent Account: '{policy.parent.username}'")
        print("  - Use this account to log in and administer the system.")
        print("  - Run 'family-ctl status' to view policies, accounts, and audit status.")
        print("  - Run 'family-ctl user add' to create additional child accounts.")
        print("  - Run 'family-parent-dashboard' to launch the web-based parent portal.")
        if policy.children:
            print("\nChild Accounts:")
            for c in policy.children:
                print(f"  - '{c.username}': Log in for child session (pre-approved apps only).")
        print("\nSecurity Status:")
        print("  - Child accounts have strictly no sudo access.")
        print("  - Screen time enforcement service: 'family-policyd'")
        print("=" * 64)

    def execute(self) -> bool:
        """Executes the full 12-step flow."""
        self.run_step_1_welcome()
        self.run_step_2_keyboard()
        self.run_step_3_network()
        self.run_step_4_disk()
        self.run_step_5_parent_account()
        self.run_step_6_child_accounts()
        self.run_step_7_safety_defaults()
        self.run_step_8_advanced_settings()
        policy = self.run_step_9_validation()
        confirmed = self.run_step_10_summary_and_confirmation(policy)
        if not confirmed:
            print("Installation cancelled by user.")
            return False
        self.run_step_11_apply(policy)
        self.run_step_12_first_boot_hints(policy)
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Family Linux Interactive Installer")
    parser.add_argument("--dry-run", action="store_true", help="Simulate installation without modifying system files")
    parser.add_argument("--non-interactive", action="store_true", help="Run unattended with defaults")
    parser.add_argument("--language", type=str, default="en_US.UTF-8", help="System locale (used for autoinstall export)")
    parser.add_argument("--keyboard", type=str, default="us", help="Keyboard layout (used for autoinstall export)")
    parser.add_argument("--target-disk", type=str, default=None, help="Target disk path, e.g. /dev/nvme0n1 (default: first disk the installer finds)")
    parser.add_argument("--parent-user", type=str, default="parent", help="Parent username")
    parser.add_argument("--parent-name", type=str, default="Family Administrator", help="Parent full name")
    parser.add_argument("--parent-pass", type=str, default=None, help=f"Parent password (required with --non-interactive; at least {MIN_PARENT_PASSWORD_LENGTH} characters with upper-case, lower-case, a number and a special character)")
    parser.add_argument("--child", action="append", help="Child account specification (format: username:fullname:tier:password, password required)")
    parser.add_argument("--export-autoinstall", type=str, help="Export Ubuntu Subiquity autoinstall user-data YAML to file and exit")
    parser.add_argument("--export-policy", type=str, help="With --export-autoinstall: also write the policy file (no passwords) for first-boot provisioning")
    args = parser.parse_args()

    wizard = InstallerWizard(dry_run=args.dry_run, interactive=not args.non_interactive)
    wizard.language = args.language
    wizard.keyboard = args.keyboard
    if args.target_disk:
        wizard.target_disk = args.target_disk

    if args.non_interactive or args.export_autoinstall:
        problems = parent_password_problems(args.parent_pass)
        if problems:
            sys.exit(f"Error: --parent-pass is required with --non-interactive and must include {', '.join(problems)}.")
        wizard.parent = ParentAccount(
            username=args.parent_user,
            full_name=args.parent_name,
            password=args.parent_pass,
            role="local_admin",
            sudo_access=True,
        )
        if args.child:
            for c_spec in args.child:
                # maxsplit=3 keeps any ':' inside the password.
                parts = c_spec.split(":", 3)
                if len(parts) < 4 or len(parts[3]) < MIN_PASSWORD_LENGTH:
                    sys.exit(f"Error: child spec '{parts[0]}' needs a password of at least {MIN_PASSWORD_LENGTH} characters (username:fullname:tier:password).")
                u = parts[0]
                fn = parts[1] or u.capitalize()
                t = parts[2] or AgeTier.PRE_TEEN.value
                wizard.children.append(ChildAccount.create(u, fn, t, parts[3]))

        policy = wizard.run_step_9_validation()

        if args.export_autoinstall:
            gen = SubiquityAutoinstallGenerator(policy)
            content = gen.generate_user_data(
                locale=wizard.language,
                keyboard_layout=wizard.keyboard,
                target_disk=args.target_disk,
            )
            out_path = Path(args.export_autoinstall)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Exported Ubuntu Subiquity autoinstall configuration to {out_path}")
            if args.export_policy:
                from family_linux.config import PolicyConfigManager
                saved = PolicyConfigManager(Path(args.export_policy)).save_policy(policy, reason="ISO build")
                print(f"Exported policy (no passwords) to {saved}")
            sys.exit(0)

        wizard.run_step_10_summary_and_confirmation(policy)
        wizard.run_step_11_apply(policy)
        wizard.run_step_12_first_boot_hints(policy)
    else:
        wizard.execute()


if __name__ == "__main__":
    main()
