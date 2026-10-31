"""First boot on an installed Family Linux system: applies the full policy once.

The Debian installer (preseed and late command) creates the accounts. This step runs the rest of
the provisioning (firewall, DNS gateway, PAM and polkit rules, AppArmor, browser policy, desktop
lockdown) after the system has booted, when systemd, the network and the account database are all
available. A marker file stops it running again after a successful apply.

Run as: python3 -m family_linux.provisioner.firstboot [--policy FILE]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from family_linux.config import PolicyConfigManager
from family_linux.provisioner.system import ProvisioningError, SystemProvisioner

MARKER_PATH = Path("/var/lib/family-linux/firstboot.done")
POLICY_PATH = Path("/etc/family-linux/policy.yaml")


def run(policy_path: Optional[Path] = None, marker: Path = MARKER_PATH) -> int:
    """Returns the process exit code: 0 when the policy is applied or was already applied."""
    if marker.exists():
        print(f"First-boot provisioning already completed ({marker}).")
        return 0
    manager = PolicyConfigManager(policy_path or POLICY_PATH)
    policy = manager.load_policy()
    try:
        results = SystemProvisioner(config_manager=manager).apply_policy(policy, reason="First boot")
    except ProvisioningError as exc:
        print(f"First-boot provisioning failed: {exc}", file=sys.stderr)
        return 1
    for warning in results.get("warnings", []):
        print(f"warning: {warning}")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("applied\n", encoding="utf-8")
    print(f"First-boot provisioning complete: {len(results.get('actions', []))} actions.")
    return 0


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Apply the Family Linux policy once, on first boot")
    parser.add_argument("--policy", type=Path, default=None, help=f"Policy file (default {POLICY_PATH})")
    args = parser.parse_args(argv)
    sys.exit(run(args.policy))


if __name__ == "__main__":
    main()
