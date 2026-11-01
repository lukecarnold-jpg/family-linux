"""First boot on an installed Family Linux system: applies the full policy once.

The Debian installer (preseed and late command) creates the accounts. This step runs the rest of
the provisioning (firewall, DNS gateway, PAM and polkit rules, AppArmor, browser policy, desktop
lockdown) after the system has booted, when systemd, the network and the account database are all
available. A marker file stops it running again after a successful apply.

Run as: python3 -m family_linux.provisioner.firstboot [--policy FILE]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Optional

from family_linux.config import PolicyConfigManager
from family_linux.provisioner.system import ProvisioningError, SystemProvisioner

MARKER_PATH = Path("/var/lib/family-linux/firstboot.done")
INSTALL_FAILURES_PATH = Path("/var/lib/family-linux/install-failures")  # written by the late command
# Written by the late command of appliance builds only: power off once the policy is applied, so the
# disk is exported from a clean shutdown (the arm64 VirtualBox guest ignores the ACPI power button).
POWEROFF_FLAG = Path("/etc/family-linux/poweroff-after-firstboot")
GRUB_DEFAULT_PATH = Path("/etc/default/grub")
SERIAL_CONSOLES = ("console=ttyAMA0", "console=ttyS0")


def without_serial_console(grub_default: str) -> str:
    """Removes the build's serial console from the kernel command line in /etc/default/grub.

    The appliance build boots with console=ttyAMA0 (arm64) or ttyS0 so it can watch the first boot.
    An imported appliance has no serial port, and with the console still set the desktop never
    appeared (seen in VirtualBox: SDDM stayed black until a serial port was attached).
    """
    lines = []
    for line in grub_default.splitlines():
        if line.startswith("GRUB_CMDLINE_LINUX") and "=" in line:
            key, _, value = line.partition("=")
            quote = '"' if value.startswith('"') else ""
            words = [w for w in value.strip('"').split() if w not in SERIAL_CONSOLES]
            line = f"{key}={quote}{' '.join(words)}{quote}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _drop_serial_console(path: Path = GRUB_DEFAULT_PATH) -> None:
    if not path.exists():
        return
    current = path.read_text(encoding="utf-8")
    updated = without_serial_console(current)
    if updated != current:
        path.write_text(updated, encoding="utf-8")
        subprocess.run(["update-grub"], check=False)
POLICY_PATH = Path("/etc/family-linux/policy.yaml")


def installer_failures(path: Path = INSTALL_FAILURES_PATH) -> List[str]:
    """Installer late-command steps that failed (see provisioner/preseed.py). Empty when none or no file."""
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _finish_appliance() -> None:
    """Appliance builds: no serial console on the exported system, then power off."""
    _drop_serial_console()
    subprocess.run(["systemctl", "poweroff", "--no-block"], check=False)


def run(
    policy_path: Optional[Path] = None,
    marker: Path = MARKER_PATH,
    failures_path: Path = INSTALL_FAILURES_PATH,
    poweroff_flag: Path = POWEROFF_FLAG,
    power_off: Callable[[], None] = _finish_appliance,
) -> int:
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
    # The apply re-does most late-command steps, but a failure there is still worth seeing.
    for step in installer_failures(failures_path):
        print(f"warning: installer step failed: {step}")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("applied\n", encoding="utf-8")
    print(f"First-boot provisioning complete: {len(results.get('actions', []))} actions.")
    if poweroff_flag.exists():
        poweroff_flag.unlink()  # only once: the appliance boots normally after import
        print("Appliance build: powering off.")
        power_off()
    return 0


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Apply the Family Linux policy once, on first boot")
    parser.add_argument("--policy", type=Path, default=None, help=f"Policy file (default {POLICY_PATH})")
    args = parser.parse_args(argv)
    sys.exit(run(args.policy))


if __name__ == "__main__":
    main()
