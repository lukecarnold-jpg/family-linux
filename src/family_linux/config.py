"""Configuration and policy management for Family Linux.

Handles loading, validating, persisting, backing up, and restoring
the Family Linux policy configuration.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Optional, List
import yaml

from family_linux.models import (
    FamilyPolicy,
    ParentAccount,
    ChildAccount,
    SecurityPolicy,
    AgeTier,
)

DEFAULT_SYSTEM_CONFIG_PATH = Path("/etc/family-linux/policy.yaml")
DEFAULT_BACKUP_DIR = Path("/etc/family-linux/backups")
REPO_CONFIG_FALLBACK = Path(__file__).resolve().parent.parent.parent / "config" / "default-policy.yaml"


class PolicyConfigManager:
    """Manages policy file loading, saving, backup, and validation."""

    def __init__(self, config_path: Optional[Path | str] = None, dry_run: bool = False):
        if config_path:
            self.config_path = Path(config_path)
        else:
            # If running as root or system file exists, use system path; otherwise check fallback or local
            if os.path.exists(DEFAULT_SYSTEM_CONFIG_PATH):
                self.config_path = DEFAULT_SYSTEM_CONFIG_PATH
            elif os.access("/etc", os.W_OK):
                self.config_path = DEFAULT_SYSTEM_CONFIG_PATH
            else:
                # User-local runtime path for non-root testing/macOS
                user_home = Path.home()
                self.config_path = user_home / ".config" / "family-linux" / "policy.yaml"

        self.dry_run = dry_run
        self.backup_dir = self.config_path.parent / "backups"

    def ensure_directories(self) -> None:
        """Creates configuration and backup directories."""
        if not self.dry_run:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.backup_dir.mkdir(parents=True, exist_ok=True)

    def load_policy(self) -> FamilyPolicy:
        """Loads policy from file or initializes from defaults."""
        if self.config_path.exists():
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return FamilyPolicy.from_dict(data)

        # Fallback to repository baseline or generated baseline
        if REPO_CONFIG_FALLBACK.exists():
            with open(REPO_CONFIG_FALLBACK, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f) or {}
            return self._build_from_baseline_yaml(raw_data)

        # Default fallback
        return self.create_default_policy("parent", "Family Administrator")

    def _build_from_baseline_yaml(self, raw: dict) -> FamilyPolicy:
        parent = ParentAccount(
            username="parent",
            full_name="Family Administrator",
            role="local_admin",
            sudo_access=True,
            shell="/bin/bash",
        )
        security = SecurityPolicy()
        return FamilyPolicy(parent=parent, children=[], security=security)

    def create_default_policy(self, parent_username: str, parent_full_name: str) -> FamilyPolicy:
        """Generates a fresh default policy structure."""
        parent = ParentAccount(
            username=parent_username,
            full_name=parent_full_name,
            role="local_admin",
            sudo_access=True,
        )
        return FamilyPolicy(
            parent=parent,
            children=[],
            security=SecurityPolicy(),
        )

    def save_policy(self, policy: FamilyPolicy, reason: str = "Policy updated") -> Path:
        """Validates, creates a backup, and saves the policy to disk."""
        validation_errors = policy.validate()
        if validation_errors:
            raise ValueError(f"Policy validation failed: {'; '.join(validation_errors)}")

        if self.dry_run:
            return self.config_path

        self.ensure_directories()

        # Backup existing file if it exists
        if self.config_path.exists():
            self.create_backup(label=reason.replace(" ", "_").lower()[:32])

        dict_data = policy.to_dict()
        temp_path = self.config_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            yaml.dump(dict_data, f, default_flow_style=False, sort_keys=False)

        # Atomic replace
        os.replace(temp_path, self.config_path)
        try:
            os.chmod(self.config_path, 0o600)  # Restricted to root/admin
        except OSError:
            pass

        return self.config_path

    def create_backup(self, label: str = "snapshot") -> Path:
        """Creates a timestamped backup of the current policy."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Cannot backup nonexistent configuration: {self.config_path}")

        self.ensure_directories()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"policy_{timestamp}_{label}.yaml"
        shutil.copy2(self.config_path, backup_file)
        try:
            os.chmod(backup_file, 0o600)
        except OSError:
            pass
        return backup_file

    def list_backups(self) -> List[Path]:
        """Lists available backup files sorted chronologically (newest first)."""
        if not self.backup_dir.exists():
            return []
        files = list(self.backup_dir.glob("policy_*.yaml"))
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return files

    def restore_backup(self, backup_path: Path | str) -> FamilyPolicy:
        """Restores policy from a specified backup path."""
        b_path = Path(backup_path)
        if not b_path.exists():
            raise FileNotFoundError(f"Backup file not found: {b_path}")

        # Validate before applying
        with open(b_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        candidate = FamilyPolicy.from_dict(data)
        errors = candidate.validate()
        if errors:
            raise ValueError(f"Backup policy is invalid: {'; '.join(errors)}")

        if not self.dry_run:
            self.create_backup("pre_restore")
            shutil.copy2(b_path, self.config_path)

        return candidate
