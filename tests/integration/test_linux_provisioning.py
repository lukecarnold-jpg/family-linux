"""Privileged integration tests that run real Linux account and firewall commands.

These tests only run when all of the following hold:
- the host is Linux
- the process is root
- FAMILY_LINUX_INTEGRATION=1 is set

They create and delete real accounts and rewrite /etc/sudoers.d drop-ins, so run
them only on a disposable VM or CI runner, never on a workstation.
"""

from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from family_linux.models import ChildAccount, ParentAccount
from family_linux.security.adapter import SystemAdapter
from family_linux.security.firewall import FirewallManager
from family_linux.security.users import SUDOERS_FILE, UserManager

pytestmark = pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and os.environ.get("FAMILY_LINUX_INTEGRATION") == "1"
    ),
    reason="requires Linux, root, and FAMILY_LINUX_INTEGRATION=1",
)


def _run(*cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True)


def _groups(username: str) -> set[str]:
    return set(_run("id", "-nG", username).stdout.split())


def _unique_name(prefix: str) -> str:
    # Usernames must be lowercase, start with a letter or underscore, and be 3-32 chars.
    return f"{prefix}{uuid.uuid4().hex[:8]}"


@pytest.fixture
def users() -> UserManager:
    return UserManager(SystemAdapter())


@pytest.fixture
def parent_name():
    name = _unique_name("fltp")
    yield name
    _run("userdel", "-r", name)


@pytest.fixture
def child_name():
    name = _unique_name("fltc")
    yield name
    _run("userdel", "-r", name)


@pytest.fixture
def sudoers_cleanup():
    yield
    Path(SUDOERS_FILE).unlink(missing_ok=True)


def test_parent_gets_sudo_and_valid_sudoers(users, parent_name, sudoers_cleanup):
    parent = ParentAccount(username=parent_name, full_name="Test Parent", password="TestPass123!")
    users.provision_parent(parent)

    assert "sudo" in _groups(parent_name)
    sudoers = Path(SUDOERS_FILE)
    assert sudoers.exists()
    check = _run("visudo", "-cf", str(sudoers))
    assert check.returncode == 0, check.stderr


def test_child_is_non_admin_with_private_home(users, child_name):
    child = ChildAccount.create(child_name, "Test Child", "pre_teen", password="ChildPass123!")
    users.provision_child(child)

    groups = _groups(child_name)
    assert not groups & {"sudo", "admin", "wheel", "adm", "family-parent"}
    assert "family-children" in groups

    mode = (Path("/home") / child_name).stat().st_mode & 0o777
    assert mode == 0o700


def test_disable_and_enable_lock_the_account(users, child_name):
    child = ChildAccount.create(child_name, "Test Child", "pre_teen", password="ChildPass123!")
    users.provision_child(child)

    users.disable_child(child_name)
    assert _run("passwd", "-S", child_name).stdout.split()[1] == "L"

    users.enable_child(child_name)
    assert _run("passwd", "-S", child_name).stdout.split()[1] == "P"


def test_firewall_baseline_is_active():
    if not _run("which", "ufw").stdout.strip():
        pytest.skip("ufw is not installed on this host")

    FirewallManager(SystemAdapter()).configure_baseline()
    status = _run("ufw", "status", "verbose").stdout
    assert "Status: active" in status
    assert "deny (incoming)" in status
