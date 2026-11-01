"""Parent password rules for every password change, through Debian's PAM password stack.

The installer checks the parent password it is given, but a parent can later change or reset it
with `passwd` (or `sudo passwd`). Those commands run the PAM "passwd" service, so the rules are
enforced there with pam_pwquality. Children are exempted by pam_succeed_if, so their passwords are
unchanged. The rules are written as a managed block in /etc/pam.d/passwd, before the shared
password stack, so pam_pwquality runs before the new password is stored.

Children are named one by one with `user = NAME`. That test compares the account being changed.
`ingroup` was tried first, but it checks the caller's groups, so root setting a child's password
was held to the parent rules.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Sequence

from family_linux.models import MIN_PARENT_PASSWORD_LENGTH
from family_linux.security.adapter import SystemAdapter

PAM_PASSWD_PATH = Path("/etc/pam.d/passwd")
BEGIN_MARKER = "# BEGIN family-linux parent password rules (managed; do not edit)"
END_MARKER = "# END family-linux parent password rules"
PWQUALITY_PACKAGE = "libpam-pwquality"
# pam_pwquality checks new passwords against the cracklib dictionary. Without it every change fails
# ("error loading dictionary"), so the parent could not change their password at all. The
# dictionary is only a recommended package, and installs without recommends leave it out.
DICTIONARY_PACKAGE = "cracklib-runtime"


def render_pam_block(children: Sequence[str]) -> List[str]:
    """Managed lines for /etc/pam.d/passwd, for the given child usernames.

    One line per child. If the account being changed is that child, success=N skips the other
    child lines and the pwquality line that follows them. Any other account falls through to
    pam_pwquality, which applies to the parent, and to root or sudo changing the parent's password
    (enforce_for_root).
    """
    lines = [BEGIN_MARKER]
    for index, name in enumerate(children, start=1):
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{2,31}", name):
            raise ValueError(f"Unsafe username for PAM rule: {name!r}")
        skip = len(children) - index + 1
        lines.append(f"password [success={skip} default=ignore] pam_succeed_if.so quiet user = {name}")
    lines.append(
        "password requisite pam_pwquality.so retry=3 enforce_for_root "
        f"minlen={MIN_PARENT_PASSWORD_LENGTH} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
    )
    lines.append(END_MARKER)
    return lines


def _without_block(lines: List[str]) -> List[str]:
    """Removes an earlier managed block so applying twice leaves one copy."""
    kept: List[str] = []
    skipping = False
    for line in lines:
        if line.strip() == BEGIN_MARKER:
            skipping = True
            continue
        if skipping:
            if line.strip() == END_MARKER:
                skipping = False
            continue
        kept.append(line)
    return kept


def insert_block(current: str, children: Sequence[str]) -> str:
    """Returns the PAM file with the managed block placed before the password stack.

    The block goes before the first password rule or the common-password include. If there is
    none, it is appended, since a file without a password stack cannot be enforced here anyway.
    """
    lines = _without_block(current.splitlines())
    block = render_pam_block(children)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"password\s", stripped) or stripped.startswith("@include common-password"):
            lines[index:index] = block
            break
    else:
        lines.extend(block)
    return "\n".join(lines) + "\n"


def block_in_place(content: str) -> bool:
    """True when the managed block is present with the required minimum length."""
    if BEGIN_MARKER not in content or END_MARKER not in content:
        return False
    return f"minlen={MIN_PARENT_PASSWORD_LENGTH}" in content and "pam_pwquality.so" in content


class ParentPasswordRules:
    """Installs the PAM rules that apply the parent password policy to password changes."""

    def __init__(self, adapter: Optional[SystemAdapter] = None, pam_path: Path = PAM_PASSWD_PATH):
        self.adapter = adapter or SystemAdapter()
        self.pam_path = pam_path

    def apply(self, child_usernames: Sequence[str]) -> List[str]:
        """Installs pwquality if needed and writes the PAM block for the current children. Returns warnings."""
        warnings: List[str] = []
        if self.adapter.run_command(["dpkg", "-s", PWQUALITY_PACKAGE]).returncode != 0:
            install = self.adapter.run_command(["apt-get", "install", "-y", "-q", PWQUALITY_PACKAGE])
            if install.returncode != 0:
                warnings.append(f"{PWQUALITY_PACKAGE} could not be installed; parent password rules are not enforced")
                return warnings
        if self.adapter.run_command(["dpkg", "-s", DICTIONARY_PACKAGE]).returncode != 0:
            install = self.adapter.run_command(["apt-get", "install", "-y", "-q", DICTIONARY_PACKAGE])
            if install.returncode != 0:
                warnings.append(f"{DICTIONARY_PACKAGE} could not be installed; password changes fail the dictionary check")

        # Dry run never reads the real file, so simulated output is the same on every host.
        current = self.pam_path.read_text(encoding="utf-8") if self.pam_path.exists() and not self.adapter.dry_run else ""
        self.adapter.write_system_file(self.pam_path, insert_block(current, child_usernames), mode=0o644)
        return warnings

    def is_in_place(self) -> bool:
        return self.pam_path.exists() and block_in_place(self.pam_path.read_text(encoding="utf-8"))
