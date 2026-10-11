"""SHA-512 crypt for the autoinstall password hashes. Vectors were produced by glibc's crypt()
(Ubuntu 24.04, Python 3.12), so the same hash works on Ubuntu's /etc/shadow."""

import pytest

from family_linux.provisioner.autoinstall import SubiquityAutoinstallGenerator
from family_linux.provisioner.sha512crypt import sha512_crypt
from family_linux.models import FamilyPolicy, ParentAccount

GLIBC_VECTORS = [
    ("Correct-Horse-42-Battery", "60c067849ce1db31", "$6$60c067849ce1db31$VjxF"),
    ("x", "abcdefgh", "$6$abcdefgh$D7W7qyozKBT."),
    ("p" * 100, "0123456789abcdef", "$6$0123456789abcdef$CH/k"),
    ("", "salt", "$6$salt$r6qPcj2UeIkfklWH"),
    ("password", "saltsalt", "$6$saltsalt$qFmFH.bQmmtX"),
]


@pytest.mark.parametrize("password, salt, prefix", GLIBC_VECTORS)
def test_matches_glibc(password, salt, prefix):
    full = sha512_crypt(password, salt)
    assert full.startswith(prefix)


def test_user_data_hashes_are_valid_sha512_crypt():
    policy = FamilyPolicy(parent=ParentAccount("parent", "Parent", password="Correct-Horse-42-Battery"))
    text = SubiquityAutoinstallGenerator(policy).generate_user_data(locale="en_US.UTF-8", keyboard_layout="us")
    line = next(l for l in text.splitlines() if l.strip().startswith("password:"))
    stored = line.split("password:", 1)[1].strip()
    salt = stored.split("$")[2]
    assert stored == sha512_crypt("Correct-Horse-42-Battery", salt)
    assert stored.startswith("$6$") and len(stored.split("$")[3]) == 86
