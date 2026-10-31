"""Parent password rules for password changes: the PAM block that enforces them."""

from pathlib import Path

from family_linux.security.adapter import SystemAdapter
from family_linux.security.password_policy import (
    BEGIN_MARKER,
    END_MARKER,
    ParentPasswordRules,
    block_in_place,
    insert_block,
    render_pam_block,
)

DEBIAN_PASSWD = """#
# The PAM configuration file for the Shadow `passwd' service
#
# @include common-password
password\t[success=1 default=ignore]\tpam_unix.so obscure
"""


def test_block_requires_the_parent_length_and_classes():
    block = "\n".join(render_pam_block(["kid"]))
    assert "minlen=14" in block
    assert "ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" in block
    assert "enforce_for_root" in block


def test_children_are_exempted_by_name_not_by_caller_group():
    block = render_pam_block(["kid"])
    assert "pam_succeed_if.so quiet user = kid" in block[1]
    assert "ingroup" not in "\n".join(block)


def test_skip_counts_jump_past_the_remaining_child_lines_and_pwquality():
    block = render_pam_block(["alice", "bob", "carol"])
    # alice skips bob's line, carol's line and pwquality (3); carol skips only pwquality (1)
    assert "[success=3 default=ignore] pam_succeed_if.so quiet user = alice" in block[1]
    assert "[success=2 default=ignore] pam_succeed_if.so quiet user = bob" in block[2]
    assert "[success=1 default=ignore] pam_succeed_if.so quiet user = carol" in block[3]
    assert "pam_pwquality" in block[4]


def test_no_children_leaves_only_the_parent_rule():
    block = render_pam_block([])
    assert len(block) == 3 and "pam_pwquality" in block[1]


def test_unsafe_usernames_are_refused():
    import pytest
    with pytest.raises(ValueError):
        render_pam_block(["kid\nauth sufficient pam_permit.so"])


def test_block_goes_before_the_common_password_include():
    text = insert_block("#\n@include common-password\n", ["kid"])
    lines = text.splitlines()
    assert lines.index(BEGIN_MARKER) < lines.index("@include common-password")
    assert lines.index(END_MARKER) < lines.index("@include common-password")


def test_block_goes_before_the_first_password_rule_when_no_include():
    text = insert_block(DEBIAN_PASSWD, ["kid"])
    lines = text.splitlines()
    assert lines.index(END_MARKER) < lines.index(
        "password\t[success=1 default=ignore]\tpam_unix.so obscure"
    )
    assert "# The PAM configuration file" in text  # existing lines are kept


def test_applying_twice_leaves_one_block():
    once = insert_block(DEBIAN_PASSWD, ["kid"])
    twice = insert_block(once, ["kid"])
    assert twice == once
    assert twice.count(BEGIN_MARKER) == 1


def test_block_is_appended_when_the_file_has_no_password_rules():
    text = insert_block("# nothing here\n", ["kid"])
    assert text.rstrip().endswith(END_MARKER)


def test_block_in_place_checks_marker_and_minimum_length():
    assert block_in_place(insert_block(DEBIAN_PASSWD, ["kid"]))
    weak = insert_block(DEBIAN_PASSWD, ["kid"]).replace("minlen=14", "minlen=8")
    assert not block_in_place(weak)
    assert not block_in_place(DEBIAN_PASSWD)


def test_dry_run_writes_the_block_to_the_pam_path_without_touching_the_host(tmp_path):
    pam = tmp_path / "passwd"
    pam.write_text(DEBIAN_PASSWD)
    adapter = SystemAdapter(dry_run=True)
    rules = ParentPasswordRules(adapter, pam_path=pam)

    rules.apply(["kid"])

    simulated = adapter.simulated_files[str(pam)]
    assert BEGIN_MARKER in simulated and "minlen=14" in simulated
    assert pam.read_text() == DEBIAN_PASSWD  # the real file is unchanged in a dry run
