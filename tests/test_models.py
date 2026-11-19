"""Tests for Family Linux data models and policy constraints."""

import pytest
from family_linux.models import (
    STARTER_SITES,
    ParentAccount,
    ChildAccount,
    FamilyPolicy,
    SecurityPolicy,
    AgeTier,
    DNSProvider,
    TimeLimitPolicy,
    AppPolicy,
)


def test_parent_account_valid():
    parent = ParentAccount(
        username="parent",
        full_name="Family Admin",
        password="ValidPassword123!",
        role="local_admin",
        sudo_access=True,
    )
    assert parent.validate() == []


def test_parent_account_invalid():
    parent = ParentAccount(
        username="Bad User!",
        full_name="",
        sudo_access=False,
    )
    errors = parent.validate()
    assert len(errors) == 3
    assert any("Invalid parent username" in e for e in errors)
    assert any("full name is required" in e for e in errors)
    assert any("must have sudo access" in e for e in errors)


def test_child_account_valid():
    child = ChildAccount.create("alice", "Alice Arnold", age_tier=AgeTier.YOUNG_CHILD)
    assert child.validate() == []
    assert child.sudo_access is False
    assert child.time_limits.daily_limit_minutes == 90
    assert "tuxpaint" in child.app_policy.approved_apps


def test_child_account_cannot_have_sudo():
    child = ChildAccount(
        username="bob",
        full_name="Bob Arnold",
        role="standard_user",
        sudo_access=True,  # Violation
    )
    errors = child.validate()
    assert any("cannot have sudo access" in e for e in errors)


def test_child_account_cannot_have_admin_role():
    child = ChildAccount(
        username="bob",
        full_name="Bob Arnold",
        role="admin",  # Violation
        sudo_access=False,
    )
    errors = child.validate()
    assert any("role must be 'standard_user'" in e for e in errors)


def test_family_policy_requires_parent():
    policy = FamilyPolicy(parent=None)  # type: ignore
    errors = policy.validate()
    assert any("exactly one parent account is required" in e for e in errors)


def test_family_policy_detects_duplicate_usernames():
    parent = ParentAccount(username="luke", full_name="Luke Arnold", sudo_access=True)
    child1 = ChildAccount.create("luke", "Luke Junior")
    policy = FamilyPolicy(parent=parent, children=[child1])
    errors = policy.validate()
    assert any("Duplicate username detected" in e for e in errors)


def test_starter_sites_are_chosen_by_age_tier():
    young = ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.YOUNG_CHILD, password="ChildSecret12")
    teen = ChildAccount.create("kid2", "Kid Two", age_tier=AgeTier.TEEN, password="ChildSecret12")

    assert "pbskids.org" in young.web_filter.allowed_domains
    assert "wikipedia.org" not in young.web_filter.allowed_domains
    assert "britannica.com" in teen.web_filter.allowed_domains
    assert "pbskids.org" not in teen.web_filter.allowed_domains
    # Blocks are the same for every age
    assert young.web_filter.blocked_domains == teen.web_filter.blocked_domains


@pytest.mark.parametrize("tier", ["young_child", "pre_teen", "teen"])
def test_starter_site_covers_the_bare_name_and_its_subdomains(tier):
    from family_linux.security.dns_gateway import DomainRules

    rules = DomainRules(blocked=["*.adult"], allowed=STARTER_SITES[tier])
    for site in STARTER_SITES[tier]:
        assert rules.decide(site) == "allow", site
        assert rules.decide(f"www.{site}") == "allow", site
        assert rules.decide(f"not{site}") != "allow", site


def test_child_can_start_without_starter_sites():
    child = ChildAccount.create("kid3", "Kid Three", age_tier=AgeTier.PRE_TEEN, password="ChildSecret12", starter_sites=False)

    assert child.web_filter.allowed_domains == []
    assert "*.adult" in child.web_filter.blocked_domains


def test_age_tier_presets():
    young = TimeLimitPolicy.for_tier(AgeTier.YOUNG_CHILD)
    assert young.daily_limit_minutes == 90
    assert young.bedtime_weekday == "20:00"

    preteen = TimeLimitPolicy.for_tier(AgeTier.PRE_TEEN)
    assert preteen.daily_limit_minutes == 150
    assert preteen.bedtime_weekday == "21:00"

    teen = TimeLimitPolicy.for_tier(AgeTier.TEEN)
    assert teen.daily_limit_minutes == 240
    assert teen.bedtime_weekday == "22:00"


@pytest.mark.parametrize("password", ["Abcdefghijkl1!", "Abcdefghijklmn1!", "Abcdefghijklm1!x"])
def test_parent_password_meets_policy(password):
    from family_linux.models import parent_password_problems
    assert parent_password_problems(password) == []


@pytest.mark.parametrize(
    "password, missing",
    [
        ("Abcdefghij1!", "at least 14 characters"),          # 12 characters
        ("abcdefghijklmn1!", "an upper-case letter"),
        ("ABCDEFGHIJKLMN1!", "a lower-case letter"),
        ("Abcdefghijklmnop!", "a number"),
        ("Abcdefghijklmnop1", "a special character"),
        ("", "a password is required"),
        (None, "a password is required"),
    ],
)
def test_parent_password_reports_each_missing_rule(password, missing):
    from family_linux.models import parent_password_problems
    problems = parent_password_problems(password)
    assert any(missing in problem for problem in problems)


def test_parent_password_non_ascii_letters_do_not_count_as_special():
    from family_linux.models import parent_password_problems
    # Accented letters are not ASCII punctuation, so the special-character rule still fails.
    assert any("special" in p for p in parent_password_problems("Abcdefghijklmé1"))


def test_child_password_keeps_its_own_minimum():
    from family_linux.models import MIN_PASSWORD_LENGTH
    assert MIN_PASSWORD_LENGTH == 8
