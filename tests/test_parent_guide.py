"""Tests for the parent's HTML guide, its install step and its export."""

import re
from urllib.parse import quote_plus

import pytest

from family_linux.models import AgeTier, ChildAccount, FamilyPolicy, ParentAccount, STARTER_SITES
from family_linux.parent_guide import BRACKETS, GUIDE_FILE_NAME, render_guide_html, search_url
from family_linux.provisioner.preseed import DebianPreseedGenerator


def make_policy(*children: ChildAccount) -> FamilyPolicy:
    parent = ParentAccount(username="parent", full_name="Family Admin", password="SuperSecretPassword!", sudo_access=True)
    return FamilyPolicy(parent=parent, children=list(children))


def test_guide_lists_each_childs_starter_sites_for_their_age():
    young = ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.YOUNG_CHILD, password="ChildSecret12")
    teen = ChildAccount.create("kid2", "Kid Two", age_tier=AgeTier.TEEN, password="ChildSecret12")
    page = render_guide_html(make_policy(young, teen))

    for site in STARTER_SITES[AgeTier.YOUNG_CHILD.value]:
        assert site in page
    for site in STARTER_SITES[AgeTier.TEEN.value]:
        assert site in page
    assert "britannica.com" in page
    assert "Under 10" in page and "14 and over" in page


def test_guide_shows_none_for_a_child_who_started_without_sites():
    child = ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.PRE_TEEN, password="ChildSecret12", starter_sites=False)
    page = render_guide_html(make_policy(child))

    assert "<td>none</td>" in page


@pytest.mark.parametrize("tier", [AgeTier.YOUNG_CHILD.value, AgeTier.PRE_TEEN.value, AgeTier.TEEN.value])
def test_each_age_bracket_links_to_a_google_search(tier):
    _, query = BRACKETS[tier]
    url = search_url(tier)

    assert url == "https://www.google.com/search?q=" + quote_plus(query)
    child = ChildAccount.create("kid1", "Kid One", age_tier=tier, password="ChildSecret12")
    assert url in render_guide_html(make_policy(child))


def test_guide_has_no_scripts_and_loads_nothing_from_the_internet():
    child = ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.PRE_TEEN, password="ChildSecret12")
    page = render_guide_html(make_policy(child))

    assert "<script" not in page.lower()
    assert "<link" not in page.lower()
    assert "<img" not in page.lower()
    assert "@import" not in page
    # The only web addresses in the page are the three Google search links, and they are the links that are there
    found = set(re.findall(r'(?:href|src)="(https?://[^"]+)"', page))
    assert found, "the search links are missing"
    assert found <= {search_url(t) for t in BRACKETS}


def test_each_child_row_shows_only_that_childs_sites():
    young = ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.YOUNG_CHILD, password="ChildSecret12")
    teen = ChildAccount.create("kid2", "Kid Two", age_tier=AgeTier.TEEN, password="ChildSecret12")
    page = render_guide_html(make_policy(young, teen))

    rows = {row for row in re.findall(r"<tr>.*?</tr>", page) if "<code>kid" in row}
    row_for = {name: next(r for r in rows if f"<code>{name}</code>" in r) for name in ("kid1", "kid2")}

    assert "pbskids.org" in row_for["kid1"] and "britannica.com" not in row_for["kid1"]
    assert "britannica.com" in row_for["kid2"] and "pbskids.org" not in row_for["kid2"]


def test_names_from_the_policy_are_escaped():
    child = ChildAccount.create("kid1", "<script>alert(1)</script>", age_tier=AgeTier.PRE_TEEN, password="ChildSecret12")
    page = render_guide_html(make_policy(child))

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_late_script_puts_the_guide_on_the_parents_desktop_and_gives_it_to_the_parent():
    child = ChildAccount.create("kid1", "Kid One", age_tier=AgeTier.PRE_TEEN, password="ChildSecret12")
    late = DebianPreseedGenerator(make_policy(child)).generate_late_script()

    install_line = f'install -m 644 $PAYLOAD/{GUIDE_FILE_NAME} "$T"/home/parent/Desktop/{GUIDE_FILE_NAME}'
    mkdir_line = "in-target mkdir -p /home/parent/Desktop"
    chown_line = "in-target chown -R parent:parent /home/parent/Desktop"
    assert install_line in late
    assert late.index(mkdir_line) < late.index(install_line) < late.index(chown_line)


def test_wizard_export_writes_the_guide_beside_the_preseed(monkeypatch, tmp_path):
    from family_linux.installer import wizard as wizard_module

    out = tmp_path / "user-data"
    monkeypatch.setattr("sys.argv", [
        "family-installer", "--dry-run", "--non-interactive", "--export-preseed", str(out),
        "--parent-pass", "Correct-Horse-42",
        "--child", "kid1:Kid One:young_child:ChildSecret12",
    ])
    with pytest.raises(SystemExit) as exc:
        wizard_module.main()
    assert exc.value.code == 0

    guide = (out.parent / GUIDE_FILE_NAME).read_text(encoding="utf-8")
    assert guide.startswith("<!doctype html>")
    assert "Family Linux: guide for the parent" in guide
    assert "pbskids.org" in guide
