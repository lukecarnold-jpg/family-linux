"""The parent's guide, written to the parent's desktop when Family Linux is installed.

The guide is one HTML file. It has no scripts and loads nothing from the internet. Its only links
are Google search pages, one for each age bracket, which open only when the parent clicks them.
The lists in it come from `STARTER_SITES`, the same lists the installer offers.
"""

from __future__ import annotations

import html
from typing import Dict, Tuple
from urllib.parse import quote_plus

from family_linux.models import AgeTier, FamilyPolicy

GUIDE_FILE_NAME = "family-linux-parent-guide.html"

# The age bracket shown to parents, and the search each one links to.
BRACKETS: Dict[str, Tuple[str, str]] = {
    AgeTier.YOUNG_CHILD.value: ("Under 10", "safe educational websites for children under 10"),
    AgeTier.PRE_TEEN.value: ("10 to 13", "safe educational websites for children aged 10 to 13"),
    AgeTier.TEEN.value: ("14 and over", "safe educational websites for teenagers aged 14 and over"),
}

STYLE = """
body { font-family: system-ui, sans-serif; line-height: 1.5; max-width: 42em; margin: 0 auto; padding: 1em 1.2em; color: #1d1d1f; background: #ffffff; }
h1 { font-size: 1.6em; }
h2 { font-size: 1.25em; margin-top: 1.6em; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; border-bottom: 1px solid #cccccc; padding: .45em .5em; vertical-align: top; }
code { background: #f2f2f2; padding: 0 .25em; border-radius: 3px; }
a { color: #0b57d0; }
@media (prefers-color-scheme: dark) {
  body { color: #e8e8e8; background: #1e1e1e; }
  code { background: #333333; }
  th, td { border-color: #555555; }
  a { color: #8ab4f8; }
}
"""


def bracket_for(tier: str) -> Tuple[str, str]:
    """The (label, search text) for an age tier. Unknown tiers use the pre-teen bracket, as the policy does."""
    return BRACKETS.get(tier, BRACKETS[AgeTier.PRE_TEEN.value])


def search_url(tier: str) -> str:
    return "https://www.google.com/search?q=" + quote_plus(bracket_for(tier)[1])


def render_guide_html(policy: FamilyPolicy) -> str:
    """The complete HTML page for this policy. Every value from the policy is escaped."""
    if policy.children:
        rows = []
        for child in policy.children:
            label, _ = bracket_for(child.age_tier)
            sites = [html.escape(d.removeprefix("*.")) for d in child.web_filter.allowed_domains]
            allowed = ", ".join(sites) if sites else "none"
            rows.append(
                "<tr>"
                f"<td>{html.escape(child.full_name)}<br><code>{html.escape(child.username)}</code></td>"
                f"<td>{html.escape(label)}</td>"
                f"<td>{allowed}</td>"
                f'<td><a href="{search_url(child.age_tier)}">Search for sites</a></td>'
                "</tr>"
            )
        children_html = (
            "<table>\n"
            "<tr><th>Child</th><th>Age bracket</th><th>Sites allowed at installation</th><th></th></tr>\n"
            + "\n".join(rows)
            + "\n</table>"
        )
    else:
        children_html = "<p>No child accounts were set up during the installation. Add one with Family Controls.</p>"

    search_items = "\n".join(
        f'<li>{html.escape(label)}: <a href="{search_url(tier)}">search Google for {html.escape(query)}</a></li>'
        for tier, (label, query) in BRACKETS.items()
    )

    parent = html.escape(policy.parent.full_name or policy.parent.username)
    example_user = html.escape(policy.children[0].username) if policy.children else "CHILD"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Family Linux: guide for the parent</title>
<style>{STYLE}</style>
</head>
<body>
<h1>Family Linux: guide for the parent</h1>
<p>Hello, {parent}. This guide is on your desktop. It was written when Family Linux was installed, so it shows the sites each child started with. It does not change when you change the settings later. Family Controls always shows the current settings.</p>
<p>This page does not connect to the internet. The search links below open Google only when you click them.</p>

<h2>Your children</h2>
{children_html}

<h2>Find sites for each age</h2>
<p>These are Google searches. Family Linux does not check the results. Look at a site before you allow it (see the checklist below).</p>
<ul>
{search_items}
</ul>

<h2>Allow or block a site</h2>
<ol>
<li>Open <b>Family Controls</b> from the application menu and enter your password.</li>
<li>Click your child's name, then find <b>Websites</b>.</li>
<li>Type the site (for example <code>example.com</code>) in <b>Always allow a website</b> or in the block box, and press Apply.</li>
</ol>
<p>In the terminal, type <code>sudo family-ctl web allow example.com --child {example_user}</code> to allow a site, or <code>sudo family-ctl web block example.com --child {example_user}</code> to block one. Use your child's user name from the table above.</p>

<h2>Website requests</h2>
<p>When your child tries a blocked site, it appears under <b>Website requests</b> in Family Controls. You decide whether to allow it.</p>

<h2>Before you allow a site</h2>
<ul>
<li>Open it yourself first, from your own account.</li>
<li>Check who runs it, and whether it is made for children, for schools or for the public.</li>
<li>Be careful with sites that have chat rooms, comments, open video feeds, shopping or sign-up forms.</li>
<li>If you are not sure, leave it blocked and ask.</li>
</ul>
</body>
</html>
"""
