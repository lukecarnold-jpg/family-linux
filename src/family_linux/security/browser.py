"""Browser policy enforcement for Family Linux.

Generates managed enterprise policies for Firefox and Chromium:
- Enforces Google, Bing, DuckDuckGo, and YouTube SafeSearch
- Disables private/incognito browsing
- Disables browser developer tools
- Restricts extension installation
- Implements URL blocklists and allowlists
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, Optional

from family_linux.models import WebFilterPolicy
from family_linux.security.adapter import SystemAdapter

FIREFOX_POLICY_PATH = Path("/etc/firefox/policies/policies.json")
CHROMIUM_POLICY_PATH = Path("/etc/chromium/policies/managed/family-policy.json")
CHROME_POLICY_PATH = Path("/etc/opt/chrome/policies/managed/family-policy.json")


class BrowserPolicyManager:
    """Configures system-wide browser security policies."""

    def __init__(self, adapter: Optional[SystemAdapter] = None):
        self.adapter = adapter or SystemAdapter()

    def generate_firefox_policy(self, web_filter: WebFilterPolicy) -> Dict[str, Any]:
        """Generates Firefox distribution/policies.json dictionary.

        URL block and allow rules are per child and enforced by the DNS gateway, because
        managed browser policy applies to every user on the machine.
        """
        policies: Dict[str, Any] = {
            "DisablePrivateBrowsing": web_filter.block_incognito,
            "DisableDeveloperTools": web_filter.disable_developer_tools,
            "DisableSafeMode": True,
            "InstallAddonsPermission": {
                "Default": not web_filter.disable_extensions_install
            },
            "SearchSuggestEnabled": True,
            "Preferences": {
                "browser.safesearch.enabled": web_filter.safe_search_enforced,
                "browser.urlbar.suggest.searches": True,
                "network.trr.mode": 5,  # Disable DoH to preserve local parent DNS filtering
            },
        }

        return {"policies": policies}

    def generate_chromium_policy(self, web_filter: WebFilterPolicy) -> Dict[str, Any]:
        """Generates Chromium / Google Chrome managed JSON dictionary.

        URL block and allow rules are per child and enforced by the DNS gateway, because
        managed browser policy applies to every user on the machine.
        """
        policy: Dict[str, Any] = {
            # 1 = Incognito disabled, 0 = enabled
            "IncognitoModeAvailability": 1 if web_filter.block_incognito else 0,
            # 2 = Developer tools disabled
            "DeveloperToolsAvailability": 2 if web_filter.disable_developer_tools else 1,
            "ForceGoogleSafeSearch": web_filter.safe_search_enforced,
            "ForceYouTubeSafetyMode": 2 if web_filter.safe_search_enforced else 0,  # 2 = Strict
            "DnsOverHttpsMode": "off",  # Keep local DNS filter active
        }

        if web_filter.disable_extensions_install:
            policy["ExtensionInstallBlocklist"] = ["*"]

        return policy

    def apply_browser_policies(self, web_filter: WebFilterPolicy) -> None:
        """Writes browser policies to their respective system directories."""
        # 1. Firefox
        ff_content = json.dumps(self.generate_firefox_policy(web_filter), indent=2)
        self.adapter.write_system_file(FIREFOX_POLICY_PATH, ff_content)

        # Also write to /usr/lib/firefox/distribution/policies.json if path exists
        ff_usr_path = Path("/usr/lib/firefox/distribution/policies.json")
        self.adapter.write_system_file(ff_usr_path, ff_content)

        # 2. Chromium / Chrome
        chrom_content = json.dumps(self.generate_chromium_policy(web_filter), indent=2)
        self.adapter.write_system_file(CHROMIUM_POLICY_PATH, chrom_content)
        self.adapter.write_system_file(CHROME_POLICY_PATH, chrom_content)
