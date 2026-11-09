"""Data models and policy definitions for Family Linux.

Enforces the core design constraints:
- One parent account (local administrator with sudo)
- Zero or more child accounts (non-admin, restricted)
- Conservative, auditable security defaults
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
import re
import string

from family_linux.timezones import is_valid_timezone

MIN_PASSWORD_LENGTH = 8  # child accounts
MIN_PARENT_PASSWORD_LENGTH = 14
CLOCK = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")  # 24-hour HH:MM
MINUTES_PER_DAY = 24 * 60


def parent_password_problems(password: Optional[str]) -> List[str]:
    """Lists the parent password rules that are not met; an empty list means the password is acceptable.

    Character classes are ASCII only: upper case A-Z, lower case a-z, digits 0-9, and any of
    the ASCII punctuation characters as the special character.
    """
    if not password:
        return ["a password is required"]
    problems = []
    if len(password) < MIN_PARENT_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PARENT_PASSWORD_LENGTH} characters")
    if not re.search(r"[A-Z]", password):
        problems.append("an upper-case letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lower-case letter")
    if not re.search(r"[0-9]", password):
        problems.append("a number")
    if not any(char in string.punctuation for char in password):
        problems.append("a special character (for example ! @ # $ %)")
    return problems


class AgeTier(str, Enum):
    YOUNG_CHILD = "young_child"  # Under 10: high protection, 90m limit, 8:00 PM curfew
    PRE_TEEN = "pre_teen"        # 10-13: balanced, 150m limit, 9:00 PM curfew
    TEEN = "teen"                # 14+: guided autonomy, 240m limit, 10:00 PM curfew
    CUSTOM = "custom"            # Custom parent configuration


class DNSProvider(str, Enum):
    CLEANBROWSING_FAMILY = "cleanbrowsing_family"  # Blocks adult content, phishing, enforces safe search
    CLOUDFLARE_FAMILY = "cloudflare_family"        # 1.1.1.3 - Blocks malware and adult content
    ADGUARD_FAMILY = "adguard_family"              # Family protection filter + safe search
    OPENDNS_FAMILY = "opendns_family"              # FamilyShield default protection
    CUSTOM = "custom"


DNS_SERVERS: Dict[str, List[str]] = {
    DNSProvider.CLEANBROWSING_FAMILY.value: ["185.228.168.168", "185.228.169.168"],
    DNSProvider.CLOUDFLARE_FAMILY.value: ["1.1.1.3", "1.0.0.3"],
    DNSProvider.ADGUARD_FAMILY.value: ["94.140.14.15", "94.140.15.16"],
    DNSProvider.OPENDNS_FAMILY.value: ["208.67.222.123", "208.67.220.123"],
}

# Desktop entry ids for the apps each age preset shows. Matching is exact, apart from the families
# in APP_FAMILIES (see approved_entries_matching).
DEFAULT_APPROVED_APPS: Dict[str, List[str]] = {
    AgeTier.YOUNG_CHILD.value: [
        "tuxpaint",
        "org.kde.kcalc",
        "org.kde.discover",
        "firefox-esr",
        "vlc",
    ],
    AgeTier.PRE_TEEN.value: [
        "tuxpaint",
        "libreoffice",
        "org.kde.kcalc",
        "org.kde.discover",
        "firefox-esr",
        "chromium",
        "google-chrome",
        "vlc",
        "org.kde.kwrite",
    ],
    AgeTier.TEEN.value: [
        "libreoffice",
        "org.kde.kcalc",
        "org.kde.discover",
        "firefox-esr",
        "chromium",
        "google-chrome",
        "vlc",
        "org.kde.kwrite",
        "gimp",
        "org.inkscape.Inkscape",
        "audacity",
    ],
    AgeTier.CUSTOM.value: [
        "firefox-esr",
        "libreoffice",
        "org.kde.kcalc",
        "org.kde.discover",
        "vlc",
    ],
}

ALWAYS_BLOCKED_COMMANDS: List[str] = [
    "konsole",
    "org.kde.konsole",
    "yakuake",
    "org.kde.yakuake",
    "qterminal",
    "xterm",
    "uxterm",
    "xfce4-terminal",
    "tilix",
    "lxterminal",
    "mate-terminal",
    "gnome-terminal",
    "alacritty",
    "kitty",
    "foot",
    "rxvt",
    "terminator",
    "sh",
    "bash",
    "zsh",
    "sudo",
    "su",
    "pkexec",
    "apt",
    "apt-get",
    "dpkg",
    "aptitude",
    "synaptic",
    "flatpak",
    "snap",
    "systemsettings",
    "org.kde.systemsettings",
    "kcmshell6",
    "org.familylinux.parent",  # the parent's Family Controls app
    # Other browsers, such as Brave or Edge, are not blocked; the browser rules in browser.py apply to them.
]


@dataclass
class TimeLimitPolicy:
    enabled: bool = True
    daily_limit_minutes: int = 120
    bedtime_weekday: str = "20:30"
    bedtime_weekend: str = "21:30"
    wake_time: str = "07:00"
    warning_minutes: List[int] = field(default_factory=lambda: [15, 5, 1])

    def validate(self, username: str) -> List[str]:
        """The screen time service reads these every minute, so a bad value must not be saved."""
        errors = []
        for label, value in (
            ("weekday bedtime", self.bedtime_weekday),
            ("weekend bedtime", self.bedtime_weekend),
            ("wake time", self.wake_time),
        ):
            if not isinstance(value, str) or not CLOCK.match(value):
                errors.append(f"Child '{username}': {label} '{value}' must be a 24-hour time such as 20:30.")
        if not isinstance(self.daily_limit_minutes, int) or not 0 <= self.daily_limit_minutes <= MINUTES_PER_DAY:
            errors.append(f"Child '{username}': daily limit must be between 0 and {MINUTES_PER_DAY} minutes.")
        if not all(isinstance(m, int) and 0 < m <= MINUTES_PER_DAY for m in self.warning_minutes):
            errors.append(f"Child '{username}': warning times must be whole minutes between 1 and {MINUTES_PER_DAY}.")
        return errors

    @classmethod
    def for_tier(cls, tier: AgeTier | str) -> TimeLimitPolicy:
        tier_str = tier.value if isinstance(tier, AgeTier) else tier
        if tier_str == AgeTier.YOUNG_CHILD.value:
            return cls(daily_limit_minutes=90, bedtime_weekday="20:00", bedtime_weekend="20:30", wake_time="07:30")
        elif tier_str == AgeTier.PRE_TEEN.value:
            return cls(daily_limit_minutes=150, bedtime_weekday="21:00", bedtime_weekend="22:00", wake_time="07:00")
        elif tier_str == AgeTier.TEEN.value:
            return cls(daily_limit_minutes=240, bedtime_weekday="22:00", bedtime_weekend="23:00", wake_time="07:00")
        return cls()


@dataclass
class WebFilterPolicy:
    dns_provider: str = DNSProvider.CLEANBROWSING_FAMILY.value
    safe_search_enforced: bool = True
    block_incognito: bool = True
    disable_developer_tools: bool = True
    disable_extensions_install: bool = True
    blocked_domains: List[str] = field(default_factory=lambda: [
        "*.adult",
        "*.xxx",
        "*.porn",
        "*.gambling",
        "omegle.com",
        "chatroulette.com",
        "tiktok.com",
    ])
    allowed_domains: List[str] = field(default_factory=lambda: [
        "*.wikipedia.org",
        "*.khanacademy.org",
        "*.scratch.mit.edu",
        "*.nasa.gov",
        "*.pbskids.org",
    ])


# Approved entries that stand for a family of desktop entries. Debian ships LibreOffice as one entry
# per program (libreoffice-writer, libreoffice-calc, ...), so "libreoffice" approves all of them.
APP_FAMILIES: Dict[str, str] = {"libreoffice": "libreoffice-"}


def approved_entries_matching(app_id: str, approved: List[str]) -> List[str]:
    """The approved-list entries that make a desktop entry visible to a child.

    The match is exact (case-insensitive), apart from the families above. It used to be a substring
    match both ways, so approving "chromium" also showed the game "chromium-bsu", and approving
    "google-chrome" showed "google-chrome-beta".
    """
    clean = app_id.rsplit("/", 1)[-1].lower()
    if clean.endswith(".desktop"):
        clean = clean[: -len(".desktop")]
    matches = []
    for entry in approved:
        name = entry.lower()
        family = APP_FAMILIES.get(name)
        if clean == name or (family is not None and clean.startswith(family)):
            matches.append(entry)
    return matches


@dataclass
class AppPolicy:
    allow_list_mode: bool = True
    approved_apps: List[str] = field(default_factory=lambda: list(DEFAULT_APPROVED_APPS[AgeTier.PRE_TEEN.value]))
    blocked_apps: List[str] = field(default_factory=lambda: list(ALWAYS_BLOCKED_COMMANDS))

    @classmethod
    def for_tier(cls, tier: AgeTier | str) -> AppPolicy:
        tier_str = tier.value if isinstance(tier, AgeTier) else tier
        apps = DEFAULT_APPROVED_APPS.get(tier_str, DEFAULT_APPROVED_APPS[AgeTier.PRE_TEEN.value])
        return cls(
            allow_list_mode=True,
            approved_apps=list(apps),
            blocked_apps=list(ALWAYS_BLOCKED_COMMANDS),
        )


@dataclass
class ParentAccount:
    username: str
    full_name: str
    # In memory only: used to set the password, never written to policy files.
    password: Optional[str] = field(default=None, repr=False)
    role: str = "local_admin"
    sudo_access: bool = True
    shell: str = "/bin/bash"

    def validate(self) -> List[str]:
        errors = []
        if not self.username or not re.match(r"^[a-z_][a-z0-9_-]{2,31}$", self.username):
            errors.append(f"Invalid parent username '{self.username}': must be 3-32 characters, lowercase letters, digits, '_' or '-'.")
        if not self.full_name.strip():
            errors.append("Parent full name is required.")
        if not self.sudo_access:
            errors.append("Parent account must have sudo access.")
        return errors


@dataclass
class ChildAccount:
    username: str
    full_name: str
    age_tier: str = AgeTier.PRE_TEEN.value
    # In memory only: used to set the password, never written to policy files.
    password: Optional[str] = field(default=None, repr=False)
    enabled: bool = True
    role: str = "standard_user"
    sudo_access: bool = False
    shell: str = "/usr/sbin/nologin"  # No direct shell for children
    time_limits: TimeLimitPolicy = field(default_factory=TimeLimitPolicy)
    web_filter: WebFilterPolicy = field(default_factory=WebFilterPolicy)
    app_policy: AppPolicy = field(default_factory=AppPolicy)

    def validate(self) -> List[str]:
        errors = []
        if not self.username or not re.match(r"^[a-z_][a-z0-9_-]{2,31}$", self.username):
            errors.append(f"Invalid child username '{self.username}': must be 3-32 characters, lowercase letters, digits, '_' or '-'.")
        if not self.full_name.strip():
            errors.append(f"Child '{self.username}' must have a full name.")
        if self.sudo_access:
            errors.append(f"Violation of Family Linux security baseline: child '{self.username}' cannot have sudo access.")
        if self.role != "standard_user":
            errors.append(f"Violation: child '{self.username}' role must be 'standard_user'.")
        errors.extend(self.time_limits.validate(self.username))
        return errors

    @classmethod
    def create(cls, username: str, full_name: str, age_tier: str | AgeTier = AgeTier.PRE_TEEN, password: Optional[str] = None) -> ChildAccount:
        tier_str = age_tier.value if isinstance(age_tier, AgeTier) else age_tier
        return cls(
            username=username,
            full_name=full_name,
            age_tier=tier_str,
            password=password,
            time_limits=TimeLimitPolicy.for_tier(tier_str),
            web_filter=WebFilterPolicy(),
            app_policy=AppPolicy.for_tier(tier_str),
        )


@dataclass
class SecurityPolicy:
    distro_base: str = "debian_stable"
    privilege_model: str = "unix_users_groups"
    admin_escalation: str = "sudo_for_parent_only"
    apparmor: str = "where_applicable"
    firewall_default: str = "deny_incoming"
    firewall_outgoing: str = "allow"
    firewall_blocked_ports: List[int] = field(default_factory=lambda: [23, 135, 137, 138, 139, 445])
    regular_security_updates: bool = True


@dataclass
class FamilyPolicy:
    parent: ParentAccount
    children: List[ChildAccount] = field(default_factory=list)
    security: SecurityPolicy = field(default_factory=SecurityPolicy)
    version: str = "1.0"
    # IANA name, e.g. "Australia/Sydney". Curfews use local time; None leaves the system setting alone.
    timezone: Optional[str] = None

    def validate(self) -> List[str]:
        errors = []
        if self.timezone is not None and not is_valid_timezone(self.timezone):
            errors.append(f"Unknown time zone '{self.timezone}': use a name such as 'Australia/Sydney' or 'UTC'.")
        if not self.parent:
            errors.append("Architecture constraint: exactly one parent account is required.")
        else:
            errors.extend(self.parent.validate())

        usernames = {self.parent.username} if self.parent else set()
        for child in self.children:
            errors.extend(child.validate())
            if child.username in usernames:
                errors.append(f"Duplicate username detected: '{child.username}'.")
            usernames.add(child.username)

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the policy for storage and the API. Passwords are never included."""
        data = asdict(self)
        data["parent"].pop("password", None)
        for child in data["children"]:
            child.pop("password", None)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FamilyPolicy:
        parent_raw = data.get("parent", {})
        parent = ParentAccount(
            username=parent_raw.get("username", "parent"),
            full_name=parent_raw.get("full_name", "Family Administrator"),
            password=parent_raw.get("password"),
            role=parent_raw.get("role", "local_admin"),
            sudo_access=parent_raw.get("sudo_access", True),
            shell=parent_raw.get("shell", "/bin/bash"),
        )

        children = []
        for c_raw in data.get("children", []):
            time_raw = c_raw.get("time_limits", {})
            web_raw = c_raw.get("web_filter", {})
            app_raw = c_raw.get("app_policy", {})

            time_policy = TimeLimitPolicy(
                enabled=time_raw.get("enabled", True),
                daily_limit_minutes=time_raw.get("daily_limit_minutes", 120),
                bedtime_weekday=time_raw.get("bedtime_weekday", "20:30"),
                bedtime_weekend=time_raw.get("bedtime_weekend", "21:30"),
                wake_time=time_raw.get("wake_time", "07:00"),
                warning_minutes=time_raw.get("warning_minutes", [15, 5, 1]),
            )
            web_policy = WebFilterPolicy(
                dns_provider=web_raw.get("dns_provider", DNSProvider.CLEANBROWSING_FAMILY.value),
                safe_search_enforced=web_raw.get("safe_search_enforced", True),
                block_incognito=web_raw.get("block_incognito", True),
                disable_developer_tools=web_raw.get("disable_developer_tools", True),
                disable_extensions_install=web_raw.get("disable_extensions_install", True),
                blocked_domains=web_raw.get("blocked_domains", []),
                allowed_domains=web_raw.get("allowed_domains", []),
            )
            app_policy = AppPolicy(
                allow_list_mode=app_raw.get("allow_list_mode", True),
                approved_apps=app_raw.get("approved_apps", []),
                blocked_apps=app_raw.get("blocked_apps", []),
            )

            children.append(ChildAccount(
                username=c_raw.get("username", ""),
                full_name=c_raw.get("full_name", ""),
                age_tier=c_raw.get("age_tier", AgeTier.PRE_TEEN.value),
                password=c_raw.get("password"),
                enabled=c_raw.get("enabled", True),
                role=c_raw.get("role", "standard_user"),
                sudo_access=c_raw.get("sudo_access", False),
                shell=c_raw.get("shell", "/usr/sbin/nologin"),
                time_limits=time_policy,
                web_filter=web_policy,
                app_policy=app_policy,
            ))

        sec_raw = data.get("security", {})
        security = SecurityPolicy(
            distro_base=sec_raw.get("distro_base", "debian_stable"),
            privilege_model=sec_raw.get("privilege_model", "unix_users_groups"),
            admin_escalation=sec_raw.get("admin_escalation", "sudo_for_parent_only"),
            apparmor=sec_raw.get("apparmor", "where_applicable"),
            firewall_default=sec_raw.get("firewall_default", "deny_incoming"),
            firewall_outgoing=sec_raw.get("firewall_outgoing", "allow"),
            firewall_blocked_ports=sec_raw.get("firewall_blocked_ports", [23, 135, 137, 138, 139, 445]),
            regular_security_updates=sec_raw.get("regular_security_updates", True),
        )

        return cls(
            parent=parent,
            children=children,
            security=security,
            version=data.get("version", "1.0"),
            timezone=data.get("timezone"),
        )
