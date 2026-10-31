# Family Linux Repository Structure

This document maps the repository: what each folder and module is for, how the pieces fit together, and where runtime state lives. For history and known issues, see [DEV_HIST.md](DEV_HIST.md).

## Top level

```
family-linux/
├── README.md              Project overview, quick start, status
├── STRUCTURE.md           This file
├── CLAUDE.md              Working notes for Claude: documentation and testing rules
├── DEV_HIST.md            Development history and review findings
├── pyproject.toml         Package metadata, dependencies, entry points, pytest config
├── LICENSE                MIT
├── .gitignore             Ignores bytecode, pytest cache, build output, ISO images
├── .github/workflows/
│   └── ci.yml             Test matrix (Python 3.9–3.13, Ubuntu and macOS runners) and privileged Linux jobs
├── docs/                  Design documents and the parent guide to web filtering
├── config/                Policy templates, browser/systemd configuration, menu entries, polkit, wallpaper
├── scripts/               Bootstrap launcher, Debian ISO build, VirtualBox appliance build
├── src/family_linux/      Python implementation (installed as package `family_linux`)
└── tests/                 pytest suite
```

Generated folders such as `__pycache__/`, `build/` and `dist/` are ignored by `.gitignore`.

## Documentation (`docs/`)

| File | Purpose |
|------|---------|
| `vision.md` | Product concept, user model (one parent, zero or more children), security direction, non-goals |
| `architecture.md` | Five-layer model (Debian base, security controls, child session, parent management, audit/recovery), data and policy model |
| `installer.md` | Installer flow (the Debian Installer preseed and the first-boot apply), recommended vs advanced mode, validation and summary requirements |
| `roadmap.md` | Phases 0 to 5, milestones |
| `web-filtering-guide.md` | Step-by-step guide for parents with no IT background: blocking and allowing sites, website requests, other browsers |

## Configuration (`config/`)

| File | Purpose | Consumed by |
|------|---------|-------------|
| `default-policy.yaml` | Design-stage baseline for identity and parent-management rules | `config.py` (fallback path, currently only read for its existence) |
| `chromium/family-policy.json` | Managed Chromium policy template (SafeSearch, incognito off, URL blocklist) | Reference copy; the generator is `security/browser.py` |
| `firefox/policies.json` | Managed Firefox policy template | Reference copy; the generator is `security/browser.py` |
| `systemd/family-policyd.service` | Runs the screen-time daemon as root, `--interval 60` | Installed manually to `/etc/systemd/system` |
| `systemd/family-linux-firstboot.service` | Runs the full apply once on the first boot of an installed system | Installed by the late command |
| `systemd/family-parent-dashboard.service` | Runs the parent web dashboard on port 8443 as root | Installed manually to `/etc/systemd/system` |
| `bin/family-ctl` | `family-ctl` wrapper for the installed system | Installed by the late command to `/usr/local/sbin` |
| `bin/family-linux-parent` | Launcher for the Family Controls app (`python3 -m family_linux.kde_app`) | Installed by the late command to `/usr/local/bin` |
| `bin/family-linux-set-wallpaper` | Sets the Family wallpaper once for each account, at its first Plasma login | Installed by the late command to `/usr/libexec/family-linux` |
| `xdg/autostart/family-linux-wallpaper.desktop` | Starts the wallpaper step at login | Installed by the late command to `/etc/xdg/autostart` |
| `applications/org.familylinux.Parent.desktop` | Menu entry for Family Controls | Installed by the late command; hidden for children |
| `polkit/org.familylinux.manage.policy` | polkit action for `pkexec family-ctl` (administrators, password remembered briefly) | Installed by the late command |
| `wallpaper/` | Optional desktop wallpaper: one PNG or JPEG, with a README. Built into the ISO when present | `scripts/build-debian-iso.sh` |

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `bootstrap-prototype.sh` | Launcher for every command: `install`, `dashboard`, `ctl`, `policyd`, `verify`, `test`, `preseed`. Sets `PYTHONPATH` to `src/`. |
| `build-debian-iso.sh` | Builds the install ISO: repacks the Debian stable netinst image (arm64 or amd64) with the preseed, the late-command script, the Family Linux payload, the wallpaper (if any) and the boot-menu entries that start the preseed. Checks the image against `SHA512SUMS` (the file name is read from that list). `DEBIAN_BASE_URL` overrides the location |
| `build-virtualbox-vm.sh` | Builds the ISO, installs it into a VirtualBox VM headless (presses Enter at the boot menu), waits for the first-boot apply, and exports an `.ova` |

## Source package (`src/family_linux/`)

### Entry points (from `pyproject.toml`)

| Command | Module | Notes |
|---------|--------|-------|
| `family-installer` | `installer/wizard.py:main` | Interactive or `--non-interactive` install flow; `--export-preseed` writes the preseed and the late-command script |
| `family-ctl` | `cli/family_ctl.py:main` | Parent administration CLI |
| `family-policyd` | `screentime/daemon.py:main` | Screen-time and curfew enforcement loop |
| `family-parent-dashboard` | `parent_ui/server.py:main` | Local web portal on `127.0.0.1` |

### Modules

| Module | Role | Key names |
|--------|------|-----------|
| `__init__.py` | Package version | `__version__` |
| `models.py` | Data model and policy rules: accounts, age tiers, time limits, web filter, app policy, security baseline. Holds the constants for DNS servers, default app lists (Debian and KDE desktop ids), always-blocked commands and terminals, and the password rules (child minimum length; parent rules). Passwords are held in memory only and are excluded from `to_dict()`. | `FamilyPolicy`, `ParentAccount`, `ChildAccount`, `SecurityPolicy`, `AgeTier`, `DNSProvider`, `MIN_PASSWORD_LENGTH`, `MIN_PARENT_PASSWORD_LENGTH`, `parent_password_problems`, `DEFAULT_APPROVED_APPS`, `ALWAYS_BLOCKED_COMMANDS` |
| `timezones.py` | Time zone names for setup: validation (IANA names only) and the host's zone as the default | `is_valid_timezone`, `detect_host_timezone` |
| `config.py` | Load, save (atomic, `0600`), back up, and restore the policy YAML | `PolicyConfigManager` |
| `audit/logger.py` | Append-only JSON-lines audit log with read and filter | `AuditLogger`, `AuditRecord` |
| `installer/wizard.py` | Installer state machine and the 12 steps. Non-interactive mode builds the policy from flags and exports the preseed. | `InstallerWizard` |
| `provisioner/preseed.py` | Generates the Debian Installer preseed (locale, time zone, the parent account as the only administrator, the first disk, Debian repositories, `kde-desktop` task, package list, UEFI boot) and the late-command script (family groups, sudoers, child accounts with nologin shells, firewall, payload, wallpaper, NetworkManager with systemd-resolved, unattended upgrades). Every value is shell-quoted | `DebianPreseedGenerator`, `PACKAGES`, `ISO_PAYLOAD_DIR` |
| `provisioner/system.py` | Saves the policy first, then applies the time zone, users, firewall, DNS, the web gateway, browsers, AppArmor, security updates, the PackageKit install gate, Firefox ESR, the Plasma kiosk lockdown, and desktop filters. Failures raise `ProvisioningError` naming the last completed step. | `SystemProvisioner.apply_policy`, `ProvisioningError` |
| `provisioner/firstboot.py` | First-boot apply with a done marker | `run`, `MARKER_PATH` |
| `provisioner/sha512crypt.py` | SHA-512 crypt (`$6$`) for the password hashes in the preseed and late command (no `crypt` module on Python 3.13+) | `sha512_crypt` |
| `cli/family_ctl.py` | `status`, `state` (JSON for the app), `user`, `app`, `time`, `web`, `audit`, `backup`, `verify` subcommands. `verify` reads real state for live checks on Linux, including the Firefox, Chromium and Brave policy files, the Plasma kiosk lockdown and the software install gate. | `FamilyCtl`, `format_table` |
| `kde_app/app.py` | Family Controls, the parent's KDE app (Qt 6 through PyQt6): children, screen time, websites, apps, website requests, add child | `FamilyControlsWindow`, `AddChildDialog`, `main` |
| `kde_app/backend.py` | Runs `pkexec family-ctl ...` for the app; input checks; demo client. No Qt, so it is tested anywhere | `FamilyCtlClient`, `DemoClient`, `make_client` |
| `kde_app/__main__.py` | Starts the Family Controls app (`python3 -m family_linux.kde_app`) | `main` |
| `parent_ui/server.py` | `http.server` dashboard: embedded HTML page plus JSON API (`/api/policy`, `/api/child`, `/api/web/block`, and others). Requires a token (bearer header or session cookie), checks Host and Origin, requires JSON bodies. Dependencies are injected via `make_handler()`. | `make_handler`, `run_server` |
| `screentime/tracker.py` | Per-day usage minutes in JSON; evaluates quota and curfew | `ScreenTimeTracker` |
| `screentime/daemon.py` | Polls logged-in users, sends warnings, terminates sessions at limit or curfew | `ScreenTimeDaemon` |

### Security layer (`security/`)

Each manager takes a `SystemAdapter`, so the same code path runs in simulation.

| Module | Role | Key names |
|--------|------|-----------|
| `adapter.py` | Runs commands and writes files. Forces dry-run on non-Linux and when not root. Writes atomically, falling back to an in-place write for bind-mounted files. | `SystemAdapter`, `CommandResult` |
| `users.py` | Creates parent and child accounts, groups (`family-parent`, `family-children`), sudoers, password, home permissions (`0700`) | `UserManager` |
| `firewall.py` | UFW baseline: deny incoming, allow outgoing, block legacy outbound ports | `FirewallManager` |
| `dns_filter.py` | systemd-resolved drop-in with family DNS servers; managed `/etc/hosts` block section | `DNSFilterManager` |
| `browser.py` | Generates and writes managed policies for Firefox ESR, Chromium, Chrome, Edge and Brave (private windows, developer tools, SafeSearch, Brave Tor off). URL rules are per child and enforced by the gateway, not here | `BrowserPolicyManager`, `FIREFOX_POLICY_PATH` |
| `dns_gateway.py` | Per-child DNS gateway. Answers each child's lookups from that child's rules, refuses blocked names, records blocked lookups for the parent, and adds allowed addresses to the child's nftables allow set | `ChildResolver`, `DomainRules`, `RequestLog`, `AddressAllowList`, `run` |
| `tls_proxy.py` | Per-child HTTPS (SNI) and HTTP (Host) name check on the redirected ports 443 and 80. Relays a connection only when its address and name came from the child's allowed lookups; falls back to the name's other allowed addresses when one cannot be reached | `ProxyContext`, `decide`, `LearnedNameAddresses`, `connection_candidates` |
| `web_gateway.py` | Renders the gateway's config, nftables rules and `family-dnsd.service` (rules loaded before the gateway starts, so the gateway fails closed) | `render_config`, `render_nft`, `render_service` |
| `desktop_lockdown.py` | Plasma kiosk restrictions in `/etc/xdg/kdeglobals` (managed block, `[KDE Action Restrictions][$i]`): no shell access, no Alt+F2 run dialog, no `--config` override. Applies to every account | `DesktopLockdown`, `with_lockdown`, `lockdown_in_place`, `LOCKED_RESTRICTIONS` |
| `apparmor.py` | Writes and loads the `family-linux-child` profile | `AppArmorManager`, `CHILD_SESSION_PROFILE` |
| `child_dirs.py` | Root-safe access to a child's override folder: each component opened with `O_NOFOLLOW` from the one above, writes by temporary name and rename, `fchown` for the child's folders, `chattr` on `/proc/self/fd/N`. Used by root real runs; dry runs use the path-based code in `app_guard.py` | `open_overrides_dir`, `write_file`, `remove_file`, `set_immutable` |
| `app_guard.py` | Scans the system `.desktop` folders (`/usr/share/applications`, `/usr/local/share/applications`); writes marked `NoDisplay=true` overrides for unapproved apps in the child's home, and removes overrides that are no longer needed | `AppGuard`, `is_managed_override`, `MANAGED_MARKER`, `SYSTEM_APP_DIRS` |
| `desktop_refresh.py` | Re-applies child app approvals; run by `family-appguard.path` (systemd) when apt or PackageKit changes desktop entries | `refresh`, `render_path_unit`, `render_service_unit`, `WATCHED_DIRS` |
| `package_gate.py` | Polkit rule that makes every PackageKit action (install, remove, update, refresh) by a child account need the parent's password (`AUTH_ADMIN`); installs PackageKit if missing | `PackageInstallGate`, `render_polkit_rule`, `rule_in_place` |
| `password_policy.py` | Managed PAM block in `/etc/pam.d/passwd`: `pam_pwquality` for the parent (14+ characters, all four classes) on every `passwd` change, with children exempted by name | `ParentPasswordRules`, `render_pam_block`, `insert_block`, `block_in_place` |

### Runtime paths

Paths are chosen at runtime. The first set is used when running as root or when `/etc` is writable. The second set is the per-user fallback (for example on a developer machine).

| Purpose | System path | User fallback |
|---------|-------------|---------------|
| Policy file | `/etc/family-linux/policy.yaml` | `~/.config/family-linux/policy.yaml` |
| Policy backups | `/etc/family-linux/backups/` | `~/.config/family-linux/backups/` |
| Audit log | `/var/log/family-linux/audit.log` | `~/.local/share/family-linux/audit.log` |
| Screen-time usage | `/var/lib/family-linux/screentime.json` | `~/.local/share/family-linux/screentime.json` |
| Install log (written during the installer's late command) | `/var/log/family-linux-install.log` | (none) |
| Child desktop overrides | `/home/<child>/.local/share/applications/` | (none) |
| Firefox ESR policy | `/usr/lib/firefox-esr/distribution/policies.json`, `/etc/firefox/policies/policies.json`, `/etc/firefox-esr/policies/policies.json` | (none) |
| Chromium policy | `/etc/chromium/policies/managed/family-policy.json` | (none) |
| Chrome policy | `/etc/opt/chrome/policies/managed/family-policy.json` | (none) |
| Edge policy | `/etc/opt/edge/policies/managed/family-policy.json` | (none) |
| Brave policy | `/etc/brave/policies/managed/family-policy.json` (for Brave from Brave's own repository) | (none) |
| Web gateway config and rules | `/etc/family-linux/dns-gateway.json`, `/etc/family-linux/nftables-children.nft`, `/etc/systemd/system/family-dnsd.service` | (none) |
| Blocked web requests | `/var/lib/family-linux/web-requests.json` | (none) |
| Plasma kiosk restrictions | `/etc/xdg/kdeglobals` (managed block) | (none) |
| Software install gate (polkit) | `/etc/polkit-1/rules.d/50-family-linux-packages.rules` | (none) |
| Wallpaper image | `/usr/share/backgrounds/family-linux/wallpaper.<extension>` | (none) |
| Wallpaper step (run at login) | `/usr/libexec/family-linux/family-linux-set-wallpaper`, `/etc/xdg/autostart/family-linux-wallpaper.desktop` | (none) |
| Wallpaper marker (one per account) | (none) | `~/.local/state/family-linux/wallpaper-set` |
| AppArmor profile | `/etc/apparmor.d/family-linux-child` | (none) |
| DNS drop-in | `/etc/systemd/resolved.conf.d/family-linux-dns.conf` | (none) |
| NetworkManager settings (managed interfaces, systemd-resolved DNS) | `/etc/NetworkManager/conf.d/family-linux-network.conf`, `/etc/NetworkManager/conf.d/family-linux-dns.conf` | (none) |
| Security updates | `/etc/apt/apt.conf.d/20auto-upgrades` | (none) |
| Sudoers drop-in | `/etc/sudoers.d/family-linux-admin` | (none) |
| Parent password rules (PAM) | `/etc/pam.d/passwd` (managed block) | (none) |
| Menu refresh units | `/etc/systemd/system/family-appguard.path`, `family-appguard.service` | (none) |

Note: `SystemAdapter` treats any non-Linux host as dry-run, so on macOS every system write is simulated and nothing is changed.

## Tests (`tests/`)

Run with `./scripts/bootstrap-prototype.sh test` or `python3 -m pytest tests`. Results are in [DEV_HIST.md](DEV_HIST.md).

| File | Covers |
|------|--------|
| `test_models.py` | Model validation rules, tier presets, policy round-trip |
| `test_config.py` | Save, backup, restore, and validation in `PolicyConfigManager` |
| `test_audit.py` | Audit log writes, reads, and filters |
| `test_installer.py` | Non-interactive wizard validation, dry-run apply, the preseed export and its late-command script |
| `test_preseed.py` | The preseed (KDE Plasma task, Debian repositories, no root login, hashes only, packages, disk, UEFI) and the late command (groups, sudoers, children, payload, networking, wallpaper). Runs `sh -n` on the script, including a child name with quotes |
| `test_cli.py` | `family-ctl` commands in simulation, isolated from real paths; `verify` is `[INCOMPLETE]` off Linux |
| `test_screentime.py` | Usage tracking, quota and curfew evaluation, one enforcement cycle |
| `test_security.py` | Security managers in simulation; Plasma kiosk lockdown; dry-run reaches policy and audit writers |
| `test_dashboard.py` | Live HTTP server: token auth, cookie and redirect, Host and Origin checks, JSON and size rules, password length |
| `test_package_gate.py` | Polkit rule content and safety (every PackageKit action), dry-run write, AppGuard hiding unapproved apps and confining approved ones |
| `test_password_policy.py` | PAM block layout, child exemption by name, idempotent insertion, dry run |
| `test_firstboot_iso.py` | First-boot marker and apply, browser policy paths, the first-boot unit ordering, wallpaper step, gateway reload on start |
| `test_sha512crypt.py` | SHA-512 crypt against glibc vectors; preseed hashes |
| `test_desktop_refresh.py` | Menu refresh units and re-apply |
| `test_kde_app_backend.py` | Family Controls backend (pkexec calls, password on stdin, errors), `state`/`web remove`/`--password-stdin`, install steps, terminals and settings never approvable |
| `test_kde_app_window.py` | Family Controls window (PyQt6, offscreen): children and requests listed, a child's page with its sites and app switches. Skipped where PyQt6 is missing |
| `test_secrets.py` | Passwords never serialised, never in repr, dropped from files on next save |
| `test_child_dirs.py` | A child's symlinks cannot make root write outside the child's folders (real files, no root needed) |
| `test_app_visibility.py` | Approved apps shown, unapproved hidden, child owns `~/.local`, overrides folder locked |
| `test_dns_gateway.py` | Per-child rules, blocked answers never reach the allow list, name-to-address records |
| `test_tls_proxy.py` | ClientHello and Host parsing, ECH refusal, the allow decision, relay, IPv6 fallback to another allowed address |
| `test_timezone.py` | Time zone validation, host default, the preseed's time zone |
| `test_provisioning.py` | Save-before-apply ordering and the `ProvisioningError` message |
| `integration/test_linux_provisioning.py` | Real accounts, sudoers, and UFW. Root on Linux with `FAMILY_LINUX_INTEGRATION=1` only; skipped elsewhere |

The integration tests run in the `linux-integration` CI job. They are not run by the default test command.

## Dependencies

- Runtime: Python 3.9 or newer (per `pyproject.toml`); `pyyaml>=6.0`. On the installed system, the Debian packages `python3`, `python3-yaml` and `python3-pyqt6` (see `PACKAGES` in `provisioner/preseed.py`).
- Dev: `pytest>=7.0`, `pytest-cov>=4.0`. `test_kde_app_window.py` also needs PyQt6 and is skipped without it.
- Standard library only elsewhere (`http.server`, `subprocess`, `json`, `dataclasses`).
- The `crypt` module is optional; the generator falls back to a SHA-512 crypt-style hash when it is missing.
