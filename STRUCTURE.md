# Family Linux Repository Structure

This document maps the repository: what each folder and module is for, how the pieces fit together, and where runtime state lives. For history and known issues, see [DEV_HIST.md](DEV_HIST.md).

## Top level

```
family-linux/
├── README.md              Project overview, quick start, status
├── STRUCTURE.md           This file
├── DEV_HIST.md            Development history and review findings
├── pyproject.toml         Package metadata, dependencies, entry points, pytest config
├── docs/                  Design documents (vision, architecture, installer, roadmap)
├── config/                Policy templates and browser/systemd configuration
├── scripts/               Bootstrap launcher and ISO build helper
├── src/family_linux/     Python implementation (installed as package `family_linux`)
└── tests/                 pytest suite
```

Generated folders such as `__pycache__/` and `.pytest_cache/` appear inside the tree but are not ignored by git (there is no `.gitignore` yet).

## Documentation (`docs/`)

| File | Purpose |
|------|---------|
| `vision.md` | Product concept, user model (one parent, zero or more children), security direction, non-goals |
| `architecture.md` | Five-layer model (Ubuntu base, security controls, child session, parent management, audit/recovery), data and policy model |
| `installer.md` | 12-step installer flow, recommended vs advanced mode, validation and summary requirements |
| `roadmap.md` | Phases 0 to 5, milestones |

## Configuration (`config/`)

| File | Purpose | Consumed by |
|------|---------|-------------|
| `default-policy.yaml` | Design-stage baseline for identity and parent-management rules | `config.py` (fallback path, currently only read for its existence) |
| `chromium/family-policy.json` | Managed Chromium policy template (SafeSearch, incognito off, URL blocklist) | Reference copy; the generator is `security/browser.py` |
| `firefox/policies.json` | Managed Firefox policy template | Reference copy; the generator is `security/browser.py` |
| `systemd/family-policyd.service` | Runs the screen-time daemon as root, `--interval 60` | Installed manually to `/etc/systemd/system` |
| `systemd/family-parent-dashboard.service` | Runs the parent web dashboard on port 8443 as root | Installed manually to `/etc/systemd/system` |

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `bootstrap-prototype.sh` | Launcher for every command: `install`, `dashboard`, `ctl`, `policyd`, `verify`, `test`, `autoinstall`. Sets `PYTHONPATH` to `src/`. |
| `build-autoinstall-iso.sh` | Generates Subiquity `user-data` and prints manual ISO repack steps. It does not build an ISO. |

## Source package (`src/family_linux/`)

### Entry points (from `pyproject.toml`)

| Command | Module | Notes |
|---------|--------|-------|
| `family-installer` | `installer/wizard.py:main` | Interactive or `--non-interactive` install flow |
| `family-ctl` | `cli/family_ctl.py:main` | Parent administration CLI |
| `family-policyd` | `screentime/daemon.py:main` | Screen-time and curfew enforcement loop |
| `family-parent-dashboard` | `parent_ui/server.py:main` | Local web portal on `127.0.0.1` |

### Modules

| Module | Role | Key names |
|--------|------|-----------|
| `__init__.py` | Package version | `__version__` |
| `models.py` | Data model and policy rules: accounts, age tiers, time limits, web filter, app policy, security baseline. Holds the constants for DNS servers, default app lists, and always-blocked commands. | `FamilyPolicy`, `ParentAccount`, `ChildAccount`, `SecurityPolicy`, `AgeTier`, `DNSProvider`, `DEFAULT_APPROVED_APPS`, `ALWAYS_BLOCKED_COMMANDS` |
| `config.py` | Load, save (atomic, `0600`), back up, and restore the policy YAML | `PolicyConfigManager` |
| `audit/logger.py` | Append-only JSON-lines audit log with read and filter | `AuditLogger`, `AuditRecord` |
| `installer/wizard.py` | Installer state machine and the 12 steps. Non-interactive mode builds the policy from flags. | `InstallerWizard` |
| `provisioner/system.py` | Applies a full policy across users, firewall, DNS, browsers, AppArmor, desktop filters, then saves and audits | `SystemProvisioner.apply_policy` |
| `provisioner/autoinstall.py` | Generates Ubuntu Subiquity autoinstall `user-data` (users, packages, late commands) | `SubiquityAutoinstallGenerator` |
| `cli/family_ctl.py` | `status`, `user`, `app`, `time`, `web`, `audit`, `backup`, `verify` subcommands | `FamilyCtl`, `format_table` |
| `parent_ui/server.py` | `http.server` dashboard: embedded HTML page plus JSON API (`/api/policy`, `/api/child`, `/api/web/block`, and others) | `DashboardRequestHandler`, `run_server` |
| `screentime/tracker.py` | Per-day usage minutes in JSON; evaluates quota and curfew | `ScreenTimeTracker` |
| `screentime/daemon.py` | Polls logged-in users, sends warnings, terminates sessions at limit or curfew | `ScreenTimeDaemon` |

### Security layer (`security/`)

Each manager takes a `SystemAdapter`, so the same code path runs in simulation.

| Module | Role | Key names |
|--------|------|-----------|
| `adapter.py` | Runs commands and writes files. Forces dry-run on non-Linux and when not root. | `SystemAdapter`, `CommandResult` |
| `users.py` | Creates parent and child accounts, groups (`family-parent`, `family-children`), sudoers, password, home permissions (`0700`) | `UserManager` |
| `firewall.py` | UFW baseline: deny incoming, allow outgoing, block legacy outbound ports | `FirewallManager` |
| `dns_filter.py` | systemd-resolved drop-in with family DNS servers; managed `/etc/hosts` block section | `DNSFilterManager` |
| `browser.py` | Generates and writes Firefox and Chromium managed policies | `BrowserPolicyManager` |
| `apparmor.py` | Writes and loads the `family-linux-child` profile | `AppArmorManager`, `CHILD_SESSION_PROFILE` |
| `app_guard.py` | Scans `.desktop` files and writes `NoDisplay=true` overrides for unapproved apps in child home | `AppGuard` |

### Runtime paths

Paths are chosen at runtime. The first set is used when running as root or when `/etc` is writable. The second set is the per-user fallback (for example on a developer machine).

| Purpose | System path | User fallback |
|---------|-------------|---------------|
| Policy file | `/etc/family-linux/policy.yaml` | `~/.config/family-linux/policy.yaml` |
| Policy backups | `/etc/family-linux/backups/` | `~/.config/family-linux/backups/` |
| Audit log | `/var/log/family-linux/audit.log` | `~/.local/share/family-linux/audit.log` |
| Screen-time usage | `/var/lib/family-linux/screentime.json` | `~/.local/share/family-linux/screentime.json` |
| Child desktop overrides | `/home/<child>/.local/share/applications/` | (none) |
| Firefox policy | `/etc/firefox/policies/policies.json` and `/usr/lib/firefox/distribution/policies.json` | (none) |
| Chromium policy | `/etc/chromium/policies/managed/family-policy.json` and `/etc/opt/chrome/policies/managed/family-policy.json` | (none) |
| AppArmor profile | `/etc/apparmor.d/family-linux-child` | (none) |
| DNS drop-in | `/etc/systemd/resolved.conf.d/family-linux-dns.conf` | (none) |
| Sudoers drop-in | `/etc/sudoers.d/family-linux-admin` | (none) |

Note: `SystemAdapter` treats any non-Linux host as dry-run, so on macOS every system write is simulated and nothing is changed.

## Tests (`tests/`)

31 tests across seven files. Run with `./scripts/bootstrap-prototype.sh test` or `python3 -m pytest tests`.

| File | Covers |
|------|--------|
| `test_models.py` | Model validation rules, tier presets, policy round-trip |
| `test_config.py` | Save, backup, restore, and validation in `PolicyConfigManager` |
| `test_audit.py` | Audit log writes, reads, and filters |
| `test_installer.py` | Non-interactive wizard validation, dry-run apply, Subiquity generator |
| `test_cli.py` | `family-ctl` commands end to end in simulation |
| `test_screentime.py` | Usage tracking, quota and curfew evaluation, one enforcement cycle |
| `test_security.py` | Security managers in simulation (users, firewall, browser, DNS, AppArmor, app guard) |

Not covered by tests: `parent_ui/server.py` (the HTTP API), the real Linux code paths, and the AppArmor profile's actual effect.

## Dependencies

- Runtime: Python 3.9 or newer (per `pyproject.toml`); `pyyaml>=6.0`.
- Dev: `pytest>=7.0`, `pytest-cov>=4.0`.
- Standard library only elsewhere (`http.server`, `subprocess`, `json`, `dataclasses`).
- The `crypt` module is optional; the generator falls back to a SHA-512 crypt-style hash when it is missing.
