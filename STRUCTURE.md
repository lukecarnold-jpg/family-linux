# Family Linux Repository Structure

This document maps the repository: what each folder and module is for, how the pieces fit together, and where runtime state lives. For history and known issues, see [DEV_HIST.md](DEV_HIST.md).

## Top level

```
family-linux/
├── README.md              Project overview, quick start, status
├── STRUCTURE.md           This file
├── DEV_HIST.md            Development history and review findings
├── pyproject.toml         Package metadata, dependencies, entry points, pytest config
├── LICENSE                MIT
├── .gitignore             Ignores bytecode, pytest cache, build output, ISO images
├── .github/workflows/
│   └── ci.yml             Test matrix (Python 3.9–3.13, Ubuntu and macOS) and privileged Linux job
├── docs/                  Design documents (vision, architecture, installer, roadmap)
├── config/                Policy templates and browser/systemd configuration
├── scripts/               Bootstrap launcher and ISO build helper
├── src/family_linux/     Python implementation (installed as package `family_linux`)
└── tests/                 pytest suite
```

Generated folders such as `__pycache__/` and `.pytest_cache/` are ignored by `.gitignore`.

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
| `models.py` | Data model and policy rules: accounts, age tiers, time limits, web filter, app policy, security baseline. Holds the constants for DNS servers, default app lists, always-blocked commands, and the minimum password length. Passwords are held in memory only and are excluded from `to_dict()`. | `FamilyPolicy`, `ParentAccount`, `ChildAccount`, `SecurityPolicy`, `AgeTier`, `DNSProvider`, `MIN_PASSWORD_LENGTH`, `DEFAULT_APPROVED_APPS`, `ALWAYS_BLOCKED_COMMANDS` |
| `config.py` | Load, save (atomic, `0600`), back up, and restore the policy YAML | `PolicyConfigManager` |
| `audit/logger.py` | Append-only JSON-lines audit log with read and filter | `AuditLogger`, `AuditRecord` |
| `installer/wizard.py` | Installer state machine and the 12 steps. Non-interactive mode builds the policy from flags. | `InstallerWizard` |
| `provisioner/system.py` | Saves the policy first, then applies users, firewall, DNS, browsers, AppArmor, security updates, and desktop filters. Failures raise `ProvisioningError` naming the last completed step. | `SystemProvisioner.apply_policy`, `ProvisioningError` |
| `provisioner/autoinstall.py` | Generates Ubuntu Subiquity autoinstall `user-data` (users, packages, late commands) | `SubiquityAutoinstallGenerator` |
| `cli/family_ctl.py` | `status`, `user`, `app`, `time`, `web`, `audit`, `backup`, `verify` subcommands. `verify` reads real state for live checks on Linux. | `FamilyCtl`, `format_table` |
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

Run with `./scripts/bootstrap-prototype.sh test` or `python3 -m pytest tests`. Results are in [DEV_HIST.md](DEV_HIST.md#verification-matrix-session-2).

| File | Covers |
|------|--------|
| `test_models.py` | Model validation rules, tier presets, policy round-trip |
| `test_config.py` | Save, backup, restore, and validation in `PolicyConfigManager` |
| `test_audit.py` | Audit log writes, reads, and filters |
| `test_installer.py` | Non-interactive wizard validation, dry-run apply, Subiquity generator |
| `test_cli.py` | `family-ctl` commands in simulation, isolated from real paths; `verify` is `[INCOMPLETE]` off Linux |
| `test_screentime.py` | Usage tracking, quota and curfew evaluation, one enforcement cycle |
| `test_security.py` | Security managers in simulation; dry-run reaches policy and audit writers |
| `test_dashboard.py` | Live HTTP server: token auth, cookie and redirect, Host and Origin checks, JSON and size rules, password length |
| `test_secrets.py` | Passwords never serialised, never in repr, dropped from files on next save |
| `test_provisioning.py` | Save-before-apply ordering and the `ProvisioningError` message |
| `integration/test_linux_provisioning.py` | Real accounts, sudoers, and UFW. Root on Linux with `FAMILY_LINUX_INTEGRATION=1` only; skipped elsewhere |

The integration tests run in the `linux-integration` CI job. They are not run by the default test command.

## Dependencies

- Runtime: Python 3.9 or newer (per `pyproject.toml`); `pyyaml>=6.0`.
- Dev: `pytest>=7.0`, `pytest-cov>=4.0`.
- Standard library only elsewhere (`http.server`, `subprocess`, `json`, `dataclasses`).
- The `crypt` module is optional; the generator falls back to a SHA-512 crypt-style hash when it is missing.
