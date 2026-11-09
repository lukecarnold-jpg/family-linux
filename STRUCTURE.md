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
│   ├── ci.yml             Test matrix (Python 3.11–3.13 on Ubuntu, 3.13 on macOS), privileged Linux jobs, Debian 13 container job, amd64 ISO check
│   └── debian-install.yml Full install of the automated amd64 ISO under QEMU (weekly, on demand, and on installer changes)
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
| `web-filtering-guide.md` | Step-by-step guide for parents with no IT background: blocking and allowing sites, website requests, other browsers, keeping the computer itself locked (firmware password, USB start-up) |

## Configuration (`config/`)

| File | Purpose | Consumed by |
|------|---------|-------------|
| `default-policy.yaml` | Design-stage baseline for identity and parent-management rules | `config.py` (fallback path, currently only read for its existence) |
| `chromium/family-policy.json` | Managed Chromium policy template (SafeSearch, incognito off, URL blocklist) | Reference copy; the generator is `security/browser.py` |
| `firefox/policies.json` | Managed Firefox policy template | Reference copy; the generator is `security/browser.py` |
| `systemd/family-linux-firstboot.service` | Runs the full apply once on the first boot of an installed system, before the sign-in screen (`Before=display-manager.service`) | Installed by the late command. Every unit in `config/systemd` must be installed by the ISO (`test_firstboot_iso.py`); the other units are written by the apply |
| `bin/family-ctl` | `family-ctl` wrapper for the installed system | Installed by the late command to `/usr/local/sbin` |
| `bin/family-linux-parent` | Launcher for the Family Controls app (`python3 -m family_linux.kde_app`) | Installed by the late command to `/usr/local/bin` |
| `bin/family-linux-set-wallpaper` | Sets the Family wallpaper once for each account, at its first Plasma login | Installed by the late command to `/usr/libexec/family-linux` |
| `xdg/autostart/family-linux-wallpaper.desktop` | Starts the wallpaper step at login | Installed by the late command to `/etc/xdg/autostart` |
| `applications/org.familylinux.Parent.desktop` | Menu entry for Family Controls | Installed by the late command; hidden for children |
| `polkit/org.familylinux.manage.policy` | polkit action for `pkexec family-ctl` (administrators, password remembered briefly) | Installed by the late command |
| `wallpaper/` | Optional desktop wallpaper: one PNG or JPEG, with a README. Built into the ISO when present | `scripts/build-debian-iso.sh` |
| `keys/debian-cd-signing.gpg` | Debian CD signing keys (fingerprints `DF9B9C49…6294BE9B` and `10460DAD…64E6EA7D`, as listed on debian.org/CD/verify) | `scripts/build-debian-iso.sh` (`gpgv` on `SHA512SUMS.sign`) |

## Scripts (`scripts/`)

| File | Purpose |
|------|---------|
| `bootstrap-prototype.sh` | Launcher for every command: `install`, `ctl`, `policyd`, `verify`, `test`, `preseed`. Sets `PYTHONPATH` to `src/`. |
| `build-debian-iso.sh` | Builds the install ISO: repacks the Debian stable netinst image (arm64 or amd64) with the preseed, the late-command script, the Family Linux payload, the wallpaper (if any) and the boot-menu entries that read the preseed. `MODE=interactive` (default) opens the Debian installer with the preseed answers and asks before erasing the disk; `MODE=automated` starts Install after 5 seconds with no questions; `APPLIANCE=1` makes the first boot power off when done. Patches both the UEFI (GRUB) and, on amd64, the BIOS (isolinux) menus through `provisioner/iso.py`. Verifies `SHA512SUMS` against Debian's signing keys, then the image against it (the file name is read from that list). `DEBIAN_BASE_URL` overrides the location; `OUTPUT_DIR` writes the ISO somewhere other than `dist/` (for a test build beside your own) |
| `build-virtualbox-vm.sh` | Builds the automated appliance ISO, installs it into a VirtualBox VM headless (VMSVGA graphics; Debian has no DRM driver for qemuramfb), waits for the first boot to apply the policy and power off (hard power-off after 4 minutes as a fallback), and exports an `.ova` |

## Source package (`src/family_linux/`)

### Entry points (from `pyproject.toml`)

| Command | Module | Notes |
|---------|--------|-------|
| `family-installer` | `installer/wizard.py:main` | Interactive or `--non-interactive` install flow; `--export-preseed` writes the preseed and the late-command script |
| `family-ctl` | `cli/family_ctl.py:main` | Parent administration CLI |
| `family-policyd` | `screentime/daemon.py:main` | Screen-time and curfew enforcement loop (on the installed system it runs as `family-policyd.service`, written by `screentime/service.py`) |

### Modules

| Module | Role | Key names |
|--------|------|-----------|
| `__init__.py` | Package version | `__version__` |
| `models.py` | Data model and policy rules: accounts, age tiers, time limits, web filter, app policy, security baseline. Holds the constants for DNS servers, default app lists (Debian and KDE desktop ids), always-blocked commands and terminals, the password rules (child minimum length; parent rules), the 24-hour time check used to validate bedtimes, and the exact approved-app match (`approved_entries_matching`, with `APP_FAMILIES` such as LibreOffice). Passwords are held in memory only and are excluded from `to_dict()`. | `FamilyPolicy`, `ParentAccount`, `ChildAccount`, `SecurityPolicy`, `AgeTier`, `DNSProvider`, `MIN_PASSWORD_LENGTH`, `MIN_PARENT_PASSWORD_LENGTH`, `parent_password_problems`, `DEFAULT_APPROVED_APPS`, `ALWAYS_BLOCKED_COMMANDS`, `CLOCK`, `approved_entries_matching`, `APP_FAMILIES` |
| `timezones.py` | Time zone names for setup: validation (IANA names only) and the host's zone as the default | `is_valid_timezone`, `detect_host_timezone` |
| `config.py` | Load, save (atomic, `0600`), back up, and restore the policy YAML | `PolicyConfigManager` |
| `audit/logger.py` | Append-only JSON-lines audit log with read and filter; the logrotate file the apply writes (`updates` layer) | `AuditLogger`, `AuditRecord`, `render_logrotate` |
| `installer/wizard.py` | Installer state machine and the 12 steps. Non-interactive mode builds the policy from flags and exports the preseed. | `InstallerWizard` |
| `provisioner/preseed.py` | Generates the Debian Installer preseed (locale, time zone, the parent account as the only administrator, the first disk, Debian repositories, `kde-desktop` task, package list, UEFI boot) and the late-command script (family groups, sudoers, child accounts with nologin shells, firewall, payload, wallpaper, NetworkManager with systemd-resolved, unattended upgrades, the GRUB password with unrestricted normal entries). Children are created locked; only `src/` is copied to `/opt/family-linux`. Every value is shell-quoted | `DebianPreseedGenerator`, `PACKAGES`, `ISO_PAYLOAD_DIR`, `grub_pbkdf2` |
| `provisioner/iso.py` | Boot-menu changes for the ISO: the preseed argument on each install entry of the GRUB (UEFI) and isolinux (amd64 BIOS) menus; in automated mode also the unattended arguments, the serial console and a 5-second timeout. Expert and rescue entries are left alone | `patch_grub`, `patch_isolinux_entries`, `patch_isolinux_timeout`, `main` |
| `provisioner/system.py` | Saves the policy first, then applies the time zone, users, firewall, DNS, the web gateway, browsers, AppArmor, security updates, the PackageKit install gate, Firefox ESR, the Plasma kiosk lockdown, desktop filters and the screen-time service. Children are unlocked only after every selected layer has applied. The apply is split into named layers (`ALL_LAYERS`); a change from `family-ctl` re-applies only its layers (`CHILD_ADDED_LAYERS`, `CHILD_SIGN_IN_LAYERS`, `APP_LAYERS`, `WEB_LAYERS`). Failures raise `ProvisioningError` naming the last completed step. | `SystemProvisioner.apply_policy`, `ProvisioningError`, `ALL_LAYERS` |
| `provisioner/firstboot.py` | First-boot apply with a done marker. Reports installer steps that failed, and powers off once in appliance builds | `run`, `MARKER_PATH`, `installer_failures`, `POWEROFF_FLAG` |
| `provisioner/sha512crypt.py` | SHA-512 crypt (`$6$`) for the password hashes in the preseed and late command (no `crypt` module on Python 3.13+) | `sha512_crypt` |
| `cli/family_ctl.py` | `status`, `state` (JSON for the app), `user`, `app`, `time`, `web`, `audit`, `backup`, `verify` subcommands. `verify` reads real state for live checks on Linux, including the Firefox, Chromium, Brave, Chrome and Edge policy files, the running `family-dnsd` and `family-policyd` services, the children's nftables rules, the Plasma kiosk lockdown and the software install gate. Bad input is reported as `[ERROR]`, not a traceback. | `FamilyCtl`, `format_table`, `web_rules_loaded` |
| `kde_app/app.py` | Family Controls, the parent's KDE app (Qt 6 through PyQt6): children, screen time, websites, apps, website requests, add child | `FamilyControlsWindow`, `AddChildDialog`, `main` |
| `kde_app/backend.py` | Runs `pkexec family-ctl ...` for the app; input checks; demo client. No Qt, so it is tested anywhere | `FamilyCtlClient`, `DemoClient`, `make_client` |
| `kde_app/__main__.py` | Starts the Family Controls app (`python3 -m family_linux.kde_app`) | `main` |
| `screentime/tracker.py` | Per-day usage minutes in JSON; evaluates quota and curfew (each evening's bedtime, including bedtimes after midnight) | `ScreenTimeTracker` |
| `screentime/daemon.py` | Polls signed-in users, counts time only for active unlocked sessions, sends warnings into the child's session (`runuser` and the session bus), asks Plasma to sign the child out at a limit or bedtime and forces it a cycle later (restarting the sign-in screen when nobody else is signed in). Each child is checked separately | `ScreenTimeDaemon`, `PLASMA_LOGOUT_COMMANDS` |
| `screentime/service.py` | Writes, enables and restarts `family-policyd.service` (the `screentime` layer) | `ScreenTimeService`, `render_service` |
| `screentime/gate.py` | Sign-in check run by `pam_exec` in SDDM's account stack: refuses a child at bedtime, after the day's limit, or when turned off; fails closed | `check`, `pam_main` |

### Security layer (`security/`)

Each manager takes a `SystemAdapter`, so the same code path runs in simulation.

| Module | Role | Key names |
|--------|------|-----------|
| `adapter.py` | Runs commands and writes files. Forces dry-run on non-Linux and when not root. Writes atomically, falling back to an in-place write for bind-mounted files. | `SystemAdapter`, `CommandResult` |
| `users.py` | Creates parent and child accounts, groups (`family-parent`, `family-children`), sudoers, password, home permissions (`0700`); signs a child out before deleting the account and reports a failed delete | `UserManager` |
| `firewall.py` | UFW baseline: deny incoming, allow outgoing, block legacy outbound ports | `FirewallManager` |
| `dns_filter.py` | systemd-resolved drop-in with family DNS servers; managed `/etc/hosts` block section; removes and pins `libnss-resolve` and keeps `resolve` off the nsswitch hosts line, so every lookup is a DNS query the child gateway sees | `DNSFilterManager`, `hosts_without_nss_resolve`, `lookups_use_dns` |
| `browser.py` | Generates and writes managed policies for Firefox ESR, Chromium, Chrome, Edge and Brave (private and guest windows, developer tools, SafeSearch, YouTube restricted, the browser's own DNS-over-HTTPS off, Encrypted Client Hello off so the child filter can see site names, proxy locked to direct, Brave Tor off). URL rules are per child and enforced by the gateway, not here | `BrowserPolicyManager`, `FIREFOX_POLICY_PATH` |
| `dns_gateway.py` | Per-child DNS gateway. Answers each child's lookups from that child's rules and DNS provider (second server as fallback), forces SafeSearch by answering search engines' names with their filtered services, refuses blocked names, records blocked lookups (including `0.0.0.0` blocks) for the parent in a private, bounded file, and adds allowed addresses to the child's nftables allow set in one transaction per answer. Reloads website rules on SIGHUP | `ChildResolver`, `DomainRules`, `RequestLog`, `AddressAllowList`, `safe_search_target`, `reload_rules`, `run` |
| `tls_proxy.py` | Per-child HTTPS (SNI) and HTTP (Host) name check on the redirected ports 443 and 80. Relays a connection only when its address and name came from the child's allowed lookups; falls back to the name's other allowed addresses when one cannot be reached | `ProxyContext`, `decide`, `LearnedNameAddresses`, `connection_candidates` |
| `web_gateway.py` | Renders the gateway's config, nftables rules (each child reaches only their own gateway ports on loopback), `family-web-rules.service` (loads the rules early at boot, apart from the gateway) and the sandboxed `family-dnsd.service`. Website rule changes reload the gateway; only a change of children restarts it, and the rules table is reloaded only when it changes | `render_config`, `render_nft`, `render_service`, `render_rules_service`, `rules_cover_children` |
| `desktop_lockdown.py` | Plasma kiosk restrictions for children only: `[KDE Action Restrictions][$i]` in `/etc/xdg/family-linux-children/kdeglobals` (no shell access, no Alt+F2 run dialog, no `--config` override, no running `.desktop` files, no Open With command line), put first in `XDG_CONFIG_DIRS` for `family-children` by a managed PAM block in `/etc/pam.d/sddm`. Two more managed blocks there, for children only: the sign-in re-lock of their start-up files (before `@include common-session`) and the sign-in hours check (`screentime/gate.py`). Removes the old system-wide block, so the parent keeps a terminal | `DesktopLockdown`, `with_pam_block`, `lockdown_in_place`, `LOCKED_RESTRICTIONS`, `render_relock_block`, `render_gate_block` |
| `child_startup.py` | Replaces each child's sign-in startup files and folders (`~/.profile`, `~/.xprofile`, `~/.xsessionrc`, `~/.config/autostart`, `autostart-scripts`, `environment.d`, `plasma-workspace/env` and `shutdown`, `systemd/user`, and under `~/.local/share`: `systemd/user`, `dbus-1/services`, `kio/servicemenus`, `plasma/plasmoids`, `kwin/scripts`) with empty root-owned immutable ones, through descriptors opened with `O_NOFOLLOW`. Existing folders are set aside, never deleted. Also run by `pam_exec` at each child sign-in (`--pam`), so a renamed parent folder is locked again | `ChildStartupLock`, `lock_startup_paths`, `startup_locked`, `pam_main`, `LOCKED_PATHS` |
| `apparmor.py` | Writes and loads the `family-linux-child` profile: desktop apps run (display, sound, network, file locks, the Firefox and Chrome sandboxes; apps under `/opt`, such as Google Chrome; script launchers such as Debian's Chromium; Qt's temporary-file saves, via `mediate_deleted`); shells, terminals, interpreters (`python3`, `perl` and others), `systemd-run`, `systemctl` and D-Bus tools, sudo, su, pkexec, package tools, sensitive files and raw sockets stay denied, as are D-Bus calls that start units in the user's service manager | `AppArmorManager`, `CHILD_SESSION_PROFILE` |
| `child_dirs.py` | Root-safe access to a child's override folder: each component opened with `O_NOFOLLOW` from the one above, writes by temporary name and rename, `fchown` for the child's folders, the immutable flag set and read with the `FS_IOC_SETFLAGS`/`FS_IOC_GETFLAGS` ioctls on the descriptor. Used by root real runs; dry runs use the path-based code in `app_guard.py` | `open_overrides_dir`, `write_file`, `remove_file`, `set_immutable`, `is_immutable` |
| `app_guard.py` | Scans the system `.desktop` folders (`/usr/share/applications`, `/usr/local/share/applications`); writes marked `NoDisplay=true` overrides for unapproved apps in the child's home (approved apps get an `aa-exec` launcher with D-Bus activation off), and removes overrides that are no longer needed. The approval check writes no audit records | `AppGuard`, `is_managed_override`, `MANAGED_MARKER`, `SYSTEM_APP_DIRS` |
| `desktop_refresh.py` | Re-applies child app approvals; run by `family-appguard.path` (systemd) when apt or PackageKit changes desktop entries | `refresh`, `render_path_unit`, `render_service_unit`, `WATCHED_DIRS` |
| `package_gate.py` | Polkit rule that makes every PackageKit action (install, remove, update, refresh) by a child account need the parent's password (`AUTH_ADMIN`); installs PackageKit if missing; removes Flatpak, Snap and Discover's Flatpak and Snap backends, and pins them at priority -1 | `PackageInstallGate`, `render_polkit_rule`, `rule_in_place`, `render_apt_pin`, `BLOCKED_PACKAGES` |
| `password_policy.py` | Managed PAM block in `/etc/pam.d/passwd`: `pam_pwquality` for the parent (14+ characters, all four classes) on every `passwd` change, with children exempted by name. Installs `cracklib-runtime` (the dictionary pwquality needs) | `ParentPasswordRules`, `render_pam_block`, `insert_block`, `block_in_place` |

### Runtime paths

Paths are chosen at runtime. The first set is used when running as root or when `/etc` is writable. The second set is the per-user fallback (for example on a developer machine).

| Purpose | System path | User fallback |
|---------|-------------|---------------|
| Policy file (`0600`) | `/etc/family-linux/policy.yaml` | `~/.config/family-linux/policy.yaml` |
| Policy backups | `/etc/family-linux/backups/` | `~/.config/family-linux/backups/` |
| Audit log (rotated weekly by `/etc/logrotate.d/family-linux`) | `/var/log/family-linux/audit.log` | `~/.local/share/family-linux/audit.log` |
| Screen-time usage | `/var/lib/family-linux/screentime.json` | `~/.local/share/family-linux/screentime.json` |
| Install log (written during the installer's late command) | `/var/log/family-linux-install.log` | (none) |
| Child desktop overrides | `/home/<child>/.local/share/applications/` | (none) |
| Firefox ESR policy | `/usr/lib/firefox-esr/distribution/policies.json`, `/etc/firefox/policies/policies.json`, `/etc/firefox-esr/policies/policies.json` | (none) |
| Chromium policy | `/etc/chromium/policies/managed/family-policy.json` | (none) |
| Chrome policy | `/etc/opt/chrome/policies/managed/family-policy.json` | (none) |
| Edge policy | `/etc/opt/edge/policies/managed/family-policy.json` | (none) |
| Brave policy | `/etc/brave/policies/managed/family-policy.json` (for Brave from Brave's own repository) | (none) |
| Web gateway config and rules | `/etc/family-linux/dns-gateway.json`, `/etc/family-linux/nftables-children.nft`, `/etc/systemd/system/family-dnsd.service`, `/etc/systemd/system/family-web-rules.service` | (none) |
| Screen-time service | `/etc/systemd/system/family-policyd.service` | (none) |
| Blocked web requests (root only, 200 per child at most) | `/var/lib/family-linux/web-requests.json` | (none) |
| Boot menu password | `/etc/grub.d/01_family-linux` (root only), `/etc/default/grub.d/family-linux.cfg`, `--unrestricted` added to `/etc/grub.d/10_linux`; `/boot/grub/grub.cfg` kept `0600` | (none) |
| Plasma kiosk restrictions (children) | `/etc/xdg/family-linux-children/kdeglobals`, `/etc/security/family-linux-children.conf`, `/etc/pam.d/sddm` (managed block) | (none) |
| Locked sign-in startup paths (children) | `/home/<child>/.profile` and the others in `child_startup.LOCKED_PATHS` | (none) |
| Installer step results | `/var/lib/family-linux/install-failures`, `/var/lib/family-linux/install-status` | (none) |
| Appliance power-off flag (removed by the first boot) | `/etc/family-linux/poweroff-after-firstboot` | (none) |
| Flatpak and Snap pin | `/etc/apt/preferences.d/family-linux-no-flatpak-snap` | (none) |
| nss-resolve pin, and the hosts line without `resolve` | `/etc/apt/preferences.d/family-linux-no-nss-resolve`, `/etc/nsswitch.conf` | (none) |
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
| `test_audit.py` | Audit log writes, reads, and filters; the logrotate file |
| `test_installer.py` | Non-interactive wizard validation, dry-run apply, the preseed export and its late-command script |
| `test_iso.py` | Boot-menu changes against Debian 13.7's own GRUB and isolinux menus (`tests/fixtures/`): interactive vs automated, expert and rescue entries untouched, no duplicate arguments, the BIOS timeout |
| `test_child_startup.py` | Sign-in startup files locked on real files: existing `.profile` emptied, autostart set aside, symlinked `.profile` and `.config` refused, second apply, the `~/.local/share` paths, re-lock after a parent folder is renamed, the PAM entry point, dry run |
| `test_preseed.py` | The preseed (KDE Plasma task, Debian repositories, no root login, hashes only, packages, disk, UEFI) and the late command (groups, sudoers, children, payload without the script or policy in `/opt`, networking, wallpaper, the GRUB password and its PBKDF2 format). Runs `sh -n` on the script, including a child name with quotes. The disk erase is confirmed by a person unless the build is unattended. Runs the real script against a temporary target to check that failed steps are listed without password hashes |
| `test_cli.py` | `family-ctl` commands in simulation, isolated from real paths; `verify` is `[INCOMPLETE]` off Linux; removing a child signs them out first and keeps them when the delete fails |
| `test_screentime.py` | Usage tracking, quota and curfew evaluation (bedtimes after midnight, weekend nights), time-limit validation, one child's error not stopping the others, notifications through `runuser`, daily warnings, locked screens not counted, the sign-in hours check, sign-out through Plasma then forced with the sign-in screen restored, the service unit |
| `test_security.py` | Security managers in simulation; Plasma kiosk lockdown and its PAM blocks; exact approved-app matching; the profile's interpreter and D-Bus denials; dry-run reaches policy and audit writers |
| `test_package_gate.py` | Polkit rule content and safety (every PackageKit action), dry-run write, AppGuard hiding unapproved apps and confining approved ones |
| `test_password_policy.py` | PAM block layout, child exemption by name, idempotent insertion, dry run |
| `test_firstboot_iso.py` | First-boot marker and apply, browser policy paths, the first-boot unit ordering (before the sign-in screen), children created locked and unlocked only after a full apply, the early rules unit, stale installer files removed from `/opt`, every unit in `config/systemd` installed by the ISO and every unit the apply writes enabled, wallpaper step |
| `test_sha512crypt.py` | SHA-512 crypt against glibc vectors; preseed hashes |
| `test_desktop_refresh.py` | Menu refresh units and re-apply |
| `test_kde_app_backend.py` | Family Controls backend (pkexec calls, password on stdin, errors), `state`/`web remove`/`--password-stdin`, install steps, terminals and settings never approvable |
| `test_kde_app_window.py` | Family Controls window (PyQt6, offscreen): children and requests listed, a child's page with its sites and app switches. Skipped where PyQt6 is missing |
| `test_secrets.py` | Passwords never serialised, never in repr, dropped from files on next save |
| `test_child_dirs.py` | A child's symlinks cannot make root write outside the child's folders (real files, no root needed) |
| `test_app_visibility.py` | Approved apps shown, unapproved hidden, child owns `~/.local`, overrides folder locked |
| `test_dns_gateway.py` | Per-child rules and providers, blocked and `0.0.0.0` answers never reach the allow list, one nft batch per answer, upstream fallback, SafeSearch answers, reload without restart, loopback isolation between children, the sandboxed unit, name-to-address records |
| `test_tls_proxy.py` | ClientHello and Host parsing, ECH refusal, the allow decision, relay, IPv6 fallback to another allowed address |
| `test_timezone.py` | Time zone validation, host default, the preseed's time zone |
| `test_provisioning.py` | Save-before-apply ordering and the `ProvisioningError` message |
| `integration/test_linux_provisioning.py` | Real accounts, sudoers, and UFW. Root on Linux with `FAMILY_LINUX_INTEGRATION=1` only; skipped elsewhere |

The integration tests run in the `linux-integration` CI job. They are not run by the default test command.

## Dependencies

- Runtime: Python 3.11 or newer (per `pyproject.toml`; Debian 13 has 3.13); `pyyaml>=6.0`. On the installed system, the Debian packages `python3`, `python3-yaml` and `python3-pyqt6` (see `PACKAGES` in `provisioner/preseed.py`).
- Dev: `pytest>=7.0`, `pytest-cov>=4.0`. `test_kde_app_window.py` also needs PyQt6 and is skipped without it.
- Standard library only elsewhere (`subprocess`, `json`, `dataclasses`, `socket`).
- The `crypt` module is optional; the generator falls back to a SHA-512 crypt-style hash when it is missing.
