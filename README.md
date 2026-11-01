# Family Linux

Family Linux is a private, prototype-stage project for a child-safe Debian desktop, with KDE Plasma, that one parent can manage without expert Linux knowledge.

The repository holds a Python prototype (an installer flow, a parent CLI, a local parent web dashboard, a screen-time daemon, and generators for browser, firewall, DNS and AppArmor policy) and the build for an installable system. It builds Debian stable install ISOs (arm64 and amd64) and a VirtualBox appliance (`.ova`). The base is Debian 13 (trixie) with KDE Plasma and packages from the Debian repositories.

- Repository layout: [STRUCTURE.md](STRUCTURE.md)
- Development history, review findings, and open items: [DEV_HIST.md](DEV_HIST.md)
- Parent guide to web filtering: [docs/web-filtering-guide.md](docs/web-filtering-guide.md)

## Project direction

- **Debian stable as the base distribution**, with KDE Plasma as the desktop and packages from the Debian repositories (main, contrib and non-free-firmware) through apt. Snap and Flatpak are not used.
- **Debian's own security mechanisms** (users and groups, sudo for administrators, AppArmor where applicable, UFW, signed packages from Debian's repositories, and unattended security updates).
- **One parent account managing multiple child accounts.**
- **An unattended install** from the ISO, with the parent and child accounts set up in advance, and a first boot that applies the full policy.
- The wallpaper is built into the ISO and set for each account at its first login.

## Project goals

- Deliver a predictable, minimal child-friendly desktop workflow
- Keep child accounts non-admin, with restricted access to settings and software changes
- Provide clear parent controls for account management, app approval, websites, and screen time
- Keep defaults conservative, auditable, and maintainable

## Security posture

Family Linux is inspired by OpenBSD discipline (minimal services, least privilege, and auditability), but it uses Debian's own security and administration models rather than a custom security stack.

Current protections in the prototype:

- The parent dashboard listens on `127.0.0.1` only, requires an access token, and rejects cross-origin and non-JSON requests.
- Passwords are never written to the policy file or the API. The installer writes only password hashes; the parent password is used once to set the account password.
- The parent password must be at least 14 characters with upper-case, lower-case, a number and a special character. This applies at install time and on every later change or reset through `passwd` (PAM `pam_pwquality`). Child passwords are not affected.
- Every software change by a child account (install, remove, update, refresh) asks for the parent's password, on every attempt (polkit rule over PackageKit).
- Child accounts use a nologin shell, have no sudo rights, and cannot open a shell from the desktop: the Alt+F2 run dialog and shell access are locked with Plasma kiosk restrictions for every account.
- DNS for each child goes through a per-child filter that refuses blocked names and any connection it did not allow.
- Saving the policy happens before system changes, so a failed apply can be re-run to finish.
- `family-ctl verify` reports real system state on Linux and says so when a check cannot run.

## System requirements

These are the configurations the project has been run on. Lower limits have not been measured.

**Machine that runs Family Linux (the installed system):**

| Item | Minimum | Recommended | Tested |
|------|---------|-------------|--------|
| Debian | 13 (trixie) stable, KDE Plasma desktop (installed by the ISO) | the current 13.x point release | 13.7.0 (netinst image, installed in VirtualBox) |
| Architecture | amd64 or arm64 | arm64 on Apple silicon; amd64 on Intel or AMD PCs | arm64 in VirtualBox 7.2.20 on Apple silicon. amd64 is built and checked in CI; it has not been installed |
| Firmware | UEFI | UEFI | UEFI |
| Memory | 4 GB (not measured with Family Linux) | 8 GB for smooth use with several apps open | 4 GB (`MEMORY_MB` 4096) |
| CPU | 2 cores (not measured) | 4 cores | 2 vCPUs (`CPUS`) |
| Disk | 25 GB (not measured with Family Linux) | 64 GB or more, for updates and apps | 40 GB virtual disk |
| Network | Needed during install (packages are downloaded) and for the first boot | Always connected, for security updates | DHCP |

**Machine that builds the ISO and appliance:**

- macOS on Apple silicon or Linux.
- About 4 GB free for the Debian image and the built ISO, plus the VM disk for the appliance.
- `xorriso`, `curl`, `rsync`, Python 3.9 or later with PyYAML, and for the appliance VirtualBox 7.2 or later (`VBoxManage`).

**Running the tests or the CLI only:** Python 3.9 or later (`requires-python` in `pyproject.toml`). The Family Controls window tests also need PyQt6 and are skipped without it.

## Quick start

Requires Python 3.9 or newer.

```bash
python3 -m pip install -e ".[dev]"      # pyyaml, pytest, pytest-cov
./scripts/bootstrap-prototype.sh test   # run the test suite
./scripts/bootstrap-prototype.sh install --dry-run
./scripts/bootstrap-prototype.sh ctl status
./scripts/bootstrap-prototype.sh dashboard
```

Outside Linux, every system change is simulated, so these commands are safe on a development machine. On Linux, `install` without `--dry-run` changes the system after you confirm the summary, so run `--dry-run` first.

### Building the install ISO (arm64 or amd64)

`scripts/build-debian-iso.sh` repacks the official Debian stable netinst image with a preseed (an unattended Debian install with KDE Plasma), a late-command script that sets up the accounts and the Family Linux payload, and the first-boot unit. It picks arm64 on Apple silicon and amd64 elsewhere; set `ARCH` to override. The image is downloaded to `build/` and checked against Debian's `SHA512SUMS`.

```bash
brew install xorriso                      # or: apt install xorriso
PARENT_PASS='Correct-Horse-42-Battery' CHILD_SPECS='kid:Kid:pre_teen:child-password' \
  ./scripts/build-debian-iso.sh
# -> dist/family-linux-debian-stable-arm64.iso (or -amd64.iso)
```

Boot the ISO and press Enter on "Install" at the boot menu. The menu waits for that key on purpose. **The install erases the first disk the installer finds** (or the disk named in `TARGET_DISK`), so boot the ISO only on a computer you mean to set up.

The installed system uses the time zone you choose in the installer; the build sets `TIMEZONE` (for example `TIMEZONE=Australia/Sydney`) and defaults to the host's zone. Bedtimes and curfews use local time. The wallpaper is the one image in `config/wallpaper/`, if there is one. The ISO contains only the parent and child password hashes.

**VirtualBox appliance (.ova):** `scripts/build-virtualbox-vm.sh` builds the ISO, installs it into a new VirtualBox VM without prompts (it presses Enter at the boot menu), waits for the first-boot apply, and exports an appliance. It needs VirtualBox 7.2 or later; on an Apple silicon Mac it builds an arm64 VM.

```bash
PARENT_PASS='your-own-14+-char-Password!' CHILD_SPECS='kid:Kid:pre_teen:child-password' \
  VM_NAME='Family Linux Debian Test' ./scripts/build-virtualbox-vm.sh
# -> dist/family-linux-debian-stable-arm64.ova   (import: File > Import Appliance)
```

The appliance contains the parent password you build it with, so use your own and do not share an appliance built with a password other people know.

### Dashboard sign-in

`dashboard` prints a one-time link:

```
[Family Linux] Open this one-time link to sign in: http://127.0.0.1:8443/?token=…
```

Open it in a browser on the same machine. It sets a session cookie and redirects, so the token leaves the address bar. Set `FAMILY_LINUX_DASHBOARD_TOKEN` to choose the token yourself.

### Family Controls (KDE app)

On an installed system, the parent opens **Family Controls** from the application menu. It shows each child, with:

- the child's account (can sign in, age preset, remove)
- screen time (daily limit, bedtimes, wake time, reset today's usage)
- websites (block, always allow, remove rules) and website requests waiting for a decision
- apps (approve or hide each installed app)

Every change runs `family-ctl` through `pkexec`. Plasma asks for the parent's password (polkit action `org.familylinux.manage`, remembered for a few minutes), so the app never runs as root and all changes go through the same validated code as the command line.

For design work without a real system: `FAMILY_LINUX_DEMO_STATE=state.json python3 -m family_linux.kde_app`.

### Commands

| Command | What it does |
|---------|--------------|
| `help` (default) | Shows usage |
| `install [--dry-run]` | Runs the 12-step interactive installer |
| `install --dry-run --non-interactive --parent-pass PASS [--child user:Name:tier:PASS]… [--timezone Area/City]` | Unattended run; `--parent-pass` is required (min 14 characters, with upper-case, lower-case, a number and a special character) |
| `dashboard [port]` | Starts the parent web dashboard on `127.0.0.1` (default port 8443) |
| `ctl <args>` | Runs the `family-ctl` parent CLI (`status`, `user`, `app`, `time`, `web`, `audit`, `backup`, `verify`) |
| `policyd [--one-shot]` | Runs the screen-time and curfew enforcement daemon |
| `verify` | Checks the baseline (see below) |
| `test` | Runs the pytest suite |
| `preseed FILE` | Writes the Debian Installer preseed (and `late-command.sh` beside it); needs `PARENT_PASS` in the environment |

### What `verify` checks

Policy checks run everywhere. Live checks run only on Linux and read the real system:

- parent sudoers drop-in present and valid (`visudo -cf`)
- UFW active with deny incoming
- Firefox ESR, Chromium and Brave managed policy files present
- AppArmor child profile loaded in enforce mode (asked of the kernel)
- unattended security upgrades enabled
- parent password rules enforced by PAM on password changes
- Alt+F2 run dialog and shell access locked for every account (Plasma kiosk restrictions)
- software changes by children need the parent's password (polkit rule)
- child menus follow app approval: approved apps are shown, other system-wide apps are hidden, and the parent's home is private (0700)

On any other host, the live checks are reported as `[SKIP]` and the result is `[INCOMPLETE]`, never `[SUCCESS]`. A missing tool is a `[FAIL]` with the reason.

### Integration tests (Linux, root)

`tests/integration/` runs real `useradd`, `passwd`, `visudo`, and `ufw` commands. It only runs as root on Linux with `FAMILY_LINUX_INTEGRATION=1`, and CI runs it in a dedicated job on an ephemeral runner. Do not run it on a workstation.

## Repository layout

- `/docs`: design and architecture documents, and the parent guide
- `/config`: policy templates, browser policy templates, systemd units, menu entries, polkit, wallpaper, and the wallpaper step
- `/scripts`: bootstrap launcher, Debian ISO builder, VirtualBox appliance builder
- `/src/family_linux`: Python implementation (`kde_app` is the Family Controls window)
- `/tests`: pytest suite, including `tests/integration/`

## Current status

Implemented (prototype level):

- Policy model with validation, saved with backups to one YAML file
- Parent CLI for child accounts, app approvals, screen-time limits, website block and allow lists, audit log, backups, and baseline verification
- Parent web dashboard with token sign-in (JSON API and single page)
- Family Controls, the parent's KDE app (PyQt6): children, screen time, websites, apps, website requests, add child
- Screen-time tracker and enforcement daemon
- Generators for firewall (UFW), per-child DNS gateway, Firefox ESR and Chromium policies, the AppArmor profile, desktop app filters, PackageKit install gate, and the Plasma kiosk lockdown
- Debian preseed and late-command generator (KDE Plasma, Debian repositories, accounts, payload, network, updates)

Status of the Debian base (see [DEV_HIST.md](DEV_HIST.md) for the checks and the open items):

- An unattended install of Debian 13.7.0 with KDE Plasma (arm64 ISO, VirtualBox 7.2.20 on Apple silicon) completed. The first boot applied the policy with no warnings and the machine reached its login prompt.
- Not yet checked on the installed desktop: a child signing in on the SDDM login screen, the wallpaper at first login, the Alt+F2 and Ctrl+Alt+T locks, Discover's password prompt for children, Firefox ESR's policy, and the DNS filter on the running system.
- The amd64 ISO builds and passes its checks, but has not been installed.
- The arm64 appliance `dist/family-linux-debian-stable-arm64.ova` is built from the same install. It has not been imported or booted yet.

Not yet implemented, or not validated:

- Installation to real hardware.
- amd64 install: the ISO is built and checked in CI, but no install has been run. Its BIOS boot menu is not patched.
- Anything that depends on the child's desktop session is only as tested as the VirtualBox run says.
- Terminal shortcut (Ctrl+Alt+T) for child accounts is expected to be blocked by hiding Konsole; not yet confirmed.
- Continuous integration does not run the Debian install. Its Linux jobs run on an Ubuntu runner.

Repository status (checked with `gh` on 2026-11-01):

- Default branch: `main`, which now includes PR #6 (`arm64-iso`, merged). CI runs on pushes to `main` and on pull requests into `main`.
- Working branch: `debian-kde`, based on `main`. It has no CI until a pull request into `main` is open.
- Open pull requests: [#7](https://github.com/lukecarnold-jpg/family-linux/pull/7) (`debian-kde` into `main`). Its CI run passed all 13 jobs: unit tests on Python 3.9 to 3.13 on Ubuntu and macOS, the privileged Linux integration job, the live-apply job, and the amd64 ISO build and check. The CI jobs do not install Debian; the arm64 install was checked in VirtualBox.

Design documents:

- `/docs/vision.md`
- `/docs/architecture.md`
- `/docs/installer.md`
- `/docs/roadmap.md`

## License

MIT. See [LICENSE](LICENSE).

## Privacy

This repository remains private until design and prototype quality are ready for a public release.
