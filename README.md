# Family Linux

Family Linux is a private, prototype-stage project for a child-safe Ubuntu LTS desktop that one parent can manage without expert Linux knowledge.

The repository holds a working Python prototype and the build for an installable system. It builds Ubuntu 24.04 install ISOs (arm64 and amd64) and a VirtualBox appliance (`.ova`). The arm64 appliance has been installed, booted and checked in VirtualBox on Apple silicon. It has not been installed on real hardware, and the amd64 ISO has not had a full install yet.

- Repository layout: [STRUCTURE.md](STRUCTURE.md)
- Development history, review findings, and open items: [DEV_HIST.md](DEV_HIST.md)
- Parent guide to web filtering: [docs/web-filtering-guide.md](docs/web-filtering-guide.md)

## Project direction

- **Ubuntu as the base distribution** (with an Ubuntu LTS baseline for long-term support)
- **Ubuntu-standard security mechanisms** (users/groups, sudo for administrators, AppArmor where applicable, firewall policy, signed packages/repositories, and regular security updates)
- **One parent account managing multiple child accounts**
- **An interactive installer** with recommended defaults plus optional advanced adjustments

## Project goals

- Deliver a predictable, minimal child-friendly desktop workflow
- Keep child accounts non-admin with restricted access to settings and software changes
- Provide clear parent controls for account management, app approval, and safety policy
- Keep defaults conservative, auditable, and maintainable

## Security posture

Family Linux is inspired by OpenBSD discipline (minimal services, least privilege, and auditability), but it uses Ubuntu-native security and administration models rather than a custom security stack.

Current protections in the prototype:

- The parent dashboard listens on `127.0.0.1` only, requires an access token, and rejects cross-origin and non-JSON requests.
- Passwords are never written to the policy file or the API. They are used once to set the account password.
- The parent password must be at least 14 characters with upper-case, lower-case, a number and a special character. This applies at install time and on every later change or reset through `passwd` (PAM `pam_pwquality`). Child passwords are not affected.
- Saving the policy happens before system changes, so a failed apply can be re-run to finish.
- `family-ctl verify` reports real system state on Linux and says so when a check cannot run.

## System requirements

**Machine that runs Family Linux (the installed system):**

| Item | Minimum | Recommended | Tested |
|------|---------|-------------|--------|
| Ubuntu | 24.04 LTS desktop (`ubuntu-desktop-minimal`, installed by the ISO) | 24.04.5 LTS | 24.04.5 LTS |
| Architecture | amd64 or arm64 | arm64 on Apple silicon; amd64 on Intel or AMD PCs | arm64 end to end in VirtualBox 7.2.20. amd64 runs in CI; the amd64 ISO has not been installed end to end |
| Firmware | UEFI | UEFI | UEFI |
| Memory | 4 GB (Ubuntu's desktop minimum; not measured with Family Linux) | 8 GB for smooth use with several apps open | 4 GB (`MEMORY_MB` 4096) |
| CPU | 2 cores (Ubuntu's desktop minimum; not measured) | 4 cores | 4 vCPUs |
| Disk | 25 GB (Ubuntu's desktop minimum; not measured with Family Linux) | 64 GB or more, for updates and apps | 40 GB virtual disk; about 10 GB used after install |
| Network | Needed during install (packages are downloaded) and for the first boot | Always connected, for security updates | DHCP |

The minimums come from Ubuntu's published desktop requirements. Family Linux has only been measured at the tested values, so treat anything below them as untested.

**Machine that builds the ISO and appliance:**

- macOS on Apple silicon or Linux. The arm64 appliance was built on an Apple M4 Mac.
- About 12 GB free: the Ubuntu image (3.8 GB), the built ISO (3.6 GB), and the appliance (5.0 GB), plus the VM disk.
- `xorriso`, `curl`, `rsync`, Python 3.9 or later with PyYAML, and for the appliance VirtualBox 7.2 or later (`VBoxManage`).

**Running the tests or the CLI only:** Python 3.9 or later (`requires-python` in `pyproject.toml`). CI runs Python 3.9 to 3.13 on Ubuntu and macOS.

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

`scripts/build-autoinstall-iso.sh` repacks the official Ubuntu 24.04.5 live-server ISO with an unattended installer, the Family Linux source and policy, and a first-boot step that applies the full policy. It picks arm64 on Apple silicon and amd64 elsewhere; set `ARCH` to override.

```bash
brew install xorriso                      # or: apt install xorriso
PARENT_PASS='Correct-Horse-42-Battery' ./scripts/build-autoinstall-iso.sh
# -> dist/family-linux-ubuntu-24.04-arm64.iso (or -amd64.iso)
```

The installed system uses the time zone of the computer that builds the ISO; set `TIMEZONE` (for example `TIMEZONE=Australia/Sydney`) to choose another. Bedtimes and curfews use local time. The image is downloaded to `build/` and checked against Ubuntu's `SHA256SUMS`. The parent password must meet the parent rules. Only its hash is written to the ISO.

To set the desktop wallpaper, put one `.png` or `.jpg` in `config/wallpaper/` before building. It becomes the default desktop and lock-screen picture for every account (see `config/wallpaper/README.md`).

**VirtualBox appliance (.ova):** `scripts/build-virtualbox-vm.sh` builds the ISO, installs it into a new VirtualBox VM without any prompts, waits for the first-boot apply, and exports an appliance. It needs VirtualBox 7.2 or later; on an Apple silicon Mac it builds an arm64 VM.

```bash
PARENT_PASS='your-own-14+-char-Password!' CHILD_SPECS='kid:Kid:pre_teen:child-password' \
  ./scripts/build-virtualbox-vm.sh
# -> dist/family-linux-ubuntu-24.04-arm64.ova   (import: File > Import Appliance)
```

The appliance contains the parent password you build it with, so use your own and do not share an appliance built with a password other people know.

### Family Controls (GNOME app)

On an installed system, the parent opens **Family Controls** from the GNOME app menu. It shows each child, with:

- **Account:** sign-in on or off, remove a child, add a child (the password is sent on standard input, never on the command line).
- **Screen time:** daily limit, bedtimes for school nights and weekends, wake time, today's usage, reset today's usage.
- **Websites:** block or always allow a site, remove a rule, and approve or keep blocked the sites a child asked for.
- **Apps:** a switch for each installed app. System tools (Terminal, Settings, the software store) are always hidden for children.

Every change runs `family-ctl` through `pkexec`. GNOME asks for the parent's password (polkit action `org.familylinux.manage`, remembered for a few minutes), so the app never runs as root. Children cannot open it: it is hidden from their menus, and polkit requires an administrator's password. It needs GTK 4 and libadwaita (`python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`), which the ISO installs.

For design work without a real system: `FAMILY_LINUX_DEMO_STATE=state.json python3 -m family_linux.gnome_app`.

### Dashboard sign-in

`dashboard` prints a one-time link:

```
[Family Linux] Open this one-time link to sign in: http://127.0.0.1:8443/?token=…
```

Open it in a browser on the same machine. It sets a session cookie and redirects, so the token leaves the address bar. Set `FAMILY_LINUX_DASHBOARD_TOKEN` to choose the token yourself.

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
| `autoinstall FILE` | Writes an Ubuntu Subiquity autoinstall `user-data` file; needs `PARENT_PASS` in the environment |

### What `verify` checks

Policy checks run everywhere. Live checks run only on Linux and read the real system:

- parent sudoers drop-in present and valid (`visudo -cf`)
- UFW active with deny incoming
- Firefox and Chromium managed policy files present
- AppArmor child profile loaded in enforce mode (asked of the kernel)
- unattended security upgrades enabled
- the new-release upgrade notice is off (security updates continue)
- parent password rules enforced by PAM on password changes
- snap installs by a child need the parent's password on every attempt (polkit rule; snapd installed)
- child menus follow app approval: approved apps are shown, other system-wide apps are hidden, and the parent's home is private (0700)

On any other host, the live checks are reported as `[SKIP]` and the result is `[INCOMPLETE]`, never `[SUCCESS]`. A missing tool is a `[FAIL]` with the reason.

### Integration tests (Linux, root)

`tests/integration/` runs real `useradd`, `passwd`, `visudo`, and `ufw` commands. It only runs as root on Linux with `FAMILY_LINUX_INTEGRATION=1`, and CI runs it in a dedicated job on an ephemeral runner. Do not run it on a workstation.

## Repository layout

- `/docs`: design and architecture documents
- `/config`: policy templates, browser policy templates, and systemd units
- `/scripts`: bootstrap launcher and ISO helper
- `/src/family_linux`: Python implementation
- `/tests`: pytest suite, including `tests/integration/`

## Current status

Last updated 15 October 2026.

### GitHub repository

- Repository: [lukecarnold-jpg/family-linux](https://github.com/lukecarnold-jpg/family-linux). Public. Default branch `main`.
- `main` contains PRs #1 to #5. The most recent merge is PR #5 (Installable Family Linux), merged on 12 October 2026. Its CI run passed.
- No pull requests are open.
- Branch `arm64-iso` has 7 commits that are **not on `main`** and have **no open pull request**. They were pushed after PR #5 was merged. CI only runs on pushes to `main` and on pull requests into `main`, so these commits have not been through CI:
  - `e052a41` Family Controls GNOME app; new-release upgrade notice off
  - `edf8cad` Firefox and the App Centre
  - `0062d2d` web filtering guide for parents
  - `11fade4` README system requirements
  - `cf321e2` web filter falls back to a site's other address; Brave and Edge settings
  - `9eae121` wallpaper; children's `~/.local` owned by root
  - `e968f56` arm64 image moved to `cdimage.ubuntu.com/ubuntu/releases`
- Branches `harden-prototype` and `snap-install-gate` were merged in PRs #3 and #4 and can be deleted.

### Implemented

- Install ISOs for arm64 and amd64, built from the official Ubuntu 24.04.5 live-server image (checked against `SHA256SUMS`), with an unattended install and a first-boot apply of the policy.
- VirtualBox appliance (arm64) built by `scripts/build-virtualbox-vm.sh`.
- Parent password rules (14+ characters, all four character classes) at install and on every `passwd` change.
- Child snap installs need the parent's password (polkit). The Snap Store app is hidden from children.
- Family Controls, the parent's GNOME app: children, screen time, websites, website requests, apps.
- Per-child web filtering through a local DNS gateway and HTTP(S) name check. Browser policies for Firefox, Chromium, Chrome, Edge and Brave (the Brave snap cannot read its policy, so it is blocked for children).
- Time zone set during setup. Optional wallpaper from `config/wallpaper/`.
- Ubuntu's new-release upgrade notice is turned off; security updates continue.
- `family-ctl verify` reports real system state on Linux and says so when a check cannot run.
- Test suite: 228 passed, 5 skipped (`pytest`).

### Not yet done, or not validated

- A full install from the amd64 ISO.
- Installed-system tests on real hardware.
- Browser settings in Chrome, Edge and Brave from Brave's own website have not been checked on an installed system. Firefox and Chromium have been set but not confirmed in a running browser.
- Child lockdown is partial: terminals can still be reached by some routes. See the open items in [DEV_HIST.md](DEV_HIST.md).
- Screen-time daemon and child notifications are not yet confirmed on an installed system.
- The built images and the appliance contain the test passwords used to build them. Do not share them.

The full list, with file references, is in [DEV_HIST.md](DEV_HIST.md).

Design documents:

- `/docs/vision.md`
- `/docs/architecture.md`
- `/docs/installer.md`
- `/docs/roadmap.md`

## License

MIT. See [LICENSE](LICENSE).

## Privacy

The repository is public on GitHub. Built images (`build/` and `dist/`) are git-ignored and are not in the repository. They contain the passwords used to build them, so do not share them.
