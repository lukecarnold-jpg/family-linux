# Family Linux

Family Linux is a private, prototype-stage project for a child-safe Ubuntu LTS desktop that one parent can manage without expert Linux knowledge.

The repository holds a working Python prototype: an installer flow, a parent CLI, a local parent web dashboard, a screen-time enforcement daemon, and generators for browser, firewall, DNS, and AppArmor policy. It configures a running Ubuntu system. It does not yet install Ubuntu or build a bootable ISO, and it has not been validated on a real Ubuntu desktop.

- Repository layout: [STRUCTURE.md](STRUCTURE.md)
- Development history, review findings, and open items: [DEV_HIST.md](DEV_HIST.md)

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

These are the configurations the project has actually been run on. Lower limits have not been measured.

**Machine that runs Family Linux (the installed system):**

| Item | Used and tested | Build default |
|------|-----------------|---------------|
| Ubuntu | 24.04.5 LTS, desktop (`ubuntu-desktop-minimal`, installed by the ISO) | same |
| Architecture | arm64 (tested end to end in VirtualBox 7.2.20) or amd64 (CI on x86_64 runners; the amd64 ISO and appliance have not been run end to end) | arm64 on Apple silicon, amd64 elsewhere |
| Firmware | UEFI | UEFI |
| Memory | 4 GB | 4096 MB |
| CPU | 4 vCPUs in tests | 2 vCPUs (`CPUS`) |
| Disk | 40 GB virtual disk; about 10 GB used after install, plus a swap file created by the installer | 40960 MB (`DISK_MB`) |
| Network | required during install (packages are downloaded) | DHCP |

**Machine that builds the ISO and appliance:**

- macOS on Apple silicon or Linux. The arm64 appliance was built on an Apple M4 Mac.
- About 12 GB free: the Ubuntu image (3.8 GB), the built ISO (3.6 GB), and the appliance (4.2 GB), plus the VM disk.
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

Implemented (prototype level):

- Policy model with validation, saved with backups to one YAML file
- Parent CLI for child accounts, app approvals, screen-time limits, web block and allow lists, audit log, backups, and baseline verification
- Parent web dashboard with token sign-in (JSON API and single page)
- Screen-time tracker and enforcement daemon
- Generators for firewall (UFW), DNS filtering, Firefox and Chromium policies, the AppArmor profile, and desktop app filters
- Ubuntu autoinstall `user-data` generator (language, keyboard, and target disk carried through)
- Live install on Ubuntu 24.04 verified in a container: accounts, sudoers, UFW, and the policy file

Not yet implemented, or not validated:

- Installation to disk. The installer does not partition or install Ubuntu.
- A bootable ISO. `scripts/build-autoinstall-iso.sh` prints manual steps.
- Child session lockdown. Only desktop menu entries are hidden; a terminal is still reachable.
- Confirmed browser policy on Ubuntu, where Firefox and Chromium are snaps.
- The AppArmor profile is not yet attached to any process, so it may confine nothing.
- Validation on a real Ubuntu VM with AppArmor and systemd running.

The full list, with file references, is in [DEV_HIST.md](DEV_HIST.md).

Design documents:

- `/docs/vision.md`
- `/docs/architecture.md`
- `/docs/installer.md`
- `/docs/roadmap.md`

## License

MIT. See [LICENSE](LICENSE).

## Privacy

This repository remains private until design and prototype quality are ready for a public release.
