# Family Linux

Family Linux is a private, prototype-stage project for a child-safe Debian desktop, with KDE Plasma, that one parent can manage without expert Linux knowledge.

The repository holds a Python prototype (an installer flow, a parent CLI, the Family Controls app, a screen-time service, and generators for browser, firewall, DNS and AppArmor policy) and the build for an installable system. It builds Debian stable install ISOs (arm64 and amd64) and a VirtualBox appliance (`.ova`). The base is Debian 13 (trixie) with KDE Plasma and packages from the Debian repositories.

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

- Passwords are never written to the policy file or the API. The installer writes only password hashes; the parent password is used once to set the account password.
- The parent password must be at least 14 characters with upper-case, lower-case, a number and a special character. This applies at install time and on every later change or reset through `passwd` (PAM `pam_pwquality`). Child passwords are not affected.
- Every software change by a child account (install, remove, update, refresh) asks for the parent's password, on every attempt (polkit rule over PackageKit). Flatpak and Snap, which would install around that rule, are removed and pinned so apt never installs them.
- Child accounts use a nologin shell, have no sudo rights, and cannot open a shell from the desktop: the Alt+F2 run dialog and shell access are locked with Plasma kiosk restrictions that apply to children only. The parent keeps a terminal.
- A child cannot run commands at sign-in: the files and folders the session reads from the child's home (`~/.profile`, autostart, Plasma env scripts, systemd user units, session bus services, Dolphin service menus, Plasma widgets and KWin scripts) are empty, root-owned and immutable, and they are locked again as root at every child sign-in, before the session starts.
- Screen time is enforced by the `family-policyd` service, which the first boot installs and starts: daily limits, bedtimes (including bedtimes after midnight) and turned-off accounts. A child's sign-in is refused at bedtime or once the day's limit is used, and time counts only while the child's session is in use and unlocked.
- Child accounts stay locked until the first boot, or any later change, has applied their web filter and desktop rules. The sign-in screen waits for the first boot.
- The boot menu (GRUB) needs the parent's name and password to edit an entry or open its command line; the computer starts normally without it. Recovery mode entries are not offered.
- Programs a child runs through the confinement profile cannot start interpreters (`python3`, `perl` and the like) or ask the service manager or session bus to start a program outside the profile.
- The Debian image is used only after its checksum list is verified against Debian's CD signing keys, which are pinned in the repository.
- DNS for each child goes through a per-child filter that refuses blocked names and any connection it did not allow. It uses that child's own DNS provider, falls back to the provider's second server, and forces SafeSearch on Google, Bing, DuckDuckGo and YouTube in every browser. It runs with only the network capability it needs, and a child cannot reach a brother's or sister's filter.
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
- `xorriso`, `curl`, `rsync`, `gpgv` (`brew install gnupg` or `apt install gpgv`), Python 3.11 or later with PyYAML, and for the appliance VirtualBox 7.2 or later (`VBoxManage`).

**Running the tests or the CLI only:** Python 3.11 or later (`requires-python` in `pyproject.toml`). The Family Controls window tests also need PyQt6 and are skipped without it.

## Quick start

Requires Python 3.11 or newer (Debian 13 has 3.13).

```bash
python3 -m pip install -e ".[dev]"      # pyyaml, pytest, pytest-cov
./scripts/bootstrap-prototype.sh test   # run the test suite
./scripts/bootstrap-prototype.sh install --dry-run
./scripts/bootstrap-prototype.sh ctl status
```

Outside Linux, every system change is simulated, so these commands are safe on a development machine. On Linux, `install` without `--dry-run` changes the system after you confirm the summary, so run `--dry-run` first.

### Building the install ISO (arm64 or amd64)

`scripts/build-debian-iso.sh` repacks the official Debian stable netinst image with a preseed (an unattended Debian install with KDE Plasma), a late-command script that sets up the accounts and the Family Linux payload, and the first-boot unit. It picks arm64 on Apple silicon and amd64 elsewhere; set `ARCH` to override. The image is downloaded to `build/`. Debian's `SHA512SUMS` is checked against its signature with the Debian CD signing keys in `config/keys/`, and then the image is checked against `SHA512SUMS`.

```bash
brew install xorriso                      # or: apt install xorriso
PARENT_PASS='your-own-14+-char-Password!' CHILD_SPECS='kid:Kid:pre_teen:child-password' \
  ./scripts/build-debian-iso.sh
# -> dist/family-linux-debian-stable-arm64.iso (or -amd64.iso); OUTPUT_DIR=... writes it elsewhere
```

Boot the ISO and choose **Install** (or Graphical install) at the boot menu. The Debian installer opens with the Family Linux answers filled in: the accounts, the packages, the time zone and the disk. It still asks about anything those answers do not cover. **The install erases the first disk the installer finds** (or the disk named in `TARGET_DISK`), so boot the ISO only on a computer you mean to set up.

The installer asks before it writes to the disk. On amd64 the BIOS menu works the same way as the UEFI menu.

`MODE=automated` builds a variant whose Install entry starts after 5 seconds and runs with no questions at all, including the disk erase. The appliance build uses it.

The installed system uses the time zone you choose in the installer; the build sets `TIMEZONE` (for example `TIMEZONE=Australia/Sydney`) and defaults to the host's zone. Bedtimes and curfews use local time. The wallpaper is the one image in `config/wallpaper/`, if there is one. The ISO contains only the parent and child password hashes.

**VirtualBox appliance (.ova):** `scripts/build-virtualbox-vm.sh` builds the ISO, installs it into a new VirtualBox VM without prompts, waits for the first boot to apply the policy and power off, and exports an appliance. It needs VirtualBox 7.2 or later; on an Apple silicon Mac it builds an arm64 VM.

```bash
PARENT_PASS='your-own-14+-char-Password!' CHILD_SPECS='kid:Kid:pre_teen:child-password' \
  VM_NAME='Family Linux Debian Test' ./scripts/build-virtualbox-vm.sh
# -> dist/family-linux-debian-stable-arm64.ova   (import: File > Import Appliance)
```

The appliance contains the parent password you build it with, so use your own and do not share an appliance built with a password other people know.

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
| `ctl <args>` | Runs the `family-ctl` parent CLI (`status`, `user`, `app`, `time`, `web`, `audit`, `backup`, `verify`) |
| `policyd [--one-shot]` | Runs the screen-time and curfew enforcement daemon |
| `verify` | Checks the baseline (see below) |
| `test` | Runs the pytest suite |
| `preseed FILE` | Writes the Debian Installer preseed (and `late-command.sh` beside it); needs `PARENT_PASS` in the environment |

### What `verify` checks

Policy checks run everywhere. Live checks run only on Linux and read the real system:

- parent sudoers drop-in present and valid (`visudo -cf`)
- UFW active with deny incoming
- Firefox ESR, Chromium, Brave, Google Chrome and Microsoft Edge managed policy files present
- the web filter service (`family-dnsd`) and the screen-time service (`family-policyd`) running, and the children's nftables rules loaded with a rule for every child account
- AppArmor child profile loaded in enforce mode (asked of the kernel)
- unattended security upgrades enabled
- parent password rules enforced by PAM on password changes
- Alt+F2 run dialog and shell access locked for children (Plasma kiosk restrictions and the SDDM PAM rules: the kiosk, the sign-in re-lock and the sign-in hours check)
- each child's sign-in startup files locked (root-owned and immutable)
- software changes by children need the parent's password (polkit rule), and Flatpak and Snap are removed and pinned
- the installer finished every step (only on systems installed from the ISO)
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
- Family Controls, the parent's KDE app (PyQt6): children, screen time, websites, apps, website requests, add child
- Audit log with weekly rotation
- Screen-time tracker, the `family-policyd` service (installed and started by the apply) and the sign-in hours check
- Generators for firewall (UFW), per-child DNS gateway, Firefox ESR and Chromium policies, the AppArmor profile, desktop app filters, PackageKit install gate, and the Plasma kiosk lockdown
- Debian preseed and late-command generator (KDE Plasma, Debian repositories, accounts, payload, network, updates)

Status of the Debian base (see [DEV_HIST.md](DEV_HIST.md) for the checks and the open items):

- An unattended install of Debian 13.7.0 with KDE Plasma (arm64 ISO, VirtualBox 7.2.20 on Apple silicon) completed. The first boot applied the policy with no warnings and the machine reached its login prompt.
- Session 28: the web filter works with any browser, because it is network-level. Google Chrome (the most used browser) was installed and checked as a child: it opens confined, allowed and ECH sites load, blocked sites do not, and `chrome://policy` shows every managed setting. See `docs/web-filtering-guide.md`.
- Session 30: the fixes from the full review (DEV_HIST Session 30). Checked on a fresh arm64 install in VirtualBox: `family-ctl verify` passes every check; the screen-time service runs and signed a child out at bedtime within a minute; GRUB starts without a password and keeps `grub.cfg` private; `/opt/family-linux` holds only the program; the confined profile refuses `python3`, `perl` and `systemd-run`; the new start-up paths are immutable and the sign-in re-lock runs before the session. A second install checked the sign-in hours check (a child's sign-in at bedtime was refused) and the sign-out at a daily limit, which now brings back the sign-in screen instead of leaving it black. Still to check in a VM: DEV_HIST open item 32.
- Session 29: browsers from Debian's repositories. Chromium and Falkon work for a child after two profile fixes. GNOME Web (Epiphany) and other WebKit browsers do not start for a child; they fail closed. Chrome, Chromium and Firefox now have their proxy setting locked, and Firefox's `about:policies` shows the managed settings. Known limit, by decision: Falkon and Konqueror cannot be managed, so a child could set them to use a proxy that skips the filter. The parent guide has a disclaimer for them (DEV_HIST open item 28).
- Session 27 (UAT): Family Controls failed to load (missing `pkexec`), and children's Firefox failed to start (the child AppArmor profile) and then could not load sites (lookups went around the web filter through nss-resolve). All three are fixed and were checked in a VM; see DEV_HIST.
- Checked on the installed desktop (VirtualBox, arm64): the child is listed on the SDDM login screen and signs in to Plasma; the Family wallpaper appears at first login; Alt+F2 and Ctrl+Alt+T do nothing for the child while the parent's Ctrl+Alt+T opens Konsole; a child's package install is refused without authentication; `family-ctl verify` passes.
- Not yet checked: Discover's password prompt in the child's desktop, and whether the pinned System Settings launcher on the child's panel still opens. See DEV_HIST open items.
- VirtualBox on Apple silicon needs the VMSVGA graphics adapter (the appliance build sets it). With `qemuramfb` the desktop stays black.
- The amd64 ISO builds and passes its checks, but has not been installed.
- The ISOs in `dist/` were built on 2026-11-01, before Sessions 29 and 30, so they have none of those fixes (no screen-time service, among others). Rebuild them with your own passwords before use. There is no appliance in `dist/`.

Not yet implemented, or not validated:

- Installation to real hardware.
- amd64 install: the ISO is built and checked in CI. A full install of the automated amd64 ISO passed in the `Debian install` workflow (QEMU) on PR #8. No interactive amd64 install has been done.
- Anything that depends on the child's desktop session is only as tested as the VirtualBox run says.
- Terminal shortcut (Ctrl+Alt+T) for child accounts is expected to be blocked by hiding Konsole; not yet confirmed.
- CI: the `debian` job runs the tests and checks the package list in a Debian 13 container. The other Linux jobs run on Ubuntu runners.

Repository status (checked with `gh` on 2026-11-09):

- Default branch: `main`. It includes PR #7 (`debian-kde`, the Debian rebuild from Session 25) and PR #8 (`debian-kde`, merged as `cdd2ef7`: interactive ISO, appliance fixes, Sessions 26 to 28). CI passed on that merge. CI runs on pushes to `main` and on pull requests into `main`.
- Working branch: `debian-kde`. Its commits that are not on `main` are the Session 29 browser changes (`33e9caa`), two status updates, the Session 30 review fixes (`69e8128`), two CI fixes (`f144eea`, `577041d`; see DEV_HIST) and this status update. They are in pull request [#9](https://github.com/lukecarnold-jpg/family-linux/pull/9) into `main` (open). On `577041d` every CI job passed (run 42562966646), including the live apply and verify with the new checks, and the `Debian install` workflow (QEMU install of the amd64 ISO) passed (run 42562966655).

Design documents:

- `/docs/vision.md`
- `/docs/architecture.md`
- `/docs/installer.md`
- `/docs/roadmap.md`

## License

MIT. See [LICENSE](LICENSE).

## Privacy

This repository remains private until design and prototype quality are ready for a public release.
