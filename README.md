# Family Linux

Family Linux is a private, prototype-stage project for a child-safe Ubuntu LTS desktop that one parent can manage without expert Linux knowledge.

The repository now holds a working Python prototype: an installer flow, a parent CLI, a local parent web dashboard, a screen-time enforcement daemon, and generators for browser, firewall, DNS, and AppArmor policy. It configures a running Ubuntu system. It does not yet install Ubuntu or build a bootable ISO, and enforcement has not been validated on a real Ubuntu machine.

- Repository layout: [STRUCTURE.md](STRUCTURE.md)
- Development history and known issues: [DEV_HIST.md](DEV_HIST.md)

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

## Quick start

Requires Python 3.9 or newer.

```bash
python3 -m pip install -e ".[dev]"    # installs pyyaml, pytest, pytest-cov
./scripts/bootstrap-prototype.sh test # run the test suite (31 tests)
./scripts/bootstrap-prototype.sh install --dry-run
./scripts/bootstrap-prototype.sh ctl status
./scripts/bootstrap-prototype.sh dashboard   # http://127.0.0.1:8443
```

Outside Linux every system change is simulated, so the commands above are safe to run on a development machine. On Linux, `install` without `--dry-run` applies changes to the system after you confirm the summary. Use `--dry-run` first.

### Commands

| Command | What it does |
|---------|--------------|
| `install [--dry-run]` | Runs the 12-step interactive installer |
| `dashboard [port]` | Starts the parent web dashboard on `127.0.0.1` (default port 8443) |
| `ctl <args>` | Runs the `family-ctl` parent CLI (`status`, `user`, `app`, `time`, `web`, `audit`, `backup`, `verify`) |
| `policyd [--one-shot]` | Runs the screen-time and curfew enforcement daemon |
| `verify` | Runs the baseline check (see known issues in DEV_HIST.md before relying on it) |
| `test` | Runs the pytest suite |
| `autoinstall FILE` | Writes an Ubuntu Subiquity autoinstall `user-data` file |

## Repository layout

- `/docs`: design and architecture documents
- `/config`: policy templates, browser policy templates, and systemd units
- `/scripts`: bootstrap launcher and ISO helper
- `/src/family_linux`: Python implementation
- `/tests`: pytest suite

## Current status

Implemented (prototype level):

- Policy model with validation, saved with backups to a single YAML file
- Parent CLI for child accounts, app approvals, screen-time limits, web block and allow lists, audit log, and backups
- Parent web dashboard (JSON API and single page)
- Screen-time tracker and enforcement daemon
- Generators for firewall (UFW), DNS filtering, Firefox and Chromium policies, AppArmor profile, and desktop app filters
- Ubuntu autoinstall `user-data` generator

Not yet implemented, or not validated:

- Installation to disk. The installer does not partition or install Ubuntu.
- A bootable ISO. `scripts/build-autoinstall-iso.sh` prints manual steps.
- Validation on a real Ubuntu LTS system. No Linux test run has been done.
- Authentication on the parent dashboard, which currently has none.
- Hardened defaults. Passwords are stored in plaintext and the installer offers hardcoded defaults.

The full list of issues, with file references and suggested fixes, is in [DEV_HIST.md](DEV_HIST.md#review-findings).

Design documents:

- `/docs/vision.md`
- `/docs/architecture.md`
- `/docs/installer.md`
- `/docs/roadmap.md`

## License

Declared as MIT in `pyproject.toml`. A `LICENSE` file has not been added yet.

## Privacy

This repository remains private until design and prototype quality are ready for a public release.
