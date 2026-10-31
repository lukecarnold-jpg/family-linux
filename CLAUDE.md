# Family Linux: working notes for Claude

Family Linux is a Debian stable (13, trixie) build with KDE Plasma for a family: one parent administrator and restricted child accounts. See [README.md](README.md) for what it does and [STRUCTURE.md](STRUCTURE.md) for where things live.

## Documentation is part of every change

Update these three files in the same piece of work as any code, configuration, script, test or dependency change:

- **README.md**: the status sections (what is implemented, what is not yet validated), the GitHub repository status (default branch, open and merged pull requests, commits on the working branch that are not on `main`, CI scope), and any user-facing instructions that changed.
- **DEV_HIST.md**: a new session entry for the change. Record the request, the cause of any defect (with evidence), the fix, and how it was checked (test counts, VM checks, CI runs). Add to the open items when something is found but not fixed.
- **STRUCTURE.md**: any new, renamed or removed module, config file, script, test file, runtime path or documentation file.

Before writing the GitHub status, check it with `gh` (`gh pr list --state all`, `git log origin/main..origin/<branch>`, `gh run list`). It changes without notice.

Do not leave these files stale at the end of a task. If a change needs no update to one of them, say so in the reply.

## Commits and pull requests

- Commit and push only when asked.
- Pull requests target `main`. CI runs only on pushes to `main` and on pull requests into `main`, so work on other branches has no CI until a pull request is open.
- Commit messages end with the `Co-Authored-By` line of the model that wrote the change.

## Testing

- Run the suite with plain `pytest` from the repository root (`./scripts/bootstrap-prototype.sh test` also works). CI runs plain `pytest`, so a test that passes only under `python -m pytest` is a bug.
- Shared fixtures go in `tests/conftest.py`. Do not import from one test module into another.
- VM checks: use the VirtualBox VM only for the behaviour the unit tests cannot reach (installed system, login, desktop, network). Remove any VM created for a test as soon as the test is finished. Never remove or power off a VM that was not created in the current session.

## Review

- Opus 5.5 at medium effort (`claude-opus-5-5`) is used to review changes and to provide improvements and fixes.
- Present the review as a priority list, most important first, with each item's fix.

## Builds and secrets

- `dist/` and `build/` are git-ignored. The built ISOs and appliances contain the passwords used to build them. Do not share them, and do not commit them.
- Build passwords come from the environment (`PARENT_PASS`, `CHILD_SPECS`). Do not write them into files in the repository.
- Each ISO build downloads the Debian netinst image and checks it against `SHA512SUMS` (the file name is read from that list, because it changes with each point release). If Debian moves its images, update `scripts/build-debian-iso.sh`, or set `DEBIAN_BASE_URL`.

## Style

- Match the code around the change: comment density, naming and idiom.
- Keep documentation plain. Parent-facing text (for example `docs/web-filtering-guide.md`) is written for people with no IT background.
