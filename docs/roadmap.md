# Family Linux Roadmap

## Phase 0: Direction lock

- confirm Debian stable with KDE Plasma as the base distribution and its support policy
- confirm Debian-standard security model language
- confirm one-parent/multi-child account model
- keep repository private during design validation

## Phase 1: Baseline architecture

- finalize Debian-focused architecture and policy boundaries
- define child-safe desktop baseline and app approval model
- define parent management requirements and audit requirements
- document installer requirements with recommended and advanced modes

## Phase 2: Installer and policy prototype

- prototype interactive installer flow (design/prototype stage)
- implement safe validation and final summary before apply
- model parent account creation and optional child creation during setup
- define first-pass policy schema and defaults

## Phase 3: System prototype

- produce first Debian-based prototype image/build process
- validate parent and child account flows on first boot
- validate baseline safety defaults and rollback/recovery paths
- evaluate operational maintenance workflow

## Phase 4: Hardening and reliability

- tighten service footprint and firewall defaults
- improve AppArmor/profile coverage where applicable
- harden update and package source governance
- expand audit visibility and incident recovery drills

## Phase 5: Release readiness

- finalize install and support documentation
- complete usability and safety validation
- prepare public release materials and governance notes
- transition repository visibility when project is ready

## Milestones

- architecture direction: complete
- installer design document: complete
- interactive installer prototype (12-step flow): complete
- policy schema and management engine: complete
- parental administration CLI (`family-ctl`): complete
- parental web control dashboard: complete
- screen time and curfew daemon (`family-policyd`): complete
- Debian preseed and late-command install workflow (KDE Plasma): complete, in VirtualBox on arm64; hardware and amd64 not yet validated
- automated test suite (pytest): complete (see DEV_HIST for the current count)
- ISO build tooling: prototype complete
- production-quality hardware validation: ongoing
