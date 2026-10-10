# Family Linux

A private, child-safe Linux distribution inspired by OpenBSD principles: secure defaults, simple administration, strong isolation, and a parent-managed workflow.

This repository is intentionally private while the project is in its early design and validation phase. It captures the architecture, governance model, and planned build steps for a distro designed for:

- children using a simple, safe desktop environment
- parents managing accounts, app access, and screen time
- admin operators maintaining a hardened, minimal OS
- schools or homes that need predictable and secure defaults

## Goals

- Install a minimal, hardened Linux base with OpenBSD-style discipline
- Remove unnecessary services and privilege escalations by default
- Create a child-safe desktop with a locked-down launcher and restricted software
- Give parents a simple dashboard to manage accounts, apps, and browsing policy
- Keep the system predictable, readable, and easy to audit

## Core design principles

1. Secure by default
   - no remote services enabled by default
   - immutable or read-only critical system paths where practical
   - least-privilege account model
   - mandatory application allow-lists

2. Simple for children
   - single-user child experience with a large, obvious interface
   - brightly colored, high-contrast launcher
   - limited desktop apps and no shell access by default

3. Manageable by parents
   - separate admin and child roles
   - time limits, app access, and network policy controls
   - clear logs of actions and attempts

4. OpenBSD-inspired discipline
   - minimal attack surface
   - explicit package policy and review
   - conservative defaults and strong defaults over convenience

## Repository layout

- `docs/` — architecture and policy documents
- `config/` — default settings and policy templates
- `scripts/` — provisioning and system bootstrap utilities
- `src/` — future build and packaging logic

## Status

This repository currently establishes the foundation for the project and documents the design direction. The next steps are to define the exact build system, package policy, and testable child-safe defaults.

## Planned direction

- create a hardened Debian/Ubuntu or Alpine-based minimal base, with OpenBSD-inspired hardening applied
- package a kiosk-like desktop plus parent dashboard
- enforce strict filesystem and network policy
- provide parent-facing controls with audit logs and recovery flows

## Notes

This repo remains private until the core design, controls, and safety model are ready for public release.
