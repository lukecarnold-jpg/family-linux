# Family Linux Architecture

## Overview

The Family Linux architecture will follow a simple layered model:

1. Hardened base OS
2. Security policy layer
3. Child-safe desktop environment
4. Parent management layer
5. Audit and recovery layer

## Layer 1: Hardened base OS

The base should be as small and predictable as possible. Preferred directions include:

- Debian with a minimal install profile
- Ubuntu LTS with reduced services and strong defaults
- Alpine or other musl-based minimal systems for compact deployment

The exact distribution should be chosen based on:

- security update cadence
- compatibility with the chosen desktop and policy tooling
- ease of long-term maintenance
- simplicity of creating a reproducible image

## Layer 2: Security policy layer

Family Linux should rely on policy-driven enforcement rather than relying on individual app management alone.

Examples:

- firewall defaults deny incoming network access unless required
- app allow-list enforced via user policy
- no `sudo` for child users
- restricted package sources
- mandatory file permissions and home-directory isolation

## Layer 3: Child-safe desktop environment

The default desktop should present a well-scoped interface:

- a large launcher with approved apps only
- no default terminal access for children
- no package managers in the child session
- no access to system settings or shell
- a parent-approved web browser with browsing restrictions

Optional features:

- screen-time limits
- reward/learning mode
- educational tools grouped by category

## Layer 4: Parent management layer

A parent manages the system through a dedicated panel or management interface that supports:

- child account creation and deletion
- permission and time restrictions
- app approval workflow
- block list and safe site lists
- simple updates and maintenance options

This layer should be visible only to trusted family admins, not hidden in the main child experience.

## Layer 5: Audit and recovery

Every action that changes policy or attempts a restricted action should be logged.

This should include:

- account changes
- app approvals or denials
- time-limit enforcement
- blocked browsing or app launches
- system update attempts
- recovery events

Recovery should be simple:

- one-click restore of a child account
- known-good baseline profile support
- rollback path for policy changes

## Security model

The operating system should favor explicit controls over flexibility for children:

- child user cannot install software
- browser is hardened or sandboxed
- no interactive root session for general use
- no default remote admin services
- family admin account is separate from child sessions

## Data and identity model

- child users have isolated home directories
- data is not shared by default across profiles
- policy and logs are stored centrally and protected
- maintenance operations should require confirmation

## Risks to design around

- accidental local privilege escalation
- malicious or unsafe browser activity
- unsanctioned package installs
- open network services on child devices
- poor default security after a system update

## Recommended implementation pattern

The early implementation should focus on a minimal family-safe system built on top of a hardened base distribution, not on a full custom kernel or custom package ecosystem. This keeps maintenance realistic while preserving the OpenBSD-inspired security posture.
