# Family Linux Architecture

## Overview

Family Linux uses a layered architecture:

1. Debian stable base system with KDE Plasma
2. Debian-aligned security and policy controls
3. Child-safe desktop/session layer
4. Parent management layer
5. Audit and recovery layer

## Layer 1: Debian stable base system

The project baseline is Debian stable: Debian 13 (trixie), with full security support until August 2028 and LTS support until June 2030 (debian.org release information). Packages come from the Debian repositories (main, contrib and non-free-firmware) through apt; Flatpak and Snap are not used.

Design intent:

- minimal package footprint
- only required services enabled by default
- reproducible image/build approach over ad hoc customization

## Layer 2: Security and policy controls

Security controls align with Debian capabilities:

- normal Unix users/groups and strict file permissions
- `sudo` reserved for the parent administrator account
- AppArmor profiles where applicable
- firewall configuration with conservative defaults
- package trust via signed repositories and controlled sources
- regular security update workflow

Family Linux should not claim a custom OpenBSD-style security framework; OpenBSD principles are guidance for secure defaults and discipline.

## Layer 3: Child-safe desktop/session

Child sessions should provide:

- launcher-focused interface with approved apps
- no default terminal/shell workflow for children
- no child access to package management or system settings
- browser configuration constrained by parent policy

## Layer 4: Parent management

Initial scope defines one parent account managing multiple child accounts.

Parent capabilities:

- create, update, disable, and recover child accounts
- approve or deny applications
- configure time and browsing restrictions
- review audit events and maintenance status

## Layer 5: Audit and recovery

The system should capture policy-relevant events and support safe recovery workflows:

- account and policy changes
- blocked actions and policy denials
- update and maintenance actions
- rollback/recovery checkpoints where feasible

## Data and identity model

- one parent identity record mapped to one local administrator account
- zero or more child identity records mapped to standard non-admin local accounts
- each child has isolated home data by default
- policy and logs are centrally stored with admin-only write access

## Policy model

- parent scope: account management, app approval, network/browsing policy, schedule policy
- child scope: runtime restrictions and approved resources
- global scope: update policy, logging retention, firewall baseline, repository trust policy

## Risks and constraints

- accidental privilege escalation via misconfigured admin rights
- overpromising controls not yet implemented in prototype stage
- policy drift after updates if validation is weak
- insufficient setup validation in installer flow
