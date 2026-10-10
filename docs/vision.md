# Family Linux Design Vision

## Mission

Family Linux is an Ubuntu-based operating system concept designed for children to use safely and for one parent administrator to manage without expert Linux knowledge.

## Product concept

The default experience should provide:

- simple child sessions with approved apps
- clear limits on risky actions and unsafe content paths
- parent-managed controls for accounts, time, apps, and browsing policy
- guided setup with safe defaults and optional advanced configuration

## User model

### Parent account (single account in initial scope)

- created during installation
- local administrator with `sudo` access
- manages child account lifecycle and policy
- reviews logs and performs maintenance tasks

### Child accounts (zero or more)

- standard non-admin Ubuntu users
- no `sudo` rights
- restricted from package installation and core system configuration
- limited to approved apps and policy-controlled browsing/session rules

### Future scope

Support for more than one parent-level administrator may be considered later, but initial scope is one parent account.

## Security model direction

Family Linux uses Ubuntu's standard security model:

- Unix users/groups and file permissions for separation
- `sudo` for the parent administrator
- AppArmor where applicable for confinement
- host firewall configuration (for example via UFW/nftables policy)
- signed packages and controlled repository sources
- regular security updates

OpenBSD remains an influence for disciplined defaults, minimal running services, least privilege, and auditability.

## Policy goals

The policy model should define:

- allowed applications
- session/time limits
- browsing/network restrictions
- account lifecycle rules for parent and child users
- update/maintenance windows and recovery workflow

## Success criteria

A milestone is successful when a parent can:

- install with recommended defaults quickly
- create one parent account and multiple child accounts in setup
- manage child policy without command-line complexity
- recover safely from configuration mistakes

## Non-goals

- replacing Ubuntu with a custom base distribution
- claiming complete policy enforcement before implementation exists
- building a general unrestricted workstation experience by default
