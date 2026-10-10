# Family Linux Design Vision

## Mission

Family Linux is a Linux-based operating system created for children to use safely and for parents to manage without requiring expert technical knowledge. The system is intentionally opinionated and conservative, modeled after OpenBSD's commitment to secure defaults and minimal risk.

## Product concept

The default user experience should feel familiar and safe:

- a child can log in to a simple desktop or kiosk session
- all software is pre-approved and limited by policy
- internet access is limited or configured by parental rules
- forbidden actions are blocked, not merely warned about
- parents can manage the system through a guided panel or administration profile

## User model

### Child account

- no interactive shell access
- no package installation
- no ability to change system settings
- access only to approved apps and websites
- limited time and session windows

### Parent account

- can create and manage child accounts
- can approve or deny apps
- can define browsing or network rules
- can inspect access logs and configure time restrictions

### Administrator account

- reserved for trusted operators or advanced family tech setup
- used only for updates, secure maintenance, and policy review
- not used for everyday child access

## Threat model

The system should assume the following:

- child users are curious and may attempt to browse outside approved content
- many apps are not suitable for unsupervised use
- families need a system that avoids accidental system damage or unsafe internet exposure
- the OS should remain simple enough to troubleshoot even without advanced Linux expertise

## Design choices

- Minimal software footprint
- Locked-down network policy by default
- Role separation between parent, child, and admin
- Explicit allow-list for applications and websites
- Strong audit logging for access, changes, and policy events
- Recovery options that do not require deep system knowledge

## Policy goals

The system should be guided by a central policy engine that defines:

- allowed applications
- screen time and session limits
- internet access policy
- safe default keyboard and locale configuration
- account lifecycle policy
- upgrade and maintenance windows

## Implementation direction

The initial implementation should prefer a hardened base system such as Debian or Ubuntu with a minimal desktop, combined with OpenBSD-style hardening principles:

- no unnecessary daemons
- systemd services restricted to required features
- UFW or nftables firewall rules with default deny on untrusted interfaces
- secure package verification and limited repository sources
- mandatory user separation

## Success criteria

A release is considered viable when a parent can:

- set up a child-safe system in under 30 minutes
- assign child-safe accounts with no shell access
- approve app access without command-line complexity
- configure screen time and internet restrictions simply
- recover from a misconfiguration without reinstalling the OS

## Non-goals

- general-purpose developer workstation
- unlimited gaming platform
- broad unmanaged user freedom
- a system meant for advanced experimentation by default

## Initial milestone

The first milestone is a documented, testable policy and build plan. The next milestone is a minimal live system image that demonstrates the user flow and enforcement model.
