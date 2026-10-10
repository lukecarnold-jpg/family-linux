# Family Linux Installer Design

## Scope and status

This document defines the interactive installer design for Family Linux. It is a design-stage specification, not a production installer implementation.

## Installer model

The installer provides two paths:

1. **Recommended mode (default):** guided setup with safe defaults and minimal required decisions.
2. **Advanced mode (optional):** exposes additional configuration for power users while preserving validation and safety checks.

## Core flow

1. Welcome and language selection
2. Keyboard layout selection
3. Network setup/check
4. Disk and installation target choices
5. Create **one parent account** (required; local administrator)
6. Create **zero or more child accounts** (standard non-admin users)
7. Apply recommended safety defaults
8. Optional advanced settings (if selected)
9. Validation pass for all selected settings
10. Review and confirmation summary
11. Installation and configuration apply
12. First-boot setup and verification hints

## Recommended mode behavior

Recommended mode should:

- preselect conservative defaults
- minimize required inputs
- enforce one parent account creation
- allow child account creation during setup or defer to first boot
- keep advanced options hidden unless explicitly requested
- block progress when required values fail validation

## Advanced mode behavior

Advanced mode may expose:

- deeper partitioning/layout options
- network/firewall configuration details
- optional service toggles within safe constraints
- policy tuning options beyond defaults

Advanced mode must still:

- preserve the one-parent-account requirement in initial scope
- keep child accounts non-admin by default
- run validation before applying changes
- show a complete pre-apply summary

## Validation requirements

Before apply, the installer should validate:

- parent account exists and is configured as local admin
- child accounts are non-admin users
- account names/password rules pass policy checks
- selected disk actions are coherent and non-contradictory
- required network/install prerequisites are met

## Summary and confirmation

A final summary page should clearly display:

- selected language/keyboard/network state
- disk/install targets
- parent account and child account plan
- safety defaults and any advanced deviations

No installation changes should be applied until explicit user confirmation.

## First-boot setup

First boot should provide:

- confirmation that accounts were created as intended
- quick links for parent policy setup and child account review
- clear indication this remains a prototype workflow in early project phases
