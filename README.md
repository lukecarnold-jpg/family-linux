# Family Linux

Family Linux is a private design-stage project for a child-safe Linux experience that parents can manage simply.

The project direction is now fixed to:

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

## Repository layout

- `/docs` - design and architecture documents
- `/config` - policy templates and defaults
- `/scripts` - prototype/bootstrap scripts
- `/src` - future implementation code

## Current status

This repository documents product and technical direction. It does **not** yet provide a production installer or complete policy enforcement implementation.

Key documents:

- `/docs/vision.md`
- `/docs/architecture.md`
- `/docs/installer.md`
- `/docs/roadmap.md`

## Privacy

This repository remains private until design and prototype quality are ready for a public release.
