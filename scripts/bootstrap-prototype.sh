#!/usr/bin/env bash
set -eu

# Family Linux bootstrap prototype
# This script is intentionally a prototype placeholder.
# It does not implement a production installer or full policy enforcement.

echo "Family Linux bootstrap prototype: no destructive actions are performed."
echo "Planned Ubuntu-aligned actions:"
echo "  - prepare an Ubuntu LTS-based minimal system profile"
echo "  - configure Ubuntu-standard security defaults (users/groups, sudo, firewall, signed repos, updates)"
echo "  - create one parent local-admin account model and multiple child non-admin account model"
echo "  - drive an interactive installer flow with recommended defaults and optional advanced mode"
echo "  - validate configuration and show a final summary before apply"

echo "This prototype will be replaced by production-grade installer/build tooling in later phases."
