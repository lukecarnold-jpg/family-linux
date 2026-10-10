#!/usr/bin/env bash
set -euo pipefail

# Family Linux Bootstrap & Launcher Script
# Provides a unified launcher for installation, policy management, parent dashboard, and verification.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=============================================================="
echo "                   FAMILY LINUX SYSTEM"
echo "  Ubuntu LTS child-safe workstation with parent administration"
echo "=============================================================="

# Ensure Python is available
if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is required to run Family Linux."
    exit 1
fi

export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH:-}"

show_help() {
    cat <<EOF
Usage: ./scripts/bootstrap-prototype.sh [COMMAND] [OPTIONS]

Commands:
  install           Launch the interactive 12-step Family Linux installer
  install --dry-run Run installer in simulation mode (no system changes)
  dashboard         Launch the local Parent Web Control Dashboard (http://127.0.0.1:8443)
  ctl [args...]     Run the 'family-ctl' parent administration CLI
  policyd           Run the screen time and curfew policy enforcement daemon
  policyd --one-shot Run a single curfew enforcement cycle
  verify            Verify system compliance against Family Linux security baseline
  test              Run the automated test suite with pytest
  autoinstall FILE  Export Ubuntu Subiquity autoinstall user-data (needs PARENT_PASS env var)

Examples:
  ./scripts/bootstrap-prototype.sh install --dry-run
  ./scripts/bootstrap-prototype.sh ctl status
  ./scripts/bootstrap-prototype.sh dashboard
  ./scripts/bootstrap-prototype.sh verify
  ./scripts/bootstrap-prototype.sh test
EOF
}

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    install)
        python3 -m family_linux.installer.wizard "$@"
        ;;
    dashboard)
        python3 -m family_linux.parent_ui.server "$@"
        ;;
    ctl)
        python3 -m family_linux.cli.family_ctl "$@"
        ;;
    policyd)
        python3 -m family_linux.screentime.daemon "$@"
        ;;
    verify)
        python3 -m family_linux.cli.family_ctl verify "$@"
        ;;
    test)
        python3 -m pytest "${PROJECT_ROOT}/tests" -v "$@"
        ;;
    autoinstall)
        OUT_FILE="${1:-autoinstall-user-data.yaml}"
        : "${PARENT_PASS:?Set PARENT_PASS to the parent password (min 14 characters, with upper-case, lower-case, a number and a special character)}"
        python3 -m family_linux.installer.wizard --non-interactive --export-autoinstall "$OUT_FILE" \
            --parent-pass "$PARENT_PASS"
        echo "Ubuntu Subiquity autoinstall user-data generated at: $OUT_FILE"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
