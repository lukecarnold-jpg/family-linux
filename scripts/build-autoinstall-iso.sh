#!/usr/bin/env bash
set -euo pipefail

# Family Linux ISO Builder Script
# Packages an official Ubuntu LTS ISO with Family Linux autoinstall configuration.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
OUTPUT_DIR="${PROJECT_ROOT}/dist"

echo "=== Family Linux Ubuntu LTS ISO Builder ==="

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

USER_DATA_FILE="${BUILD_DIR}/user-data"
echo "Generating Family Linux autoinstall configuration..."
: "${PARENT_PASS:?Set PARENT_PASS to the parent password (min 14 characters, with upper-case, lower-case, a number and a special character)}"
PYTHONPATH="${PROJECT_ROOT}/src" python3 -m family_linux.installer.wizard \
    --non-interactive \
    --parent-user "parent" \
    --parent-name "Family Administrator" \
    --parent-pass "$PARENT_PASS" \
    --export-autoinstall "$USER_DATA_FILE"

cat <<EOF

Autoinstall configuration successfully generated:
  -> ${USER_DATA_FILE}

To build a bootable Ubuntu 22.04 / 24.04 LTS Live ISO with Family Linux preconfigured:

1. Download Ubuntu 24.04 or 22.04 Live Server/Desktop ISO:
   wget https://releases.ubuntu.com/noble/ubuntu-24.04.1-live-server-amd64.iso

2. Extract and repack with autoinstall parameters:
   mkdir -p ${BUILD_DIR}/iso-extract
   xorriso -osirrox on -indev ubuntu-*.iso -extract / ${BUILD_DIR}/iso-extract

3. Place autoinstall files into extracted ISO:
   mkdir -p ${BUILD_DIR}/iso-extract/nocloud
   cp ${USER_DATA_FILE} ${BUILD_DIR}/iso-extract/nocloud/user-data
   touch ${BUILD_DIR}/iso-extract/nocloud/meta-data

4. Repack bootable ISO:
   xorriso -as mkisofs -r \\
     -V "FamilyLinux" \\
     -o "${OUTPUT_DIR}/family-linux-ubuntu-lts.iso" \\
     -J -l -b boot/grub/i386-pc/eltorito.img -c boot.catalog \\
     -no-emul-boot -boot-load-size 4 -boot-info-table \\
     -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot \\
     "${BUILD_DIR}/iso-extract"

Done! Generated autoinstall payload ready.
EOF
