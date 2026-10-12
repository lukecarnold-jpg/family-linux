#!/usr/bin/env bash
set -euo pipefail

# Family Linux ISO builder.
#
# Repacks an official Ubuntu 24.04 LTS live-server ISO with:
#   - an autoinstall configuration (accounts, base packages, the Family Linux payload)
#   - the Family Linux source and policy (no passwords), installed by a first-boot unit
#   - kernel arguments that start the autoinstall without a prompt
#
# Architecture: arm64 on Apple silicon and other ARM hosts (for example VirtualBox 7.2 on an M-series
# Mac), amd64 elsewhere. Override with ARCH=arm64 or ARCH=amd64.
#
# Optional: CHILD_SPECS='kid:Kid:pre_teen:child-password' (one child per line).
# Optional: TIMEZONE='Australia/Sydney' (default: this computer's time zone). Curfews use local time.
# Requires: xorriso (brew install xorriso | apt install xorriso), curl, rsync, PARENT_PASS, and a
# Python with PyYAML (PYTHON=/path/to/python to choose one; default python3).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
OUTPUT_DIR="${PROJECT_ROOT}/dist"
UBUNTU_RELEASE="${UBUNTU_RELEASE:-24.04.5}"

case "$(uname -m)" in
    arm64|aarch64) DEFAULT_ARCH=arm64 ;;
    *)             DEFAULT_ARCH=amd64 ;;
esac
ARCH="${ARCH:-$DEFAULT_ARCH}"
case "$ARCH" in
    arm64|amd64) ;;
    *) echo "ARCH must be arm64 or amd64 (got '$ARCH')" >&2; exit 2 ;;
esac

PYTHON="${PYTHON:-python3}"
for tool in xorriso curl rsync; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
"$PYTHON" -c "import yaml" 2>/dev/null || { echo "$PYTHON needs PyYAML: $PYTHON -m pip install pyyaml (or set PYTHON)" >&2; exit 2; }
: "${PARENT_PASS:?Set PARENT_PASS to the parent password (min 14 characters, with upper-case, lower-case, a number and a special character)}"

ISO_NAME="ubuntu-${UBUNTU_RELEASE}-live-server-${ARCH}.iso"
# arm64 images are on cdimage.ubuntu.com; amd64 images are on releases.ubuntu.com.
if [ "$ARCH" = arm64 ]; then
    UBUNTU_BASE_URL="https://cdimage.ubuntu.com/releases/24.04/release"
else
    UBUNTU_BASE_URL="https://releases.ubuntu.com/24.04"
fi
ISO_SRC="${BUILD_DIR}/${ISO_NAME}"
PAYLOAD="${BUILD_DIR}/payload"
OUT_ISO="${OUTPUT_DIR}/family-linux-ubuntu-24.04-${ARCH}.iso"

echo "=== Family Linux ISO builder (${ARCH}, Ubuntu ${UBUNTU_RELEASE}) ==="
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# 1. The official image, checked against Ubuntu's SHA256SUMS
if [ ! -f "$ISO_SRC" ] || [ -f "${ISO_SRC}.partial" ]; then
    echo "Downloading ${ISO_NAME}..."
    curl -fL --retry 3 -C - -o "${ISO_SRC}.partial" "${UBUNTU_BASE_URL}/${ISO_NAME}"
    mv "${ISO_SRC}.partial" "$ISO_SRC"
fi
curl -fsL -o "${BUILD_DIR}/SHA256SUMS" "${UBUNTU_BASE_URL}/SHA256SUMS"
expected="$(grep " \*${ISO_NAME}\$" "${BUILD_DIR}/SHA256SUMS" | awk '{print $1}')"
[ -n "$expected" ] || { echo "No checksum for ${ISO_NAME} in SHA256SUMS" >&2; exit 1; }
if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$ISO_SRC" | awk '{print $1}')"
else
    actual="$(shasum -a 256 "$ISO_SRC" | awk '{print $1}')"
fi
[ "$actual" = "$expected" ] || { echo "Checksum mismatch for ${ISO_SRC}; delete it and rerun." >&2; exit 1; }
echo "Checksum OK."

# 2. Payload: autoinstall user-data, policy without passwords, and the Family Linux source
rm -rf "$PAYLOAD" "${BUILD_DIR}/export"
mkdir -p "$PAYLOAD/nocloud" "$PAYLOAD/family-linux" "${BUILD_DIR}/export"
# Optional child accounts: CHILD_SPECS holds one "username:Full Name:tier:password" per line.
CHILD_ARGS=()
if [ -n "${CHILD_SPECS:-}" ]; then
    while IFS= read -r spec; do
        [ -n "$spec" ] && CHILD_ARGS+=(--child "$spec")
    done <<< "$CHILD_SPECS"
fi
PYTHONPATH="${PROJECT_ROOT}/src" "$PYTHON" -m family_linux.installer.wizard \
    --non-interactive \
    --parent-user "parent" \
    --parent-name "Family Administrator" \
    --parent-pass "$PARENT_PASS" \
    ${CHILD_ARGS[@]+"${CHILD_ARGS[@]}"} \
    ${TIMEZONE:+--timezone "$TIMEZONE"} \
    --export-autoinstall "$PAYLOAD/nocloud/user-data" \
    --export-policy "${BUILD_DIR}/export/policy.yaml"
: > "$PAYLOAD/nocloud/meta-data"
cp "${BUILD_DIR}/export/policy.yaml" "$PAYLOAD/family-linux/policy.yaml"
cp "${PROJECT_ROOT}/config/systemd/family-linux-firstboot.service" "$PAYLOAD/family-linux/"
cp "${PROJECT_ROOT}/config/bin/family-ctl" "$PAYLOAD/family-linux/family-ctl"
rsync -a --exclude '__pycache__' --exclude '*.egg-info' "${PROJECT_ROOT}/src/" "$PAYLOAD/family-linux/src/"

# 3. Boot menu: start the autoinstall from the ISO's nocloud directory without a prompt
xorriso -osirrox on -indev "$ISO_SRC" -extract /boot/grub/grub.cfg "${BUILD_DIR}/grub.cfg" >/dev/null 2>&1
chmod u+w "${BUILD_DIR}/grub.cfg"  # ISO files are read-only
"$PYTHON" - "${BUILD_DIR}/grub.cfg" "$ARCH" <<'PY'
import sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
changed = 0
ARCH = sys.argv[2]
for index, line in enumerate(lines):
    if line.lstrip().startswith("linux") and "---" in line:
        # Before "---": for the installer only.
        lines[index] = line.replace("---", "autoinstall ds=nocloud\\;s=/cdrom/nocloud/ ---", 1)
        # After "---": also copied to the installed system. The serial console is last, so it is
        # /dev/console and headless builds (QEMU, VirtualBox) can see the first-boot result.
        lines[index] += " console=ttyAMA0" if ARCH == "arm64" else " console=ttyS0"
        changed += 1
if changed == 0:
    sys.exit("No kernel command lines found in grub.cfg; the ISO layout is not what this script expects.")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print(f"Autoinstall added to {changed} boot entr{'y' if changed == 1 else 'ies'}.")
PY

# 4. Repack, keeping the original boot records (works for arm64 and amd64)
rm -f "$OUT_ISO"
xorriso -indev "$ISO_SRC" -outdev "$OUT_ISO" -boot_image any replay \
    -volid "FAMILYLINUX" \
    -map "${BUILD_DIR}/grub.cfg" /boot/grub/grub.cfg \
    -map "$PAYLOAD/nocloud" /nocloud \
    -map "$PAYLOAD/family-linux" /family-linux >/dev/null 2>&1

# 5. Check the result
xorriso -indev "$OUT_ISO" -osirrox on -extract /nocloud/user-data "${BUILD_DIR}/check-user-data" >/dev/null 2>&1
grep -q "autoinstall:" "${BUILD_DIR}/check-user-data" || { echo "user-data missing from ISO" >&2; exit 1; }
xorriso -indev "$OUT_ISO" -osirrox on -extract /boot/grub/grub.cfg "${BUILD_DIR}/check-grub.cfg" >/dev/null 2>&1
grep -q "ds=nocloud" "${BUILD_DIR}/check-grub.cfg" || { echo "autoinstall boot argument missing from ISO" >&2; exit 1; }
rm -f "${BUILD_DIR}/check-user-data" "${BUILD_DIR}/check-grub.cfg"

echo "Built: ${OUT_ISO}"
echo "Size: $(du -h "$OUT_ISO" | awk '{print $1}')"
echo "Boot the ISO in a VM for ${ARCH}. The install runs unattended; the first boot applies the Family Linux policy."
