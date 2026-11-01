#!/usr/bin/env bash
set -euo pipefail

# Family Linux ISO builder: Debian stable with KDE Plasma.
#
# Repacks the official Debian netinst image (arm64 or amd64) with:
#   - a preseed: the unattended Debian install (KDE Plasma, the parent account, UEFI, the first disk)
#   - a late-command script and the Family Linux payload, run by the installer on the new system
#   - a boot menu entry that starts the preseed (the menu still waits for Enter, so the disk is
#     never wiped by accident)
#
# Modes (MODE):
#   interactive (default): the menu's Install and Graphical install entries open the Debian installer.
#       The preseed supplies the answers it covers (accounts, packages, disk, time zone), and the
#       installer shows the rest. The disk is still erased.
#   automated: Install starts unattended, with no questions. Used by build-virtualbox-vm.sh.
#
# The installer erases the disk it installs to. Boot the ISO only on a computer you mean to set up.
#
# Architecture: arm64 on Apple silicon and other ARM hosts (for example VirtualBox 7.2 on an M-series
# Mac), amd64 elsewhere. Override with ARCH=arm64 or ARCH=amd64.
#
# Optional: CHILD_SPECS='kid:Kid:pre_teen:child-password' (one child per line).
# Optional: TIMEZONE='Australia/Sydney' (default: UTC). Curfews use local time.
# Optional: TARGET_DISK=/dev/nvme0n1 (default: the first disk the installer finds).
# Optional: MODE=interactive (default) or MODE=automated.
# Optional: APPLIANCE=1 (set by build-virtualbox-vm.sh): the first boot powers off when it has finished.
# Optional: DEBIAN_BASE_URL (default https://cdimage.debian.org/debian-cd/current/<arch>/iso-cd).
# Requires: xorriso, curl, rsync, gpgv (brew install gnupg | apt install gpgv), PARENT_PASS, and a
# Python with PyYAML (PYTHON=... to choose one).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
OUTPUT_DIR="${PROJECT_ROOT}/dist"

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
for tool in xorriso curl rsync gpgv; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
"$PYTHON" -c "import yaml" 2>/dev/null || { echo "$PYTHON needs PyYAML: $PYTHON -m pip install pyyaml (or set PYTHON)" >&2; exit 2; }
: "${PARENT_PASS:?Set PARENT_PASS to the parent password (min 14 characters, with upper-case, lower-case, a number and a special character)}"

DEBIAN_BASE_URL="${DEBIAN_BASE_URL:-https://cdimage.debian.org/debian-cd/current/${ARCH}/iso-cd}"
PAYLOAD="${BUILD_DIR}/payload"
EXPORT="${BUILD_DIR}/export"
MODE="${MODE:-interactive}"
case "$MODE" in
    interactive) OUT_ISO="${OUTPUT_DIR}/family-linux-debian-stable-${ARCH}.iso" ;;
    automated)   OUT_ISO="${OUTPUT_DIR}/family-linux-debian-stable-${ARCH}-automated.iso" ;;
    *) echo "MODE must be interactive or automated (got '$MODE')" >&2; exit 2 ;;
esac

echo "=== Family Linux ISO builder (${ARCH}, Debian stable netinst) ==="
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

sha512_of() {
    if command -v sha512sum >/dev/null; then
        sha512sum "$1" | awk '{print $1}'
    else
        shasum -a 512 "$1" | awk '{print $1}'
    fi
}

# 1. The official netinst image. Debian publishes the current file name in SHA512SUMS, so the file
#    name is read from there (it changes with each point release). SHA512SUMS is checked against its
#    signature with Debian's CD signing keys, pinned in config/keys (fingerprints DF9B9C49...6294BE9B
#    and 10460DAD...64E6EA7D, as listed on https://www.debian.org/CD/verify), then the image against it.
KEYRING="${PROJECT_ROOT}/config/keys/debian-cd-signing.gpg"
curl -fsSL --retry 3 -o "${BUILD_DIR}/SHA512SUMS" "${DEBIAN_BASE_URL}/SHA512SUMS" || {
    echo "Could not download ${DEBIAN_BASE_URL}/SHA512SUMS. If Debian moved its images, set DEBIAN_BASE_URL." >&2
    exit 1
}
curl -fsSL --retry 3 -o "${BUILD_DIR}/SHA512SUMS.sign" "${DEBIAN_BASE_URL}/SHA512SUMS.sign" || {
    echo "Could not download ${DEBIAN_BASE_URL}/SHA512SUMS.sign" >&2
    exit 1
}
gpgv --keyring "$KEYRING" "${BUILD_DIR}/SHA512SUMS.sign" "${BUILD_DIR}/SHA512SUMS" 2>/dev/null || {
    echo "SHA512SUMS is not signed by a Debian CD signing key; not using it." >&2
    exit 1
}
echo "Signature OK (SHA512SUMS, Debian CD signing key)."
ISO_NAME="$(awk '{print $2}' "${BUILD_DIR}/SHA512SUMS" | sed 's/^\*//' | grep -E "^debian-[0-9.]+-${ARCH}-netinst\.iso$" | tail -n 1)"
[ -n "$ISO_NAME" ] || { echo "No ${ARCH} netinst image listed in SHA512SUMS" >&2; exit 1; }
ISO_SRC="${BUILD_DIR}/${ISO_NAME}"
expected="$(awk -v name="$ISO_NAME" '{ f=$2; sub(/^\*/, "", f); if (f == name) print $1 }' "${BUILD_DIR}/SHA512SUMS")"
if [ ! -f "$ISO_SRC" ] || [ -f "${ISO_SRC}.partial" ]; then
    echo "Downloading ${ISO_NAME}..."
    curl -fL --retry 3 -C - -o "${ISO_SRC}.partial" "${DEBIAN_BASE_URL}/${ISO_NAME}"
    mv "${ISO_SRC}.partial" "$ISO_SRC"
fi
[ "$(sha512_of "$ISO_SRC")" = "$expected" ] || { echo "Checksum mismatch for ${ISO_SRC}; delete it and rerun." >&2; exit 1; }
echo "Checksum OK (${ISO_NAME})."

# 2. Installer files (preseed and late-command script) and the policy, without passwords
rm -rf "$PAYLOAD" "$EXPORT"
mkdir -p "$PAYLOAD/family-linux" "$EXPORT"
CHILD_ARGS=()
if [ -n "${CHILD_SPECS:-}" ]; then
    while IFS= read -r spec; do
        [ -n "$spec" ] && CHILD_ARGS+=(--child "$spec")
    done <<< "$CHILD_SPECS"
fi
TARGET_ARGS=()
# Only the automated build erases the disk without the installer's confirmation screen.
if [ "$MODE" = automated ]; then
    TARGET_ARGS+=(--unattended-disk)
fi
# Appliance builds (build-virtualbox-vm.sh): the first boot powers off when done, for a clean export.
if [ "${APPLIANCE:-0}" = 1 ]; then
    TARGET_ARGS+=(--poweroff-after-firstboot)
fi
if [ -n "${TARGET_DISK:-}" ]; then
    TARGET_ARGS+=(--target-disk "$TARGET_DISK")
fi
PYTHONPATH="${PROJECT_ROOT}/src" "$PYTHON" -m family_linux.installer.wizard \
    --non-interactive \
    --parent-user "parent" \
    --parent-name "Family Administrator" \
    --parent-pass "$PARENT_PASS" \
    ${CHILD_ARGS[@]+"${CHILD_ARGS[@]}"} \
    ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} \
    ${TIMEZONE:+--timezone "$TIMEZONE"} \
    --export-preseed "$EXPORT/preseed.cfg" \
    --export-policy "$EXPORT/policy.yaml"
cp "$EXPORT/late-command.sh" "$PAYLOAD/family-linux/late-command.sh"
cp "$EXPORT/policy.yaml" "$PAYLOAD/family-linux/policy.yaml"
cp "${PROJECT_ROOT}/config/systemd/family-linux-firstboot.service" "$PAYLOAD/family-linux/"
cp "${PROJECT_ROOT}/config/bin/family-ctl" "$PAYLOAD/family-linux/family-ctl"
cp "${PROJECT_ROOT}/config/bin/family-linux-parent" "$PAYLOAD/family-linux/family-linux-parent"
cp "${PROJECT_ROOT}/config/bin/family-linux-set-wallpaper" "$PAYLOAD/family-linux/family-linux-set-wallpaper"
cp "${PROJECT_ROOT}/config/xdg/autostart/family-linux-wallpaper.desktop" "$PAYLOAD/family-linux/"
cp "${PROJECT_ROOT}/config/applications/org.familylinux.Parent.desktop" "$PAYLOAD/family-linux/"
cp "${PROJECT_ROOT}/config/polkit/org.familylinux.manage.policy" "$PAYLOAD/family-linux/"
rsync -a --exclude '__pycache__' --exclude '*.egg-info' "${PROJECT_ROOT}/src/" "$PAYLOAD/family-linux/src/"

# Optional desktop wallpaper: one PNG or JPEG in config/wallpaper/. Plasma has no system-wide
# default, so the image is copied to the installed system and applied at each account's first login.
WALLPAPERS=()
for f in "${PROJECT_ROOT}"/config/wallpaper/*; do
    case "$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')" in
        *.png|*.jpg|*.jpeg) WALLPAPERS+=("$f") ;;
    esac
done
if [ "${#WALLPAPERS[@]}" -gt 1 ]; then
    echo "config/wallpaper/ holds ${#WALLPAPERS[@]} images; keep one." >&2
    exit 2
elif [ "${#WALLPAPERS[@]}" -eq 1 ]; then
    ext="$(printf '%s' "${WALLPAPERS[0]##*.}" | tr '[:upper:]' '[:lower:]')"
    cp "${WALLPAPERS[0]}" "$PAYLOAD/family-linux/wallpaper.${ext}"
    echo "Wallpaper: $(basename "${WALLPAPERS[0]}")"
fi

# 3. Boot menu: every install entry reads the preseed from the ISO root (provisioner/iso.py).
#    Expert and rescue entries are left as Debian ships them.
xorriso -osirrox on -indev "$ISO_SRC" -extract /boot/grub/grub.cfg "${BUILD_DIR}/grub.cfg" >/dev/null 2>&1
chmod u+w "${BUILD_DIR}/grub.cfg"  # ISO files are read-only
PYTHONPATH="${PROJECT_ROOT}/src" "$PYTHON" -m family_linux.provisioner.iso grub "${BUILD_DIR}/grub.cfg" \
    --arch "$ARCH" --mode "$MODE"

# 3b. amd64 BIOS boot menu (isolinux): the same arguments on its Install and Graphical install
#     entries. Without this, a BIOS machine got the stock installer without the Family Linux answers.
ISOLINUX_MAPS=()
if [ "$ARCH" = amd64 ]; then
    for f in txt.cfg gtk.cfg isolinux.cfg; do
        xorriso -osirrox on -indev "$ISO_SRC" -extract "/isolinux/$f" "${BUILD_DIR}/isolinux-$f" >/dev/null 2>&1
        chmod u+w "${BUILD_DIR}/isolinux-$f"
        ISOLINUX_MAPS+=(-map "${BUILD_DIR}/isolinux-$f" "/isolinux/$f")
    done
    PYTHONPATH="${PROJECT_ROOT}/src" "$PYTHON" -m family_linux.provisioner.iso isolinux \
        "${BUILD_DIR}/isolinux-txt.cfg" "${BUILD_DIR}/isolinux-gtk.cfg" "${BUILD_DIR}/isolinux-isolinux.cfg" \
        --arch amd64 --mode "$MODE"
fi

# 4. Repack, keeping the original boot records (arm64 is UEFI, amd64 has BIOS and UEFI)
rm -f "$OUT_ISO"
xorriso -indev "$ISO_SRC" -outdev "$OUT_ISO" -boot_image any replay \
    -volid "FAMILYLINUX" \
    -map "${BUILD_DIR}/grub.cfg" /boot/grub/grub.cfg \
    -map "$EXPORT/preseed.cfg" /preseed.cfg \
    ${ISOLINUX_MAPS[@]+"${ISOLINUX_MAPS[@]}"} \
    -map "$PAYLOAD/family-linux" /family-linux >/dev/null 2>&1

# 5. Check the result
CHECK="${BUILD_DIR}/check"
rm -rf "$CHECK" && mkdir -p "$CHECK"
xorriso -indev "$OUT_ISO" -osirrox on -extract /preseed.cfg "$CHECK/preseed.cfg" >/dev/null 2>&1
grep -q "tasksel tasksel/first multiselect kde-desktop" "$CHECK/preseed.cfg" || { echo "preseed missing from ISO" >&2; exit 1; }
xorriso -indev "$OUT_ISO" -osirrox on -extract /boot/grub/grub.cfg "$CHECK/grub.cfg" >/dev/null 2>&1
grep -q "file=/cdrom/preseed.cfg" "$CHECK/grub.cfg" || { echo "preseed boot argument missing from ISO" >&2; exit 1; }
if [ "$ARCH" = amd64 ]; then
    xorriso -indev "$OUT_ISO" -osirrox on -extract /isolinux/txt.cfg "$CHECK/txt.cfg" >/dev/null 2>&1
    grep -q "file=/cdrom/preseed.cfg" "$CHECK/txt.cfg" || { echo "preseed boot argument missing from the BIOS menu" >&2; exit 1; }
fi
xorriso -indev "$OUT_ISO" -osirrox on -extract /family-linux/late-command.sh "$CHECK/late-command.sh" >/dev/null 2>&1
grep -q "Family Linux late command" "$CHECK/late-command.sh" || { echo "late-command script missing from ISO" >&2; exit 1; }
rm -rf "$CHECK"

echo "Built: ${OUT_ISO}"
echo "Size: $(du -h "$OUT_ISO" | awk '{print $1}')"
if [ "$MODE" = automated ]; then
    echo "Boot the ISO for ${ARCH}. At the menu, press Enter on 'Install'; the install runs unattended and the first boot applies the Family Linux policy."
else
    echo "Boot the ISO for ${ARCH}. At the menu, choose 'Install' (or 'Graphical install'). The Debian installer opens with the Family Linux answers filled in; the first boot applies the Family Linux policy."
fi
