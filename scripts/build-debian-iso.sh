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
# Optional: DEBIAN_BASE_URL (default https://cdimage.debian.org/debian-cd/current/<arch>/iso-cd).
# Requires: xorriso, curl, rsync, PARENT_PASS, and a Python with PyYAML (PYTHON=... to choose one).

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
for tool in xorriso curl rsync; do
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
#    name is read from there (it changes with each point release). The checksum is checked before
#    the image is used. The signature (SHA512SUMS.sign) is not checked by this script.
curl -fsSL --retry 3 -o "${BUILD_DIR}/SHA512SUMS" "${DEBIAN_BASE_URL}/SHA512SUMS" || {
    echo "Could not download ${DEBIAN_BASE_URL}/SHA512SUMS. If Debian moved its images, set DEBIAN_BASE_URL." >&2
    exit 1
}
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

# 3. Boot menu: every install entry starts the preseed from the ISO root (file=/cdrom/preseed.cfg).
#    Expert, rescue and graphical-automated entries are left as Debian ships them.
xorriso -osirrox on -indev "$ISO_SRC" -extract /boot/grub/grub.cfg "${BUILD_DIR}/grub.cfg" >/dev/null 2>&1
chmod u+w "${BUILD_DIR}/grub.cfg"  # ISO files are read-only
"$PYTHON" - "${BUILD_DIR}/grub.cfg" "$ARCH" "$MODE" <<'PY'
import sys
path = sys.argv[1]
ARCH = sys.argv[2]
MODE = sys.argv[3]
lines = open(path, encoding="utf-8").read().splitlines()
changed = 0
for index, line in enumerate(lines):
    stripped = line.lstrip()
    if not stripped.startswith("linux") or "---" not in line:
        continue
    if "priority=low" in line or "rescue/enable" in line:
        continue
    # Before "---": for the installer only. The preseed is read from the ISO root.
    head, _, tail = line.partition("---")
    extra = []
    if MODE == "automated" and "auto=true" not in head:
        extra.append("auto=true priority=critical")
    if "file=" not in head:
        extra.append("file=/cdrom/preseed.cfg")
    if extra:
        head = head.rstrip() + " " + " ".join(extra) + " "
    if MODE == "automated":
        # After "---": also copied to the installed system. The serial console is last, so it is
        # /dev/console, and headless builds (VirtualBox) can see the first-boot result.
        console = " console=ttyAMA0" if ARCH == "arm64" else " console=ttyS0"
        if console.strip() not in tail:
            tail = tail.rstrip() + console
    lines[index] = head + "---" + tail
    changed += 1
if changed == 0:
    sys.exit("No install kernel lines found in grub.cfg; the ISO layout is not what this script expects.")
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print(f"Preseed added to {changed} boot entr{'y' if changed == 1 else 'ies'}.")
PY

# 4. Repack, keeping the original boot records (arm64 is UEFI, amd64 has BIOS and UEFI)
rm -f "$OUT_ISO"
xorriso -indev "$ISO_SRC" -outdev "$OUT_ISO" -boot_image any replay \
    -volid "FAMILYLINUX" \
    -map "${BUILD_DIR}/grub.cfg" /boot/grub/grub.cfg \
    -map "$EXPORT/preseed.cfg" /preseed.cfg \
    -map "$PAYLOAD/family-linux" /family-linux >/dev/null 2>&1

# 5. Check the result
CHECK="${BUILD_DIR}/check"
rm -rf "$CHECK" && mkdir -p "$CHECK"
xorriso -indev "$OUT_ISO" -osirrox on -extract /preseed.cfg "$CHECK/preseed.cfg" >/dev/null 2>&1
grep -q "tasksel tasksel/first multiselect kde-desktop" "$CHECK/preseed.cfg" || { echo "preseed missing from ISO" >&2; exit 1; }
xorriso -indev "$OUT_ISO" -osirrox on -extract /boot/grub/grub.cfg "$CHECK/grub.cfg" >/dev/null 2>&1
grep -q "file=/cdrom/preseed.cfg" "$CHECK/grub.cfg" || { echo "preseed boot argument missing from ISO" >&2; exit 1; }
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
