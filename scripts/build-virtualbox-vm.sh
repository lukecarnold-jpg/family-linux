#!/usr/bin/env bash
set -euo pipefail

# Family Linux VirtualBox appliance builder.
#
# Builds the install ISO, creates a VirtualBox VM, installs Family Linux unattended and headless,
# waits for the first-boot apply, then exports an .ova that can be imported with
# File > Import Appliance (or: VBoxManage import <file>.ova).
#
# Architecture: arm64 on Apple silicon (VirtualBox 7.2 or later), amd64 elsewhere. Override with ARCH.
#
# Required: VirtualBox (VBoxManage), PARENT_PASS, and what scripts/build-autoinstall-iso.sh needs.
# Optional: VM_NAME (default "Family Linux"), CHILD_SPECS, MEMORY_MB (4096), CPUS (2),
#           DISK_MB (40960), TIMEOUT_MIN (90), SKIP_ISO=1 to reuse an existing ISO.
#
# The parent password in the appliance is PARENT_PASS. Build with your own; do not share an
# appliance built with a password other people know.

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
    arm64) PLATFORM=arm; OSTYPE=Ubuntu24_LTS_arm64; GRAPHICS=qemuramfb ;;
    amd64) PLATFORM=x86; OSTYPE=Ubuntu24_LTS_64;    GRAPHICS=vmsvga ;;
    *) echo "ARCH must be arm64 or amd64 (got '$ARCH')" >&2; exit 2 ;;
esac

VM_NAME="${VM_NAME:-Family Linux}"
MEMORY_MB="${MEMORY_MB:-4096}"
CPUS="${CPUS:-2}"
DISK_MB="${DISK_MB:-40960}"
TIMEOUT_MIN="${TIMEOUT_MIN:-90}"
ISO="${OUTPUT_DIR}/family-linux-ubuntu-24.04-${ARCH}.iso"
OVA="${OUTPUT_DIR}/family-linux-ubuntu-24.04-${ARCH}.ova"
SERIAL_LOG="${BUILD_DIR}/vbox-${ARCH}-serial.log"

command -v VBoxManage >/dev/null || { echo "VBoxManage not found; install VirtualBox 7.2 or later." >&2; exit 2; }
: "${PARENT_PASS:?Set PARENT_PASS to the parent password (min 14 characters, with upper-case, lower-case, a number and a special character)}"
if VBoxManage showvminfo "$VM_NAME" >/dev/null 2>&1; then
    echo "A VM named '$VM_NAME' already exists. Set VM_NAME, or remove that VM first." >&2
    exit 2
fi
[ ! -e "$OVA" ] || { echo "$OVA already exists; move it away first." >&2; exit 2; }
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# 1. Install ISO
if [ "${SKIP_ISO:-0}" = 1 ] && [ -f "$ISO" ]; then
    echo "Reusing ${ISO}"
else
    ARCH="$ARCH" "${SCRIPT_DIR}/build-autoinstall-iso.sh"
fi

# 2. VM: ${ARCH}, EFI, VirtIO disk and network, serial output to a log so the build can follow it
echo "Creating VM '${VM_NAME}' (${ARCH})..."
VBoxManage createvm --name "$VM_NAME" --platform-architecture "$PLATFORM" --ostype "$OSTYPE" --register >/dev/null
VM_DIR="$(dirname "$(VBoxManage showvminfo "$VM_NAME" --machinereadable | sed -n 's/^CfgFile="\(.*\)"$/\1/p')")"
rm -f "$SERIAL_LOG"
VBoxManage modifyvm "$VM_NAME" \
    --memory "$MEMORY_MB" --cpus "$CPUS" --firmware efi \
    --graphicscontroller "$GRAPHICS" --vram 16 \
    --nic1 nat --nic-type1 virtio \
    --audio-enabled off --usb-xhci on --mouse usbtablet --keyboard usb \
    --uart1 0x3F8 4 --uart-mode1 file "$SERIAL_LOG"
VBoxManage createmedium disk --filename "${VM_DIR}/family-linux.vdi" --size "$DISK_MB" --format VDI >/dev/null
VBoxManage storagectl "$VM_NAME" --name VirtIO --add virtio --controller VirtIO --portcount 2 --bootable on
VBoxManage storageattach "$VM_NAME" --storagectl VirtIO --port 0 --device 0 --type hdd --medium "${VM_DIR}/family-linux.vdi"
VBoxManage storageattach "$VM_NAME" --storagectl VirtIO --port 1 --device 0 --type dvddrive --medium "$ISO"

# 3. Unattended install, reboot, and first-boot apply
echo "Installing (headless). Progress: ${SERIAL_LOG}"
VBoxManage startvm "$VM_NAME" --type headless >/dev/null
deadline=$(( $(date +%s) + TIMEOUT_MIN * 60 ))
result=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -aq "First-boot provisioning complete" "$SERIAL_LOG" 2>/dev/null; then result=ok; break; fi
    if grep -aqE "First-boot provisioning failed|install_fail" "$SERIAL_LOG" 2>/dev/null; then result=failed; break; fi
    sleep 20
done
if [ "$result" != ok ]; then
    echo "Install did not finish (${result:-timed out after ${TIMEOUT_MIN} minutes}). The VM is left running for inspection." >&2
    tail -n 20 "$SERIAL_LOG" >&2 || true
    exit 1
fi
grep -a "First-boot provisioning complete" "$SERIAL_LOG" | tail -n 1

# 4. Shut down cleanly, remove the ISO and the host-specific serial log, export
echo "Shutting down..."
VBoxManage controlvm "$VM_NAME" acpipowerbutton
for _ in $(seq 1 60); do
    VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -q '^VMState="poweroff"' && break
    sleep 5
done
if ! VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -q '^VMState="poweroff"'; then
    echo "The VM did not shut down within 5 minutes; not exporting a disk that may be in use." >&2
    exit 1
fi
VBoxManage storageattach "$VM_NAME" --storagectl VirtIO --port 1 --device 0 --type dvddrive --medium emptydrive
VBoxManage modifyvm "$VM_NAME" --uart1 off

echo "Exporting ${OVA}..."
VBoxManage export "$VM_NAME" -o "$OVA" \
    --vsys 0 --product "Family Linux" --version "Ubuntu 24.04 LTS (${ARCH})" \
    --description "Family Linux: one parent administrator, restricted child accounts. Policy applied on first boot."
echo "Built: ${OVA} ($(du -h "$OVA" | awk '{print $1}'))"
echo "Import with: VBoxManage import \"${OVA}\"  (or File > Import Appliance in VirtualBox)"
