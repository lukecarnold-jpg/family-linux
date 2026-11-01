"""Boot-menu changes for the Family Linux ISO (used by scripts/build-debian-iso.sh).

The Debian netinst image has two boot menus: GRUB (UEFI, both architectures; boot/grub/grub.cfg) and,
on amd64, isolinux (BIOS; isolinux/txt.cfg, gtk.cfg, isolinux.cfg). Each install entry gets the
preseed from the ISO root. In automated mode it also gets the arguments that skip every question,
the serial console (headless builds watch it), and a 5-second timeout on the first entry. Expert and
rescue entries are left as Debian ships them.

Run as: python3 -m family_linux.provisioner.iso grub|isolinux FILE... --arch ARCH --mode MODE
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Tuple

PRESEED_ARG = "file=/cdrom/preseed.cfg"
AUTOMATED_ARGS = "auto=true priority=critical"
MODES = ("interactive", "automated")


def serial_console(arch: str) -> str:
    return "console=ttyAMA0" if arch == "arm64" else "console=ttyS0"


def patch_kernel_line(line: str, arch: str, mode: str) -> str:
    """Adds the preseed (and, when automated, the unattended and console arguments) to one entry.

    Arguments before "---" are for the installer only; arguments after it are also copied to the
    installed system. The serial console goes last, so it becomes /dev/console.
    """
    head, _, tail = line.partition("---")
    extra = []
    if mode == "automated" and "auto=true" not in head:
        extra.append(AUTOMATED_ARGS)
    if "file=" not in head:
        extra.append(PRESEED_ARG)
    if extra:
        head = head.rstrip() + " " + " ".join(extra) + " "
    console = serial_console(arch)
    if mode == "automated" and console not in tail:
        tail = tail.rstrip() + " " + console
    return head + "---" + tail


def _is_install_entry(line: str, keyword: str) -> bool:
    return line.strip().startswith(keyword) and "---" in line and "priority=low" not in line and "rescue/enable" not in line


def patch_grub(text: str, arch: str, mode: str) -> Tuple[str, int]:
    """Returns the patched grub.cfg and the number of entries changed."""
    _check_mode(mode)
    lines = text.splitlines()
    changed = 0
    for index, line in enumerate(lines):
        if _is_install_entry(line, "linux"):
            lines[index] = patch_kernel_line(line, arch, mode)
            changed += 1
    if mode == "automated":
        # Start the first entry (Install) after 5 seconds; interactive ISOs keep Debian's waiting menu.
        lines = ["set default=0", "set timeout=5", *lines]
    return "\n".join(lines) + "\n", changed


def patch_isolinux_entries(text: str, mode: str) -> Tuple[str, int]:
    """Patches the append lines of isolinux/txt.cfg or gtk.cfg (amd64 BIOS menu)."""
    _check_mode(mode)
    lines = text.splitlines()
    changed = 0
    for index, line in enumerate(lines):
        if _is_install_entry(line, "append"):
            lines[index] = patch_kernel_line(line, "amd64", mode)
            changed += 1
    return "\n".join(lines) + "\n", changed


def patch_isolinux_timeout(text: str, mode: str) -> str:
    """isolinux counts tenths of a second, and 0 waits for a key. Automated menus start after 5 seconds."""
    _check_mode(mode)
    return text.replace("timeout 0", "timeout 50") if mode == "automated" else text


def _check_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)} (got {mode!r})")


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description="Patch the Debian ISO's boot menus for Family Linux")
    parser.add_argument("menu", choices=("grub", "isolinux"))
    parser.add_argument("files", nargs="+", type=Path, help="grub.cfg; or isolinux txt.cfg gtk.cfg isolinux.cfg")
    parser.add_argument("--arch", choices=("arm64", "amd64"), required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args(argv)

    changed = 0
    for path in args.files:
        text = path.read_text(encoding="utf-8")
        if args.menu == "grub":
            text, count = patch_grub(text, args.arch, args.mode)
        elif path.name.endswith("isolinux.cfg"):
            text, count = patch_isolinux_timeout(text, args.mode), 0
        else:
            text, count = patch_isolinux_entries(text, args.mode)
        path.write_text(text, encoding="utf-8")
        changed += count
    needed = 1 if args.menu == "grub" else 2
    if changed < needed:
        print(f"No install entries found in the {args.menu} menu; the ISO layout is not what the build expects.", file=sys.stderr)
        return 1
    print(f"Preseed added to {changed} {'UEFI' if args.menu == 'grub' else 'BIOS'} boot entr{'y' if changed == 1 else 'ies'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
