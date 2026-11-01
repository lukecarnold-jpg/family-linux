"""Boot-menu changes, tested against the menus in Debian 13.7's own netinst images (tests/fixtures)."""

from pathlib import Path

import pytest

from family_linux.provisioner.iso import (
    main,
    patch_grub,
    patch_isolinux_entries,
    patch_isolinux_timeout,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _entry(text: str, title: str) -> str:
    """The kernel line of the menu entry with this exact title."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if f"menuentry '{title}'" in line)
    return next(line for line in lines[start:] if line.strip().startswith("linux"))


def test_interactive_grub_reads_the_preseed_but_still_waits_and_asks():
    text, changed = patch_grub(_read("debian-13.7-arm64-grub.cfg"), "arm64", "interactive")
    install = _entry(text, "Install")
    assert "file=/cdrom/preseed.cfg ---" in install
    assert "auto=true" not in install and "console=" not in install
    assert "set timeout=5" not in text  # the menu waits for a person
    assert changed > 0


def test_automated_grub_skips_questions_starts_by_itself_and_logs_to_serial():
    text, _ = patch_grub(_read("debian-13.7-arm64-grub.cfg"), "arm64", "automated")
    install = _entry(text, "Install")
    assert "auto=true priority=critical file=/cdrom/preseed.cfg ---" in install
    assert install.rstrip().endswith("console=ttyAMA0")
    assert text.startswith("set default=0\nset timeout=5\n")


def test_expert_and_rescue_entries_are_left_as_debian_ships_them():
    original = _read("debian-13.7-arm64-grub.cfg")
    text, _ = patch_grub(original, "arm64", "automated")
    for title in ("... Graphical expert install", "... Graphical rescue mode"):
        assert _entry(text, title) == _entry(original, title)


def test_entries_that_were_already_automated_get_no_second_copy():
    text, _ = patch_grub(_read("debian-13.7-arm64-grub.cfg"), "arm64", "automated")
    line = _entry(text, "... Automated install")
    assert line.count("auto=true") == 1 and line.count("file=") == 1
    again, _ = patch_grub(text.split("\n", 2)[2], "arm64", "automated")
    assert _entry(again, "Install") == _entry(text, "Install")


def test_amd64_grub_uses_the_pc_serial_console():
    text, _ = patch_grub(_read("debian-13.7-amd64-grub.cfg"), "amd64", "automated")
    assert "console=ttyS0" in text and "console=ttyAMA0" not in text


def test_amd64_bios_menu_gets_the_same_arguments():
    for name in ("debian-13.7-amd64-isolinux-txt.cfg", "debian-13.7-amd64-isolinux-gtk.cfg"):
        text, changed = patch_isolinux_entries(_read(name), "interactive")
        assert changed == 1 and "file=/cdrom/preseed.cfg ---" in text and "auto=true" not in text
        text, _ = patch_isolinux_entries(_read(name), "automated")
        assert "auto=true priority=critical file=/cdrom/preseed.cfg ---" in text and "console=ttyS0" in text


def test_bios_menu_waits_unless_automated():
    original = _read("debian-13.7-amd64-isolinux-isolinux.cfg")
    assert "timeout 0" in original
    assert patch_isolinux_timeout(original, "interactive") == original
    assert "timeout 50" in patch_isolinux_timeout(original, "automated")


def test_unknown_mode_is_refused():
    with pytest.raises(ValueError):
        patch_grub("", "arm64", "silent")


def test_command_line_fails_when_the_menu_has_no_install_entries(tmp_path):
    empty = tmp_path / "grub.cfg"
    empty.write_text("set menu_color_normal=cyan/blue\n")
    assert main(["grub", str(empty), "--arch", "arm64", "--mode", "interactive"]) == 1


def test_command_line_patches_the_bios_files_in_place(tmp_path):
    files = []
    for part in ("txt", "gtk", "isolinux"):
        path = tmp_path / f"isolinux-{part}.cfg"
        path.write_text(_read(f"debian-13.7-amd64-isolinux-{part}.cfg"))
        files.append(str(path))
    assert main(["isolinux", *files, "--arch", "amd64", "--mode", "automated"]) == 0
    assert "timeout 50" in (tmp_path / "isolinux-isolinux.cfg").read_text()
    assert "file=/cdrom/preseed.cfg" in (tmp_path / "isolinux-txt.cfg").read_text()
