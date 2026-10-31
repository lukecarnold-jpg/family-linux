# Wallpaper

Put one image here (`.png`, `.jpg` or `.jpeg`) to make it the desktop and lock-screen wallpaper for every account on systems installed from the ISO or the `.ova`.

- Any file name works. Keep only one image in this folder; the build stops if it finds more.
- 3840 × 2160 (or 1920 × 1080) suits most screens. The image is scaled to fill the screen ("zoom").
- Rebuild after adding or changing it: `scripts/build-autoinstall-iso.sh`, then `scripts/build-virtualbox-vm.sh`.
- With no image here, Ubuntu's own wallpaper is used.

It is a default, not a lock. The parent can choose a different wallpaper in Settings; children cannot open Settings, so theirs stays as set here.
