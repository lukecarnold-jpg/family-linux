# Wallpaper

Put one image here (`.png`, `.jpg` or `.jpeg`) to make it the desktop wallpaper for every account on systems installed from the ISO or the `.ova`.

- Any file name works. Keep only one image in this folder; the build stops if it finds more.
- 3840 × 2160 (or 1920 × 1080) suits most screens.
- Rebuild after adding or changing it: `scripts/build-debian-iso.sh`, then `scripts/build-virtualbox-vm.sh`.
- With no image here, Plasma's own default wallpaper is used.

Plasma has no system-wide wallpaper default, so the image is applied once for each account at its first login (`config/bin/family-linux-set-wallpaper`, started from `config/xdg/autostart/`). After that the account can change it, and the change is kept. The parent can choose a different wallpaper in System Settings. Children's menus hide System Settings, so the wallpaper set here stays theirs.
