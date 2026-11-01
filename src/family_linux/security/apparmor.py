"""AppArmor confinement management for Family Linux.

Provides baseline confinement profiles for child sessions and restricted applications,
preventing privilege escalation, raw socket manipulation, and access to admin paths.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, List
from family_linux.security.adapter import SystemAdapter

APPARMOR_DIR = Path("/etc/apparmor.d")
PROFILE_NAME = "family-linux-child"
PROFILE_PATH = APPARMOR_DIR / "family-linux-child"


CHILD_SESSION_PROFILE = """# AppArmor profile for Family Linux child session confinement
#include <tunables/global>

profile family-linux-child flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>
  #include <abstractions/fonts>
  #include <abstractions/freedesktop.org>
  # Desktop apps (Firefox, LibreOffice, VLC): display, graphics, sound, session bus, certificates.
  # Without these the profile stopped Firefox from starting at all (seen on Debian 13).
  #include <abstractions/X>
  #include <abstractions/wayland>
  #include <abstractions/dri-common>
  #include <abstractions/mesa>
  #include <abstractions/audio>
  #include <abstractions/dbus-session-strict>
  #include <abstractions/openssl>
  #include <abstractions/ssl_certs>

  dbus,
  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network netlink raw,
  network unix,
  unix,
  # Firefox's own content sandbox uses user namespaces; without them it runs less isolated. The
  # two capabilities apply only inside that namespace (a child has none in the real system).
  userns,
  capability sys_admin,
  capability sys_chroot,
  signal (send, receive) peer=family-linux-child,
  ptrace (read, trace) peer=family-linux-child,

  # System libraries and the helpers apps start from them (Firefox runs
  # /usr/lib/firefox-esr/firefox-esr for every content process)
  /usr/lib/** mrix,
  /usr/lib64/** mr,
  /lib/** mr,
  /lib64/** mr,

  # Ordinary system configuration, data, and binaries that approved apps need.
  # The deny rules below take precedence over these allow rules.
  /etc/** r,
  /usr/share/** r,
  /usr/local/share/** r,
  /usr/bin/** ix,
  /usr/libexec/** ix,
  /bin/** ix,
  @{PROC}/** r,
  owner @{PROC}/@{pid}/** rw,
  /sys/** r,
  /dev/ r,
  deny /var/cache/fontconfig/ w,
  owner /dev/shm/** rwk,
  owner /run/user/*/** rwkl,

  # Deny direct access to administrative and sensitive directories
  deny /etc/shadow* rwk,
  deny /etc/sudoers* rwk,
  deny /root/** rwk,
  deny /etc/security/** rwk,
  deny /etc/family-linux/** rw,

  # Deny execution of package managers and shell escalators
  deny /usr/bin/sudo x,
  deny /usr/bin/su x,
  deny /usr/bin/pkexec x,
  deny /usr/bin/apt x,
  deny /usr/bin/apt-get x,
  deny /usr/bin/dpkg x,

  # Deny command lines: shells and terminal emulators. Exec is checked on every
  # program a confined process starts, so this also stops env, python, or
  # os.system from reaching a shell.
  deny /{,usr/}bin/{,ba,da,z,fi}sh x,
  deny /{,usr/}bin/{rbash,ksh,tcsh,csh} x,
  deny /{,usr/}bin/{gnome-terminal*,xterm,uxterm,konsole,kgx,xfce4-terminal,tilix,terminator,lxterminal,mate-terminal,rxvt*,st,alacritty,kitty,foot} x,
  deny /usr/libexec/gnome-terminal-* x,

  # Child home access, with file locks (Firefox locks its profile folder; without k it reported
  # that another copy was already running)
  owner @{HOME}/ r,
  owner @{HOME}/** rwkl,
  owner @{HOME}/** mr,

  # Deny raw packet sockets (netlink stays allowed: apps use it to watch the network)
  deny network inet raw,
  deny network inet6 raw,
  deny network packet,
}
"""


class AppArmorManager:
    """Manages Family Linux AppArmor confinement profiles."""

    def __init__(self, adapter: Optional[SystemAdapter] = None):
        self.adapter = adapter or SystemAdapter()

    def is_available(self) -> bool:
        """Checks if AppArmor is supported on the running kernel."""
        status = self.adapter.run_command(["aa-status", "--enabled"])
        return status.returncode == 0

    def install_profile(self) -> Path:
        """Installs and reloads the child confinement AppArmor profile."""
        self.adapter.write_system_file(PROFILE_PATH, CHILD_SESSION_PROFILE, mode=0o644)
        self.adapter.run_command(["apparmor_parser", "-r", str(PROFILE_PATH)])
        return PROFILE_PATH

    def get_status(self) -> str:
        """Returns AppArmor status output."""
        res = self.adapter.run_command(["aa-status"])
        return res.stdout
