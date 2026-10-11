# Family Linux Development History

This records how the project got to its current state, the decisions behind it, the issues found in review, and what has been fixed. For the repository layout see [STRUCTURE.md](STRUCTURE.md).

Git records the early commits with the date 2026-10-10. Those dates reflect when the history was written in this repository, not necessarily when each change was first drafted.

## Commit timeline

| Commit | Author | Summary |
|--------|--------|---------|
| `73dd9bc` | Luke Arnold | Initial commit |
| `f18e5e3` | Luke Arnold | Initialize Family Linux with architecture, policy, and planning docs. |
| `6d6bb06` | copilot-swe-agent[bot] (co-authored with lukecarnold-jpg) | Align design docs with Ubuntu, parent-child model, and installer flow. Adds `docs/installer.md`. |
| `0022875` | Luke Arnold | Merge PR #1 `copilot/update-ubuntu-references` into `main`. |
| `644a98e` | Luke Arnold | Implement the prototype with CI workflow. Adds the implementation, tests, `.gitignore`, `LICENSE`, `.github/workflows/ci.yml`, and these docs. |

The CI run for `644a98e` passed on `main`.

## Current state

The work in the "Session 2" section below is uncommitted. Files changed or added in that session:

- Modified: `.github/workflows/ci.yml`, `pyproject.toml`, `scripts/bootstrap-prototype.sh`, `scripts/build-autoinstall-iso.sh`, `src/family_linux/cli/family_ctl.py`, `src/family_linux/installer/wizard.py`, `src/family_linux/models.py`, `src/family_linux/parent_ui/server.py`, `src/family_linux/provisioner/autoinstall.py`, `src/family_linux/provisioner/system.py`, `src/family_linux/security/adapter.py`, `src/family_linux/security/app_guard.py`, `src/family_linux/security/apparmor.py`, `tests/test_cli.py`, `tests/test_security.py`.
- Added: `tests/integration/test_linux_provisioning.py`, `tests/test_dashboard.py`, `tests/test_provisioning.py`, `tests/test_secrets.py`.

## Decisions log

1. **Ubuntu LTS is the base distribution** (`6d6bb06`). Security uses Ubuntu's own mechanisms: users and groups, sudo, AppArmor, UFW, signed repositories. OpenBSD is a source of principles only.
2. **One parent account, many child accounts.** Children are non-admin with no sudo. Enforced in `models.py`, the installer, the provisioner, and `verify`.
3. **Installer is a 12-step flow** (`docs/installer.md`), with recommended and advanced modes.
4. **Configuration is applied to a running system.** The provisioner applies a policy to users, firewall, DNS, browsers, AppArmor, and desktop filters. Disk partitioning is not implemented. Ubuntu itself is meant to be installed from autoinstall `user-data`.
5. **Dry-run is the default off Linux and whenever not root.** Session 2 fixed a gap where the dry-run flag did not reach the policy and audit writers (see Session 2).
6. **Passwords are never persisted** (Session 2). They exist in memory long enough to call `chpasswd` or to build the autoinstall hashes.
7. **Save before apply** (Session 2). The policy is written before any system change, so a failed apply leaves the intended state on disk. Every step is idempotent, so re-running the apply converges.
8. **The dashboard requires an access token and a session cookie** (Session 2). It binds to loopback only, checks the Host and Origin headers, and requires JSON bodies.

## Session 1 review (prior review, before `644a98e`)

Findings from reading the code. All listed here were still open at the start of Session 2 unless marked otherwise.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | Dashboard has no authentication; accepts POST from any origin with any Content-Type | **Fixed** (Session 2) |
| 2 | High | Passwords stored in plaintext in `policy.yaml` and backups | **Fixed** for new saves (Session 2). Backups created before this change still hold old plaintext. |
| 3 | High | Installer prompts used hardcoded default passwords; input echoed | **Fixed** (Session 2) |
| 4 | High | `family-ctl verify` hardcoded two checks as passing and printed "complies 100%" | **Fixed** (Session 2) |
| 5 | Medium | AppArmor profile in complain mode | **Fixed** (flag changed to enforce; attachment still missing, see open item 2) |
| 6 | Medium | Two sudoers drop-ins with different paths | **Fixed**: both now use `/etc/sudoers.d/family-linux-admin` |
| 7 | Medium | Child shell is `/usr/sbin/nologin`; may block desktop login | Open (needs a real desktop test) |
| 8 | Medium | Autoinstall package list included `scratch3`, which is not in Ubuntu 24.04 apt | **Fixed** (removed; see Session 2, section C) |
| 9 | Medium | ISO helper prints steps and does not build an ISO | Open |
| 10 | Medium | Installer's advanced target disk captured but unused | **Fixed**: passed to autoinstall `storage.layout.match.path` (unverified against Subiquity; see Session 2, section C) |
| 11 | Low | Fallback policy ignores `config/default-policy.yaml` | Open |
| 12 | Low | `bootstrap-prototype.sh` with no arguments started the installer | **Fixed**: default is now `help` |
| 13 | Low | No `.gitignore` | **Fixed** (`644a98e`) |
| 14 | Low | No `LICENSE` | **Fixed** (`644a98e`) |
| 15 | Low | Notification sends a shell string built by interpolation | Open (low risk today) |
| 16 | Low | No tests for the dashboard or real Linux paths | **Fixed** (Session 2) |

## Session 2 review and changes

Session 2 worked through the gap list from the second review. Each item below records what was done and what was not.

### A. Linux-privileged integration tests and CI job (done)

- `tests/integration/test_linux_provisioning.py` runs real `useradd`, `usermod`, `passwd`, `visudo`, and `ufw` commands. It only runs as root on Linux with `FAMILY_LINUX_INTEGRATION=1`, and it skips everywhere else.
- A `linux-integration` job in `.github/workflows/ci.yml` installs `ufw` and `apparmor-utils`, then runs those tests as root.
- Passed in a local Ubuntu 24.04 container (privileged Docker).

### B. Dashboard hardening and tests (done)

- `make_handler()` takes its dependencies as parameters, so tests run against a temporary directory.
- Every request needs the token: an `Authorization: Bearer` header, or the `fl_session` cookie.
- The one-time link `/?token=…` sets an `HttpOnly; SameSite=Strict` cookie and redirects, so the token leaves the address bar.
- Requests must have a loopback `Host` header, and any `Origin` header must match the dashboard. POSTs must be `application/json`, and bodies are capped at 64 KB.
- The `Access-Control-Allow-Origin: *` header is removed.
- Child passwords must be at least 8 characters, and invalid input returns 400 instead of an unhandled error.
- Startup prints the one-time link with `flush=True`. Without the flush, a systemd journal or pipe would show it late or not at all.
- `tests/test_dashboard.py` covers 14 cases. A live check with `curl` against a real server process confirmed 401, 200, 403, 415, and the cookie.

### C. Installer choices and the autoinstall output (partly done)

- The installer's language, keyboard, and target disk now reach the autoinstall export. Before this, the export always used the defaults.
- `--target-disk` is written to the storage layout as `match.path`, but only when given explicitly. The `match.path` key is unverified against Subiquity (no Subiquity runtime here).
- `scratch3` was removed from the autoinstall package list (not in Ubuntu 24.04 apt).
- **Not done:** the autoinstall is still the only install path. The wizard's network step is still a print statement.

### D. Passwords (done)

- `ParentAccount.password` and `ChildAccount.password` are `repr=False` and are excluded from `FamilyPolicy.to_dict()`. The policy file and the API never contain them.
- Policies loaded from older files still work. The plaintext values are used for provisioning, and the next save removes them. `tests/test_secrets.py` covers this.
- Installer: defaults removed. Prompts use `getpass`. Non-interactive runs require `--parent-pass`. The parent rule is at least 14 characters with an upper-case letter, a lower-case letter, a number and a special character (Session 13). The child spec needs a password, and `split(":", 3)` keeps colons inside passwords.
- `build-autoinstall-iso.sh`, `bootstrap-prototype.sh autoinstall`, and the CI smoke test now require `PARENT_PASS`.

### E. Honest `verify` (done)

- Policy checks always run. Live checks run only on Linux; elsewhere they are reported as `[SKIP]`, and the overall result is `[INCOMPLETE]`, never `[SUCCESS]`.
- Live checks: parent sudoers drop-in present and passes `visudo -cf`; UFW active with deny incoming; Firefox and Chromium managed policy files present; AppArmor profile loaded in enforce mode (asked of the kernel with `aa-status`, not read from the file); unattended-upgrades enabled.
- A missing tool is reported as a FAIL with a reason. It no longer raises an exception.
- `family-ctl web status` derives SafeSearch, incognito, and DevTools status from the policy instead of printing fixed text.

### F. Apply ordering and failure recovery (done)

- `apply_policy` saves the policy first, then applies the system layers. A failure raises `ProvisioningError`, which names the last completed step and says to re-run the apply.
- Before this, a failure partway through left the system changed and the policy file out of date. This happened in a live container run: the `/etc/hosts` write failed after users were created.
- The installer and the dashboard report `ProvisioningError` cleanly.
- **Not done:** a pre-apply diff or dry-run preview of changes, and rollback of completed steps.

### G. Security updates (partly done)

- `regular_security_updates` is now applied: the provisioner installs `unattended-upgrades` if it is missing, then runs `systemctl enable --now`. A failure is a warning.
- Before this, the policy field was stored but never used.

### H. Bugs found by testing (fixed)

- **Dry-run leaked to real files.** `SystemProvisioner` and `AppGuard` created `AuditLogger()` and `PolicyConfigManager()` without the dry-run flag. A simulated install still wrote the real audit log (on Linux) and `~/.config/family-linux/policy.yaml` (on macOS). Fixed, with a regression test in `tests/test_security.py`. Test artifacts left in the home directory on this Mac were removed.
- **Unit tests modified the real system when run as root on Linux.** `test_cli.py` built a live `FamilyCtl`, which wrote `/etc/hosts`, `/var/log/family-linux`, and `/var/lib/family-linux`. The fixture now simulates system writes and uses temporary files for usage and audit data.
- **Bind-mounted files could not be written.** `write_system_file` used an atomic rename, which fails on bind-mounted files such as `/etc/hosts` in containers. It now falls back to an in-place write. Also, the temp file was named with `with_suffix`, which could collide: `family-linux-dns.conf` and `family-linux-dns.tmp` mapped to the same temp file. It now appends `.tmp` to the full name.
- **AppArmor message contradicted the code.** The warning said "profile written but not enforced", but the profile was only written when AppArmor was active. The profile is now always written, and the warning is accurate.

### I. CLI and tests (done)

- `family-ctl user add --password` enforces the minimum length.
- The existing test that asserted the hardcoded "complies 100%" message was replaced.

### Not done in Session 2

- **Child session lockdown** (gap 2). The architecture requires no terminal or shell workflow for children. The code hides desktop entries only. A terminal is still reachable by keyboard shortcut, file manager, or similar. This needs a real GNOME session to design and test, and a container cannot run one.
- **Browser policy on Ubuntu** (gap 3). `apt-cache` in Ubuntu 24.04 shows `firefox` and `chromium-browser` as transitional packages that install snaps. The managed policy files are written to `/etc/firefox/policies` and `/etc/chromium/policies`. Whether snap builds read those paths is unverified. Snapd cannot run in a container here.
- **Packaging** (gap 6). Nothing installs the console scripts or the systemd units (`/usr/local/bin`, `/etc/systemd/system`).
- **ISO build** (gap 9). `build-autoinstall-iso.sh` still prints manual steps.
- **Child shell** (finding 7). Needs a real login test.
- **Notification quoting** (finding 15). Low risk. Pass arguments as a list.
- **Backups still hold old plaintext** (finding 2). Scrub or re-create backups from policies saved after this change.

## Verification matrix (Session 2)

| Environment | What ran | Result |
|-------------|----------|--------|
| macOS, Python 3.14 (scratch venv) | Full suite | 53 passed, 4 skipped (integration tests skip off Linux) |
| Ubuntu 24.04 container, root, `FAMILY_LINUX_INTEGRATION=1` | Full suite | 56 passed, 1 skipped (Linux-only `verify` test) |
| Ubuntu 24.04 container, non-root (CI test job) | Full suite | 52 passed, 5 skipped |
| Ubuntu 24.04 container, root | Live non-dry-run install with one child, then `verify` | Install exit 0 with two warnings (AppArmor not active; unattended-upgrades enable failed without a running init). `verify`: 9 PASS, 1 FAIL (AppArmor not loaded: kernel has no AppArmor). |
| Ubuntu 24.04 container, root | Dashboard process, `curl` | 401 without token; 200 with bearer; 403 bad Host; 415 form POST; 400 short password; cookie set on link |
| Ubuntu 24.04 container | Plaintext search across `/etc/family-linux`, `/etc/firefox`, `/etc/chromium`, `/etc/apparmor.d` | No matches |

Limitations of the container runs:

- No init (PID 1) is systemd. `systemctl is-enabled unattended-upgrades` reports `enabled` because the package enables its unit on install, but `systemctl enable --now` fails, so the container cannot show the service running. On a real Ubuntu host this check is meaningful; in a container it is not proof of a running service.
- No snapd, no desktop session, and `/etc/hosts` is a bind mount.
- AppArmor is not active in the container, so the "loaded in enforce mode" check fails there. That is the correct result for this environment. Confirming it passes needs a VM or a host with AppArmor enabled.

## Session 3: AppArmor attachment

The profile was named but never attached, so it could not confine any process (open item 1 in Session 2).

- Approved apps for a child are now launched through `aa-exec -p family-linux-child`. `AppGuard` writes a per-user desktop entry whose `Exec=` lines are prefixed with that command. `aa-exec` ships in Ubuntu's `apparmor` package.
- The wrapper is written only when AppArmor is active (`aa-status --enabled` succeeds). Otherwise `aa-exec` would fail to start the app, so approved apps stay unwrapped.
- The profile name is defined once in `security/apparmor.py` (`PROFILE_NAME`) and imported by `app_guard.py`. A test checks that the profile text uses it.
- `apply_child_desktop_filters` now takes `confine`, `home_root`, and `app_dirs`, and returns `(hidden, confined)`. The injected paths let tests run without touching `/home`.
- Verified in the Ubuntu container: the profile parses with `apparmor_parser -Q`, and a live install with AppArmor inactive wraps nothing. The attachment itself has not been exercised at runtime, because the container has no AppArmor kernel and no desktop. Next step is a VM run and a check that `aa-exec` launches each approved app under the profile.

## Session 4: PR and VM validation

- Opened PR #2 (`harden-prototype` into `main`). CI is green across Python 3.9–3.13 on Ubuntu and macOS.
- The privileged `linux-integration` job ran on GitHub: 4 tests passed on a real Ubuntu runner.
- Added a `live-install` job that applies a real non-dry-run policy on the GitHub Ubuntu VM (systemd and AppArmor running), runs `family-ctl verify`, and checks the AppArmor profile. All 9 live checks pass on the VM.
- The VM job found a real problem. The child profile denied a plain read of `/etc/hostname`, which would stop approved apps from running under it. Caught by a positive control: an unrestricted-read check would have passed the negative check while breaking normal use.
- Fixed the profile: allows `/etc`, `/usr/share`, and standard binary paths. The explicit denies (shadow, sudoers, root, package managers, family policy) still apply. The VM job then passed both controls: `/etc/hostname` readable, `/etc/shadow` denied under `family-linux-child`.
- Known trade-off: confined processes can still execute other binaries, including shells. A launched app that spawns a shell escapes the file restrictions. Closing this needs the child session work below.

## Session 5: child session lockdown and web filtering

Item 1 (child session lockdown):

- Child AppArmor profile now denies starting shells (`sh`, `bash`, `dash`, `zsh`, `fish`, and others) and terminal emulators. Exec is checked on each program a confined process starts, so `env`, Python, or `os.system` cannot reach a shell.
- Terminal shortcut (Ctrl+Alt+T) and the Alt+F2 command line are locked with system-wide dconf settings written to `/etc/dconf/db/local.d`. The locks apply to every user, including the parent.
- Blocked-program list adds terminal emulators and GNOME desktop IDs (`org.gnome.Terminal`, `org.gnome.Console`, `kgx`, and others).
- Tested on the GitHub Ubuntu VM: `/bin/sh` and `bash` cannot be started from inside the profile, `/usr/bin/env` (an allowed binary) still runs, and the lockdown files are written.
- Found while testing: `aa-exec -p PROFILE -- SHELL` does not test the deny rule. `aa-exec` switches profile on exec, but the exec is checked against the caller, which is unconfined root. The meaningful test starts the shell from inside the profile.
- Not covered: a terminal started outside the profile (for example from a file manager's "open terminal here") and any interpreter that can run code. The dconf locks and the desktop-entry hiding only cover the entry points listed above. A child's login shell is `nologin`, which blocks a text console login.

Web filtering (answer to the parent's question):

- Parents can set blocked and allowed domains per child, from the CLI or the dashboard. Blocking is enforced in three places: the browser (Firefox and Chromium managed policies), the hosts file, and the DNS provider chosen in the policy (CleanBrowsing Family by default).
- Found and fixed: the default wildcard rules (`*.adult`, `*.porn`, `*.gambling`) did not block anything. The hosts file got `0.0.0.0 adult` (a host named "adult") and Firefox got `*://adult/*`. Firefox now gets `*://*.adult/*`, and the hosts layer skips wildcards and reports them as warnings.
- Not fixed, needs a decision:
  - **Per-child rules are not per-child.** Browser policy and the DNS provider come from the first child only. Browser policies are system-wide, so they apply to every user. Per-child browser rules cannot be expressed this way. The blocklist is the union across children, so one child's block applies to all.
  - **Allowlists do not override DNS blocks.** An allowed site that the DNS family filter blocks stays blocked. The allowlist only affects browser URL exceptions.
  - **Chromium wildcard syntax is unverified.** The Chromium URL blocklist still gets `http://*.adult`. I did not change it because I could not check Chromium's wildcard format here.
  - **Snap builds.** Ubuntu's Firefox and Chromium are snaps, so the managed policy files may not apply (see open item on browser policy).

## Session 6: per-child web filtering and request approval

Design: each child's DNS is enforced by a per-child gateway, not by machine-wide browser or hosts rules. Machine-wide rules applied one child's settings to everyone, including the parent.

- **Resolver** (`security/dns_gateway.py`): stdlib-only DNS server, UDP and TCP, one listener per child on loopback. Blocked names get `0.0.0.0` (AAAA gets an empty answer). Allowed names go to an unfiltered upstream. Everything else goes to the family-safe upstream from the policy. Allow rules take precedence over block rules. The `*.name` wildcard matches hosts under `name`, not `name` itself.
- **Redirect** (`security/web_gateway.py`): an nftables table redirects each child's port 53 traffic (UDP and TCP, any destination) to that child's listener, matched by Linux UID. DNS over TLS and QUIC (port 853) are dropped for children.
- **Service**: `family-dnsd.service` runs the gateway as root with the Python interpreter that provisioned it.
- **Requests (C)**: blocked lookups and names the family upstream refuses (NXDOMAIN) are recorded per child. `family-ctl web requests` lists them. `web approve CHILD DOMAIN` allows the domain for that child and clears the request. `web deny` dismisses it, and the domain stays blocked. The dashboard has `GET /api/web/requests` and `POST /api/web/approve`. There is no dashboard page yet.
- **Removed**: the browser URL block and allow lists (managed browser policy is machine-wide, so per-child lists could not be expressed) and the machine-wide hosts blocklist. The provisioner clears any hosts block left by an earlier version.
- **CLI**: `web block` and `web allow` take `--child`. Without it they apply to all children, as before.

Verified on the GitHub Ubuntu VM (live job):
- The gateway service runs and the nftables table is present.
- A child's lookup of `tiktok.com` (blocked by default) returns `0.0.0.0`. The parent's lookup resolves normally.
- A child's UDP query addressed to `8.8.8.8` is answered by the gateway with `0.0.0.0`, so the redirect catches queries to outside resolvers.
- DNS over TLS from a child is dropped.
- `omegle.com` appears in `web requests`, and after `web approve` the child's lookup resolves normally.

Found while testing:
- A TCP connect from a child to `8.8.8.8:53` succeeds, because the redirect sends it to the gateway. The test checks the answer rather than the connection.
- The oversized-body test failed on macOS: the server replied 413 without reading the body, so the client saw a connection reset. The server now drains up to 1 MB before replying and closes the connection.

Known limits (not closed by this design):
- **Direct IP access.** A child who connects to an IP address directly bypasses DNS filtering. Stopping this needs an allow-list of resolved addresses, which is more work.
- **Non-browser DNS-over-HTTPS.** Browsers are set to use the system resolver, but other apps can still use DoH to a public IP.
- **Chromium wildcard syntax** is no longer used, since browser URL lists were removed. Chromium is not affected by this design.
- **Gateway availability.** If the gateway is down, the child's DNS fails closed (queries time out) rather than falling back. The restart policy is `on-failure`.
- **No dashboard page** for requests yet. The API exists.

## Session 7: closing the direct-IP bypass

Design: a child may only connect to addresses that the gateway has just returned in a lookup the parent allowed.

- **Address parsing** (`dns_gateway.parse_answer_addresses`): reads A and AAAA records with their TTLs from successful replies, following compressed names. Malformed replies yield what was read before the error and never stop the resolver.
- **Allow sets** (`web_gateway.render_nft`): per child, an IPv4 and an IPv6 nftables set with timeouts. The output filter drops that child's outbound traffic unless it is to loopback, part of an established connection, or in one of the sets. DoT (port 853) is dropped first.
- **Learning** (`dns_gateway.AddressAllowList`): after an allowed or default answer, each address is deleted and re-added with the record's TTL, clamped to 60 seconds to 1 hour. Blocked answers add nothing. The gateway config carries each child's UID.
- **Loopback match**: the rules match the destination (`127.0.0.0/8`, `::1`), not the output interface. A redirected packet's interface is chosen before the redirect, so `oif "lo"` missed it and child DNS was dropped with `EPERM`. Found on the VM.

Verified on the GitHub Ubuntu VM:
- The parent connects directly to `9.9.9.9:443` (control).
- The child cannot connect to `9.9.9.9:443`, an address no lookup returned.
- The child looks up `example.com`, gets an address, and can connect to it.
- The earlier checks still pass: blocked names return `0.0.0.0`, a query to `8.8.8.8` is answered by the gateway, DNS over TLS is dropped, and blocked lookups become requests that approval unblocks.

Known limit, not closed:
- **Shared addresses.** A CDN address often serves many sites. An allowed lookup therefore allows connections to any site on that address, and a child who sends a blocked site's name in TLS SNI can reach it there. Closing this needs TLS SNI inspection, which is a separate design. Until then, IP-level allowance is a strong control against casual bypass, not a complete one for CDN-hosted sites.

## Session 8: server-name control for shared addresses

Design: a child's HTTPS connection is checked on its server name (SNI), which is sent in plain text, so nothing is decrypted. HTTP is checked on its Host header.

- **Redirect**: nftables sends a child's TCP 80 and 443 to a per-child proxy (`tls_port`, base 5401). UDP 443 (QUIC) is dropped for children, so browsers fall back to TCP where the check applies.
- **Decision** (`security/tls_proxy.py`): a connection is relayed only if all hold:
  - the destination address came from an allowed lookup of this child (the address store from Session 7)
  - the name came from an allowed lookup through this child's gateway, or a parent allow rule names it
  - the name is not blocked
  - the ClientHello has no encrypted server name (ECH)
- **Relay**: the original destination is read from connection tracking (`SO_ORIGINAL_DST`). Allowed connections are relayed unchanged. Refused connections are closed, and the name is recorded as a request.
- **Parsing**: truncated names and extensions are rejected, not returned as partial names. A review test found that a cut-off hello returned `exampl` as the server name. Partial names are never returned now.
- **Learning**: the resolver records a name when an allowed lookup returns addresses, for the clamped TTL.

Verified on the GitHub Ubuntu VM:
- The parent connects directly to `9.9.9.9:443` (control).
- The child's TLS handshake to `9.9.9.9` with name `example.com` is refused, because no lookup returned that address.
- The child's TLS handshake to `example.com`'s address with name `example.com` completes (TLS 1.3).
- The child's TLS handshake to the same address with name `tiktok.com` is refused. The address is allowed, the name was never looked up.
- The earlier checks still pass: blocked names resolve to `0.0.0.0`, DNS to `8.8.8.8` is answered by the gateway, and DNS over TLS is dropped.

Decisions for you to confirm:
- **ECH is refused for children.** Encrypted server names hide the real name, so the check cannot apply. Some sites may fail for children. The alternative is to allow ECH and decide on the public outer name, which weakens the control.
- **QUIC is dropped for children.** Browsers fall back to TCP, which costs some speed.

Known limits:
- **Connection reuse.** The check runs when a connection opens. A browser that reuses an open HTTP/2 connection for another site on the same address (connection coalescing) is not checked again. Browsers normally look up a new name before connecting, which the lookup check catches, but this is not proven for every browser.
- **Other ports.** Only TCP 80 and 443 are name-checked. Other ports are limited to the address allow sets.
- **Cost.** HTTPS and HTTP for children now go through a userspace proxy. Expect extra CPU and latency on a small device.
- **Linux only.** The proxy reads the original destination from netfilter.

## Session 9: testing the server-name control in a real browser

Goal: measure the two open weaknesses from Session 8 (ECH and QUIC decisions, connection reuse) before deciding whether to build the next option.

Outcome: **not measured yet.** Two blockers:

- **CI is not running.** GitHub refused every job with "recent account payments have failed or your spending limit needs to be increased." Pushes since then have not been tested on the VM. This needs a billing fix on the account.
- **Headless Chrome crashes** as the child account before loading any page (`chrome_crashpad_handler: --database is required`). A matrix of launch variants was added to the job but has not run. The crash is in the test harness, not the gateway.

Corrections to earlier notes:
- **IPv6 was not broken by the gateway.** An earlier note said IPv6 HTTPS failed for children. The VM has no global IPv6 address or default route, and the parent's own `curl -6` fails the same way. The redirect rules were fine; the environment had no IPv6 path.
- The IPv6 listeners on `::1` and the explicit `dnat ip6 to [::1]:port` rules are still the correct design. They are unverified end to end, because the VM has no IPv6 route to test them against.

Assessment so far (reasoning, not measured):
- **Connection reuse.** A browser normally resolves a host before it connects, and the gateway returns `0.0.0.0` for blocked hosts, so a blocked site is unlikely to be reached through a reused connection. Not measured, so not confirmed.
- **ECH refusal and QUIC drop.** These are usability costs (some sites may fail for children), not bypasses.

Decision not taken: the Session 9 criterion ("implement option 2 if the weakness increases significantly") can't be applied, because the weakness was not measured. Option 2 (the dashboard requests page) does not close any weakness in any case.

## Session 10: local end-to-end run (CI disabled)

CI is disabled manually (`gh workflow disable CI`) while the account's billing is unresolved. To keep testing, the gateway was run end to end in a privileged Ubuntu 24.04 container with real nftables rules and two child accounts. systemd is not available in the container, so the gateway was started by hand.

Results:
- Child lookup of `tiktok.com` (blocked by default) returns `0.0.0.0`. The parent's lookup resolves normally.
- A child's query sent to `8.8.8.8` is answered by the gateway with `0.0.0.0`.
- Child TLS to a looked-up address with a looked-up name completes (TLS 1.3).
- Child TLS to an address no lookup returned (`9.9.9.9`) is refused.
- Child TLS to a learned address with a name never looked up (`tiktok.com`) is refused.
- Parent connects directly to `9.9.9.9:443` (control).

Not covered locally: the systemd unit, the AppArmor and gateway interaction (covered by the earlier VM job), headless Chrome, IPv6, and connection reuse. The Chrome measurement and the Session 8 decisions still wait on CI.

## Session 11: browser measurement with CI re-enabled

CI was re-enabled after billing was restored. The live job now runs Playwright Chromium as the child account against the gateway, and the whole run is green.

Measured in a real browser (Chromium 1xx, child account, gateway with the Session 8 controls):
- **Allowed site (`example.com`):** loads, title "Example Domain".
- **Blocked site (`youtube.com`):** refused. DNS returns `0.0.0.0`, and the proxy refuses any connection that reaches it.
- **`cloudflare.com`:** the page did not load. Every connection to it was allowed by the gateway, so the cause is not known yet. This is not the ECH refusal, because no real ECH connection was seen.
- **Connection reuse:** not measured.
- **Real ECH refusal:** not measured. The advertised-config refusal is in place, but no real ECH connection occurred in the run.

Bugs the browser run exposed (all fixed, all covered by tests):
- **HTTPS record address hints.** Chrome connected to `ipv4hint` and `ipv6hint` addresses without an A lookup, and those addresses were never learned. The gateway now reads hints from HTTPS and SVCB records (RFC 9460).
- **GREASE ECH.** Chrome sends a random ECH extension on every connection. Treating any ECH hello as a refusal refused nearly all browser traffic. Only ECH that uses a config advertised in an allowed HTTPS record is refused now. Other ECH hellos are judged by their outer name.
- **IPv6 without a route.** With no IPv6 route on the host, the local proxy accepted a child's IPv6 connection and then failed upstream. Browsers saw a closed connection instead of a connect failure and did not fall back to IPv4. When the host has no IPv6 default route, children's IPv6 is now refused at the source.
- **IPv4-only ruleset.** It referenced allow sets it did not declare, so `nft` rejected the whole table. Now declared, and `nft -c` passes.
- **Chrome launch.** Google Chrome crashed in every launch variant on the runner before loading a page. Playwright's Chromium launches and is used instead.

Corrections:
- The Session 9 note that IPv6 was broken for children was wrong: the VM has no IPv6 route, and the parent's own `curl -6` fails too.
- The Session 8 note that refusing ECH was an acceptable cost was wrong as written: it refused all Chrome traffic (GREASE). The corrected rule refuses only real ECH.

Known limits:
- **ECH config ID collisions.** Config IDs are one byte, so a GREASE hello can collide with a learned ID and be refused (about 1 in 256 per learned config).
- **Real ECH is refused only when its config was learned through the gateway.** A config obtained another way is judged by its outer name, which is the public name, not the real one.

## Session 12: connection reuse and the cloudflare.com failure

Connection reuse (measured in Chromium as the child, same browser session):
- An allowed Google page (`www.google.com`) loaded, holding open connections to Google front ends.
- A background request from that page to blocked `youtube.com` failed.
- Navigating to `youtube.com` in the same session failed.
- The gateway log shows why: the browser looked up `youtube.com` itself, got `0.0.0.0`, and connected to that, which the proxy refused. It did not reuse the Google connection.
- Control: the parent, without the gateway, loaded all three.

`cloudflare.com`:
- The parent loads it (control), so the earlier child failures involved the gateway, not the site.
- Found and fixed a real defect while investigating: the 5-second connect timeout stayed on the upstream socket, so any relayed connection idle for 5 seconds was closed. HTTP/2 keeps connections open between requests. A regression test fails without the fix.
- The failure did not reproduce afterwards: 6 of 6 loads as the child and 6 of 6 as the parent in one run. One failing run happened with the timeout fix already in place, so the fix is not proven to be the cure. The cause of the earlier failures is not known.

Decision on option 2 (Session 9 rule: build it if the measured weakness is significant):
- No significant weakness was measured. A blocked site stayed blocked in a real browser, including through an open connection to the same front ends.
- Option 2 was not started.

Still not measured:
- A real ECH connection (no site in the runs used one).
- Long sessions (HTTP/2 connections held for minutes), beyond the regression test.

## Session 13: parent password policy

Requirement from the user: the parent password must be at least 14 characters and include an upper-case letter, a lower-case letter, a number and a special character.

- `models.py`: `MIN_PARENT_PASSWORD_LENGTH = 14` and `parent_password_problems()`. Character classes are ASCII (`A-Z`, `a-z`, `0-9`, `string.punctuation`), so accented letters do not count as special characters. The function returns the rules a password fails, and the messages never echo the password.
- Enforced where the parent password is set: the interactive installer (step 5 retries until it complies) and the non-interactive flags (`install --non-interactive`, `autoinstall`, and `build-autoinstall-iso.sh`, which all go through the same parser).
- Not enforced in `ParentAccount.validate()`. Policy loads call `validate()` (`config.py`), and an older install with a shorter parent password in its file would then fail to load.
- Child passwords keep the 8-character minimum.
- Tests: `tests/test_models.py` (each rule, boundary length, non-ASCII) and `tests/test_installer.py` (non-interactive rejection and acceptance, interactive retry). 130 passed, 4 skipped locally.

**Gap (closed in Session 14):** the rule applied only when the installer set the password.

## Session 14: parent password rules on every password change

Requirement from the user: the parent's rules must also apply when the parent changes or resets the password, not only at install time.

Mechanism: the PAM `passwd` service, which `passwd`, `sudo passwd` and desktop password dialogs all use.
- `security/password_policy.py` writes a managed block to `/etc/pam.d/passwd`, before `@include common-password`. It has one `pam_succeed_if` line per child and then `pam_pwquality.so` (`minlen=14`, one upper, one lower, one digit, one other character; `enforce_for_root`).
- Children are named with `user = NAME`. The first version used `ingroup family-children`, but `ingroup` checks the caller's groups, not the account being changed. Root setting a child's password was then held to the parent rules. The Docker run below showed this, and a unit test now checks that the block has no `ingroup`.
- The block is regenerated on every apply, so child add and remove are covered. Usernames are checked against the account-name pattern before they are written.
- `libpam-pwquality` is installed with apt if missing. If it cannot be installed, the warning is recorded.
- `family-ctl verify` has a new live check, "Parent password rules enforced by PAM".

Evidence (Ubuntu 24.04 container, real `passwd` in a pty, scripts kept in the scratchpad):
- Parent changes own password to `Weak1!`: refused (shorter than 14).
- Parent changes to 14+ characters with no special character: refused.
- Parent changes to `Correct-Horse-42-Battery`: accepted.
- Root runs `passwd parent` with a weak password: refused.
- Root runs `passwd kid` with `abc`: accepted (child exempt). Child changes own password: accepted.
- A child still gets Ubuntu's default 8-character check (from `common-password`). That is unchanged by this session, and a 1-character child password is still refused.
- `tests/integration/test_linux_provisioning.py::test_parent_password_rules_refuse_a_weak_change` passes as root in the same container (`FAMILY_LINUX_INTEGRATION=1`, `pamtester`). The `linux-integration` CI job installs `pamtester` and `libpam-pwquality`, so the test runs there instead of skipping.

Limits:
- `ocredit` counts any non-alphanumeric character, including a space. The installer's check (ASCII punctuation only) is stricter, so the two differ only for a space as the special character.
- Only the `passwd` PAM service is covered. `chpasswd` (used by the provisioner) and any other PAM service are not.
- Ubuntu's stock `pam_pwquality` settings for children remain as they were.

## Session 15: snap installs need the parent's password

Requirement from the user: children can use Ubuntu's app store (snap), and each child attempt to install must prompt for the parent's account to authorise it.

Mechanism: PolicyKit, which snapd checks before it installs, updates or removes a snap. The stock policy (`/usr/share/polkit-1/actions/io.snapcraft.snapd.policy`, from the snapd package) is `auth_admin_keep` for an active session. That remembers an authorisation for several minutes, so later attempts would not prompt.
- `security/snap_policy.py` writes `/etc/polkit-1/rules.d/50-family-linux-snap.rules`. For child accounts it returns `AUTH_ADMIN` for `io.snapcraft.snapd.manage` and `manage-interfaces`, so every attempt asks for admin authentication and nothing is kept. Children are named in the rule, as with the PAM rule, not by group.
- The only administrator is the parent, so the prompt takes the parent's password. Ubuntu's base image includes an extra `ubuntu` admin user; the test below removes it, and a Family Linux install does not create one.
- snapd is installed if missing (apt). The rule is written on every apply.
- AppGuard now also reads snapd's desktop directory (`/var/lib/snapd/desktop/applications`). Unapproved snap apps are hidden like other apps. Approved snap apps are not wrapped in `aa-exec`, because snapd already confines them.

Visibility follows approval, in both directions (a bug fixed in this session):
- Before, an app hidden at one apply kept its hidden override. Approving it later did not make it visible. Overrides now carry a marker line. An approved app's managed override is removed. Overrides without the marker are not touched.
- Overrides for apps that are no longer installed are removed.
- AppGuard also reads flatpak's system exports (`/var/lib/flatpak/exports/share/applications`).
- Provisioning sets the parent's home to `0700`. Before, Ubuntu's default `0750` kept it private from children, but this makes the rule explicit.

Answer to "can apps the parent installs be invisible to the child unless the child has them?": yes. Visibility is decided by the child's approved list, not by who installed the app.
- User-level installs in the parent's home (`~/.local/share/applications`, `~/.local/share/flatpak`, `~/.local/bin`) are invisible and unusable from the child's account. The child is denied access to the parent's home (tested: `Permission denied`).
- System-wide installs (apt, snap, system flatpak) are visible to every account, so the child's menu hides them unless they are approved for that child.
- `family-ctl verify` has a live check for the rule.

Evidence (Ubuntu 24.04 container, real polkitd, a polkit agent on the child's terminal, snapd's policy file):
- Without an agent, the child's request is refused (`rc=2`, authentication required).
- With the agent, the prompt says "Authenticating as: parent", and the parent's password authorises the request (`rc=0`).
- A second request with no prompt allowed is refused (`rc=2`), so nothing is remembered.
- A third request prompts for the parent again and is authorised.

Limits:
- The container session is not an active desktop session, so polkit's default there is already `auth_admin`. The run shows that every attempt prompts. It does not show that the rule overrides the `auth_admin_keep` default for an active session. That needs a real desktop session and is not yet tested.
- Decision (parent's, this session): authorising an install only installs. It does not approve the app for the child.
- `security/desktop_refresh.py` and a systemd path unit (`family-appguard.path`) re-apply approvals when apt, snapd or flatpak adds or removes a desktop entry. A new app is therefore hidden from the child as soon as it is installed, until the parent approves it. Tested in the container by running the refresh directly. The path unit itself has not been run under systemd here.
- Snap's own confinement applies to these apps, not the family AppArmor profile.
- Not tested: the store download itself, snap refreshes that run without a user request, and the snap store login (`io.snapcraft.snapd.login`, also `auth_admin_keep`).

## Session 16: arm64 install ISO and VirtualBox appliance

Requests from the user: check whether the build works in VirtualBox on an M4 MacBook, build an ISO that supports arm64, and build a pre-configured VirtualBox VM file.

What was built:
- `scripts/build-autoinstall-iso.sh` repacks the official Ubuntu 24.04.5 live-server ISO for arm64 (the default on Apple silicon) or amd64. It checks the image against Ubuntu's `SHA256SUMS`, adds the autoinstall and a serial console to the boot menu, and keeps the original boot records (`xorriso -boot_image any replay`).
- The ISO payload is the source, the policy (no passwords), the first-boot unit, and a `family-ctl` wrapper. The autoinstall installs `ubuntu-desktop-minimal`.
- `family-linux-firstboot.service` runs the full apply once, after cloud-init has created the child accounts, then writes `/var/lib/family-linux/firstboot.done`.
- `scripts/build-virtualbox-vm.sh` builds the ISO, creates a VirtualBox VM, installs headless, waits for the first-boot apply on the serial log, shuts down with the ACPI button, and exports an `.ova`.

Defects found by installing for real (QEMU on Apple silicon, then VirtualBox 7.2.20), all fixed:
1. **Logins failed on Python 3.13+.** The autoinstall password hash fell back to a hex SHA-512 digest when `crypt` was missing, which is not a crypt string. Added `provisioner/sha512crypt.py`, checked against glibc vectors from Ubuntu 24.04.
2. **Install aborted with a child account.** Late commands ran `usermod` on children, but cloud-init creates them on first boot. Removed; the first-boot apply sets the group and home permissions.
3. **First-boot unit setting ignored.** `StartLimitIntervalSec` was under `[Service]`; moved to `[Unit]`.
4. **Browser policies missing with no children.** They were written only when a child existed. Now always written.
5. **Services could not import the package.** Only the first-boot unit had `PYTHONPATH`; `family-dnsd` restarted in a loop. A `.pth` file in `/usr/lib/python3/dist-packages` now points to `/opt/family-linux/src`.
6. **Child web rules lost after a reboot (fail open).** The `inet family_linux` table was loaded once with `nft -f` and is not persistent. `family-dnsd` now loads it in `ExecStartPre`, so every start (and boot) restores it. If the gateway stops, the redirect stays and the child has no DNS (fail closed). CI never rebooted, so it did not catch this.
7. **Children hidden on the login screen.** AccountsService hides accounts whose shell is not in `/etc/shells`. The child shell (`nologin`) is now listed there.
8. **Exported disks with empty firmware entries.** The disk now also has the removable-media boot path (`EFI/BOOT/BOOTAA64.EFI`).
9. **First boot silently skipped.** Ordering the first-boot unit after `cloud-final.service` made a cycle (`cloud-final` runs after `multi-user.target`, which waits for the unit). systemd logged "Job family-linux-firstboot.service/start deleted to break ordering cycle" and nothing was applied. Now ordered after `cloud-init.service`, which is where the accounts are created.
10. **Headless build could not see the first boot.** The serial console argument was before `---`, so the installed system did not keep it. It is now after `---` and last, so it is `/dev/console` on the installed system.
11. **Every boot waited about 2 minutes** on `systemd-networkd-wait-online`, because the autoinstall used networkd while the desktop uses NetworkManager. The autoinstall now sets `renderer: NetworkManager` and disables the networkd wait. Not yet confirmed in an install.

Reboot check (appliance VM, fixes 5-7 built in, fix 9 applied by hand): after `sudo reboot`, the `inet family_linux` table was back, `family-dnsd` was active, and the first-boot unit was skipped by its marker.

Evidence (VirtualBox 7.2.20 on this M4 Mac, arm64 VM, before fixes 5-7 were built into the ISO and then applied by hand):
- The ISO boots in VirtualBox and the install runs unattended. The installed system boots from the disk with the ISO removed.
- The first boot applied the policy (23 actions). `family-ctl verify`: all baseline checks passed.
- Child web filtering: after `family-ctl web block youtube.com --child kid`, the child resolves `youtube.com` to `0.0.0.0`, the parent gets the real address, and the child still resolves `wikipedia.org`.
- The child signs in to the GNOME desktop with the `nologin` shell (open item 5 answered).
- ACPI shutdown works (about 70 seconds).

Limits:
- Serial input does not reach the guest on the VirtualBox ARM VM (output works). The checks above used the VM's screen and virtual keyboard.
- The appliance holds the parent password given at build time. Build it with your own password; an appliance built with a known password should not be shared.
- Every import of the same appliance has the same machine ID.
- The amd64 ISO and appliance paths have not been run.
- The parent rule applies to `passwd`. A password change forced at login (expired password) uses the login service's stack, which does not include the parent rule.

## Open items, in priority order

1. Watch for the intermittent `cloudflare.com` failure in later runs; the repeat loads in CI will show it if it returns (Session 12).
2. Measure a real ECH site once one is found, to see what the real-ECH refusal costs.
3. Dashboard page for web requests (API exists).
4. Terminals and interpreters outside the profile: file-manager "open terminal" and interpreter-based escape routes (see Session 5).
5. Child login path: answered in Session 16 (a child signs in to GNOME with the `nologin` shell).
6. Extend the VM job to launch each approved app under the profile (only `/bin/true`, `env`, and `cat` have been exercised).
7. Check browser policy on Ubuntu snap builds and move the policy to where snaps read it, if different.
8. Add a pre-apply plan (dry-run diff) and consider rollback.
9. Packaging: install the console scripts and systemd units.
10. Scrub or recreate backups that hold old plaintext passwords.
