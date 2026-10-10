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
- Installer: defaults removed. Prompts use `getpass`. Non-interactive runs require `--parent-pass` (min 8 characters). The child spec needs a password, and `split(":", 3)` keeps colons inside passwords.
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

## Open items, in priority order

1. Restore CI (billing), then run the Chrome launch matrix and the browser measurement (Session 9).
2. Confirm the Session 8 decisions (ECH refused, QUIC dropped) with the measurement results.
3. Dashboard page for web requests (API exists).
4. Terminals and interpreters outside the profile: file-manager "open terminal" and interpreter-based escape routes (see Session 5).
5. Child login path: the child's shell is `nologin`. Test that a desktop login still works for a child account (GDM or LightDM on a real session).
6. Extend the VM job to launch each approved app under the profile (only `/bin/true`, `env`, and `cat` have been exercised).
7. Check browser policy on Ubuntu snap builds and move the policy to where snaps read it, if different.
8. Add a pre-apply plan (dry-run diff) and consider rollback.
9. Packaging: install the console scripts and systemd units.
10. Scrub or recreate backups that hold old plaintext passwords.
