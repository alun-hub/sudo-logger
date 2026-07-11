# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.35.0] - 2026-07-11

### Fixed
- **ci**: The published `sudo_logger_plugin.so` was built directly on the `ubuntu-24.04` release runner (glibc 2.39), which made it require `GLIBC_2.38` at load time — a version none of the documented minimum-supported distros (RHEL/Rocky 9, Ubuntu 22.04, Debian 12) actually have. `sudo` refused to load the plugin at all there (`GLIBC_2.38 not found`), making the client completely unusable on any currently-supported LTS/stable release except very recent ones. The C plugin now builds inside a Rocky Linux 9 (glibc 2.34) container before GoReleaser runs, restoring compatibility with every previously-documented minimum.
- **install**: The one-liner installer (`scripts/install.sh`) constructed RPM download filenames using the traditional `x86_64`/`aarch64` arch suffixes, but the actual release assets are named after the Go `amd64`/`arm64` values for every package format. Every RPM download 404'd, and cosign then tried (and failed) to verify the resulting "Not Found" page as a signed blob — which is what actually surfaced as a signature-verification error. The one-liner installer had never successfully installed an RPM package, on any architecture, until this fix.
- **server-pkg**: Three compounding bugs broke the manual RPM/DEB install walkthrough in `INSTALLATION.md` on any fresh system: `openssl` was never declared as a dependency, so the postinstall ACK-signing-key generation step failed silently (all output redirected to `/dev/null`) whenever it was missing; `/var/log/sudoreplay` was never created by the package, so the systemd unit's `ReadWritePaths` failed at startup on every fresh install; and the real release binaries are named `sudo-logger-server`/`sudo-logger-replay`, but the shipped systemd units expect `sudo-logserver`/`sudo-replay-server` — a naming mismatch that broke `systemctl start` outright. All three are fixed, and the postinstall scripts now warn loudly instead of silently if `openssl` is still missing.
- **helm**: The Helm chart shipped as a non-functional skeleton — no TLS material, no ACK-signing key, and no args at all on either Deployment, so `helm install` crash-looped immediately regardless of `storage.type`. Rebuilt with self-signed CA/cert generation and ACK-signing-key generation (both persisted across `helm upgrade`), full args/env wiring for local and distributed storage, and credential wiring into the bundled PostgreSQL/MinIO subcharts. Also pins those subcharts to `bitnamilegacy` images (Bitnami deprecated the free `bitnami/*` tags this chart's subchart versions pin in 2025), makes the logserver Service type configurable (`NodePort` default, since `ClusterIP` alone is unreachable from monitored hosts outside the cluster), and bumps the chart's stale `appVersion` (was silently pinned nine versions behind).
- **k8s**: The local-storage Kubernetes path (`kubectl apply -k k8s/`) never actually deployed a replay server and had a `volumeMounts`/`volumes` name mismatch that made the manifest schema-invalid — `kubectl apply` would have rejected it outright. Also fixes a kustomization that applied a placeholder secret template (invalid base64) directly, drifted `hmac.key`/`ack-sign.key` naming across several files, `deploy-local.sh --image` never patching `imagePullPolicy` (so a published image got stuck in `ErrImageNeverPull`), and the documented manual distributed-apply steps missing the approval-token Secret/ConfigMap that `deployment-distributed.yaml` requires.
- **docker**: The runtime image never installed `wget`, which every healthcheck in `docker-compose.yaml` depends on. The healthchecks could therefore never pass, so `sudo-replay-server` (which waits on `depends_on: condition: service_healthy`) never started even though `sudo-logserver` itself was running fine.

### Documentation
- Corrected the client's true minimum OS requirement and added a new "Kubernetes — Local Storage" section to `INSTALLATION.md`, among other install-doc accuracy fixes found while verifying every documented installation path against a real install.
- Extracted `SECURITY.md` from `CONTRIBUTING.md`.

## [1.34.0] - 2026-07-10

### Security
- **replay**: `isBootstrapMode` treated any `-htpasswd`-configured deployment with zero "modern" store users as first-run/open, serving every request as admin with no auth at all, regardless of the htpasswd file's contents. It now returns false whenever `-htpasswd` is set.
- **replay**: `-htpasswd` authentication had been silently non-functional — nothing parsed the htpasswd file's bcrypt hashes against a submitted password. Restored (new `htpasswd.go`, load/parse/reload), with `SIGHUP` reload wired up as the flag's help text already documented.
- **replay**: An htpasswd-authenticated user with no matching store entry stayed at the default viewer role. `-htpasswd` predates per-user roles and was always a flat, single-tier auth mode, so such users now get admin, matching that history.

### Added
- **ci**: The existing 14-test container-based end-to-end suite (`tests/run-system-test.sh`) now runs in CI on every release tag, instead of only locally.

## [1.33.0] - 2026-07-07

### Fixed
- **agent**: A path listed in more than one of the sandbox's `protect.files`, `protect.forbidden`, or `protect.noexec` lists was silently dropped from every list after the first, because a single dedup set was shared across all three resolution loops. Each list now has its own set.
- **agent**: The idle-timeout session watcher could send its termination signal into an already-frozen cgroup — leaving the session stuck the same way TTL/freeze-timeout termination could before v1.32.0 — since it never called the freeze-disarming guard added in that release. It now does.

### Documentation
- Documented the sandbox's `CAP_MAC_ADMIN`/`CAP_SYS_RAWIO`/`CAP_SYS_BOOT` capability denials in the README and `sandbox.yaml(5)` (previously only the original three were listed).
- Added the missing "Sandbox (LSM) subsystem" section to `sudo-logger-agent(8)` (the page claimed "four subsystems" but only documented three) and corrected its stale version stamp.

### Removed
- Unused `loadRules()` function and its dedicated tests (superseded by `loadRulesFromText`); abandoned AI-tool scaffolding files left over from an earlier review pass.

## [1.32.0] - 2026-07-07

### Fixed
- **agent**: A session ending via TTL expiry or the freeze-timeout watcher could be left permanently stuck in a frozen cgroup — unkillable by Ctrl-C or a plain `kill`, since a frozen cgroup delivers no signal until thawed — if a concurrent server-connection-lost freeze (`markDead`) or the post-session lingering-process watcher (`lingerCgroup`) re-froze the cgroup after the watcher's own unfreeze but before the terminating signal was actually processed. Both termination watchers now mark the cgroup as terminating before unfreezing, which permanently disarms any later freeze attempt for that session.

## [1.31.0] - 2026-07-07

### Fixed
- **replay**: A session whose cast has a header but no playback events (a genuinely I/O-less command, or a stale in-progress placeholder that never got a real recording) showed the terminal player's generic crash icon instead of the session content. Now shows "No output was recorded for this session."

## [1.30.0] - 2026-07-07

### Changed
- **replay**: The OIDC step-up re-authentication flow (sudoers/sandbox push) now returns to the page you stepped up from (e.g. `/config/sandbox`) instead of always landing on the session list.
- **replay**: The step-up re-authentication TTL is now admin-configurable — **Config → System Auth → "Step-up Re-authentication TTL"** — instead of a fixed 10 minutes.

### Documentation
- Documented the A-1/A-3 push protections (diff confirmation, step-up re-authentication, audit/SIEM notifications, sandbox-weakening detection) across the README, configuration guide, API reference, and troubleshooting chapter.
- Fixed several stale documentation entries found in the process: the `/api/sudoers/config` API reference described an endpoint shape that no longer exists, a claim that config writes are never separately audit-logged, and a frontend API/test-file inventory in the developer guide that predated several files being split out.

## [1.29.0] - 2026-07-07

### Security
- **agent**: A server-pushed `sandbox.yaml` reload that silently removes protection the previous config had (a feature flag disabled, or a previously-protected path/process/systemd-ipc-socket/forbidden-binary/noexec-dir no longer covered) now logs a distinctly-marked warning instead of applying silently.
- **replay**: Every sudoers/sandbox config push now writes an audit-log line with actor and a line-diff summary, and forwards a `sudoers_config_push`/`sandbox_config_push` event through the existing SIEM/audit-forwarding mechanism.
- **replay**: The sudoers and sandbox editors now show a diff of what's about to change and require an explicit confirmation before pushing, instead of applying on click.
- **replay**: Sudoers/sandbox pushes now require a step-up re-authentication within the last 10 minutes (password re-entry for local auth, forced IdP re-login via `prompt=login` for OIDC) — a passively stolen session cookie is no longer sufficient on its own. No-op (documented) for proxy-mode or open (no local passwords configured) deployments, where there's no independent credential to re-check.

## [1.28.0] - 2026-07-06

### Changed
- **server**: Extracted the duplicated session-open tail (open session, log, send `SERVER_READY`) shared by the session-start and challenge-response paths into a single helper.
- **server, replay**: Deduplicated agent-host validation and log-string sanitization into a shared `internal/util` package; unified the session divergence-status default.
- **agent**: Split the 693-line plugin-connection handler into a `sessionConn` type with focused methods (freeze/idle/TTL watches, sender, reader-ack, heartbeat, handshake) instead of one large closure-heavy function.
- **agent**: Split `ebpf.go` into `ebpf.go` (subsystem lifecycle), `ebpf_events.go` (ring-buffer event handling), `ebpf_pkexec.go` (polkit session tracking), and `ebpf_watch.go` (cgroup/inotify watch loop).
- **plugin**: Split `plugin_open` into `parse_user_info`, `parse_command_info`, `parse_settings`, `build_session_start_json`, and `run_handshake` helpers.
- **store**: Split `distributed.go` and `local.go` into per-domain files (sessions, policy, users/roles, approval, sudoers) instead of one large file per backend.

No functional or behavioral changes — this release is a structural refactor for readability and maintainability, verified with the full test suite (including the race detector) and symbol-level diffs confirming no code was lost or duplicated.

## [1.27.0] - 2026-07-06

### Security
- **replay**: Fail closed instead of open when the auth-config store errors, rather than falling back to "no local passwords configured" behavior.
- **replay**: Removed `'unsafe-inline'` from the `script-src` CSP directive — the built UI has no inline scripts, so it was unnecessary XSS-defense weakening.
- **siem**: Replaced a substring-based SSRF denylist with resolved-IP range checks (blocks loopback/link-local/cloud-metadata addresses) applied to both the HTTPS and syslog transports; syslog previously had no destination check at all, and the old denylist missed addresses like `127.0.0.2` and DNS names that resolve to a blocked range.
- **store**: `DeleteSession` now writes (and fsyncs) the audit-log entry before removing a session, instead of treating the audit write as best-effort after deletion, so a failed audit write can no longer leave an untraceable deletion.
- **iolog**: Invalid UTF-8 bytes in recorded session data are now escaped from their raw byte value instead of being replaced with U+FFFD, preserving forensic byte-for-byte fidelity; a multi-byte character split across a chunk boundary is also reassembled correctly instead of being corrupted.
- **plugin**: Cleared the 30s socket receive timeout after a JIT-approval challenge response, so a long-running approval no longer aborts sudo with a spurious "no response from agent" error.
- **agent**: Gated the `SUDO_LOGGER_INSECURE_TEST` root-check bypass to test binaries only, so it can never fire in a production build even if the environment variable leaks into the unit file.
- **replay**: Fixed a risk-scoring bypass where an unterminated terminal title/hyperlink escape sequence anywhere in a session's output silently blinded content-based risk rules for the rest of that session (the raw session recording itself was never affected).

### Fixed
- **server**: The approval decision API now distinguishes a missing request (404) from a backend failure (500).
- **server**: Exemption host patterns support multiple wildcards instead of only a single `*`.
- **store**: The cleanup worker now actually stops when the store is closed; expired approval requests are purged on every cleanup pass regardless of retention-policy configuration.
- **store**: Session creation fails loudly on a tsid collision instead of silently continuing.
- **replay**: Consolidated cache invalidation so a rules/SIEM-config change no longer leaves the sudoers-hosts API serving stale data for up to a minute.
- **replay**: Session duration display no longer rounds a 0-second session up to "1m".
- **agent**: Extended the sandbox's insert-before-delete config-reload pattern to the remaining protected-inode sets, closing the last empty-map windows.

### Changed
- **agent**: Deduplicated the eBPF chunk/session-end wire encoders into the shared protocol package.
- **replay**: Extracted the duplicated viewer-ownership check into a shared helper.
- **replay**: Terminal-output sanitization for risk scoring now also strips OSC/DCS escape sequences, not just cursor/color codes.

## [1.26.0] - 2026-07-05

### Added
- **plugin**: Unit tests for getsockopt verification, safe TTY writing, and string sanitization.
- **plugin**: Auto-build and test execution in GitHub Actions CI workflow.
- **agent**: Unit tests for raw BPF event bounds checks and handleIO clamping.

### Changed
- **refactoring**: Structural modularization of the TCP session connection, local storage, replay handlers, and eBPF session streaming.

### Fixed
- **plugin**: Crash on `sudo -V` when convo/printf pointer is not initialized.
- **plugin**: Hardened peer verification via `getsockopt` `SO_PEERCRED` to verify agent is root.
- **plugin**: Safe ANSI SGR formatting sanitizer for TTY writes, escaping all other ESC sequences.
- **plugin**: Sanitized hostname and username before formatting session ID to prevent path traversal.
- **plugin**: Drained unsolicited warning and freeze socket frames to prevent framing desync.
- **agent**: Non-blocking heartbeat priority queue sends to prevent agent freezing on clogged socket.
- **agent**: Raw BPF event bounds check clamping in `handleIO` to prevent out-of-bounds panics.
- **agent**: Atomic sandboxes reloading with diff-based insert-then-delete map updates.
- **agent**: Refactored attach ladder using link helper slice.
- **agent**: Linger robust reading of `cgroup.procs` to prevent premature termination.
- **server**: Fail-closed database query error propagation in block policy and whitelist checks.
- **server**: Solved session data race in disk writer using atomic session pointer.
- **server**: JIT policy reload fail-closed recovery for database errors.
- **server**: Supported `max_session_duration` validation and Settings UI configuration.
- **server**: Prevented duplicate session start memory leaks and Slowloris resource exhaustion on health ports.

## [1.25.5] - 2026-07-03

### Fixed

- **ci:** Vendor `sudo_plugin.h` so the release pipeline no longer depends on
  a system package that doesn't exist on the Ubuntu runner, which had been
  causing the automated release build to fail

## [1.25.4] - 2026-07-03

### Security

- **replay:** Enforce RBAC permissions on the sudoers management API (list/read/write/delete) — previously reachable by any authenticated user regardless of role
- **replay:** Scope the session report to the caller's own sessions unless they hold the list-all permission, matching the session list API
- **replay:** Require a permission check on the host-listing API
- **server:** Restrict which config keys an agent may fetch over the wire to the small set it legitimately needs, preventing disclosure of unrelated server-side secrets
- **server:** Mask secret-looking text in a JIT approval justification before it is logged or forwarded to a notification webhook
- **server:** Sanitize user/host fields before writing them to the server log, preventing log-injection via control characters
- **agent:** Drop (rather than forward) a session chunk that fails to parse, so malformed data can never bypass the secret-redaction filter
- **store:** Add defense-in-depth path validation to the heartbeat storage layer

## [1.22.0] - 2026-04-25

### Added

- **replay:** Implement split-view and synchronized playback for TTY and Wayland
- **replay:** Add pop-out window and smart sync visibility for Wayland
- **replay:** Implement loading screen, fix pop-out layout, and enable pure Wayland playback
- **wayland:** Support multiple sequential GUI applications
- Add verify-integrity script for AI validation
- **replay:** Instant playback with progressive streaming (Release 13.1)

### Changed

- **shipper:** Implement smart batching to prevent freezes under high I/O

### Documentation

- Add GTK accessibility warning explanation to README
- Add AI reliability mandates
- Update developer configuration and reliability commands
- Align technical and operational documentation with Release 12 architecture
- **readme:** Correct stale constants and version numbers

### Fixed

- Require 2 consecutive heartbeat windows before declaring server alive
- Remove unfreeze from updateAck to prevent duplicate freeze banners
- **plugin:** Remove redundant banner write from terminal-reclaim
- **plugin:** Remove redundant FREEZE_MSG from monitor thread
- **shipper:** Close done before serverConnAlive=false to eliminate ghost banner
- **shipper:** Stability period for recovery, fix(plugin): terminal-reclaim cooldown
- **plugin:** JSON injection, cgroup path traversal, and protocol robustness
- Suppress GTK accessibility warnings in sudo sessions
- **replay:** Fix pop-out sync and enable pure Wayland playback
- **replay:** Fix infinite message loop and ensure stable frontend
- **replay:** Fix JS syntax error in template literals
- **replay:** Absolute fix for frontend syntax and logic
- **replay:** Ensure loading screen resets on session switch
- Make verify-integrity script more robust for Go internal packages
- **replay:** Ensure autoplay works for pure IMAGE sessions
- **replay:** Make IMAGE session detection robust to fix autoplay race condition
- **replay:** Final robust fix for IMAGE autoplay race condition
- **shipper:** Implement wait-on-drain to prevent premature freezes and 'incomplete' reports
- **shipper:** Replace unsafe channel closures with safe drain signal and increase bulk buffer (Release 6)
- **server:** Async ACK coalescing and final shipper tuning (Release 7)
- **server:** Implement asynchronous disk writer to handle high I/O bursts (Release 8)
- **shipper:** Use single bufio reader to prevent stream corruption during handshake
- **server:** Implement disk write batching and panic-free termination (Release 10)
- **server:** Protect shared network buffer with a mutex to prevent stream corruption (Release 11)
- Non-blocking server disk handoff and precise shipper write deadlines (Release 12)
- **plugin:** Add mutex to prevent race between ship_chunk and refresh_ack_cache
- **replay:** Implement streaming NDJSON architecture to handle large sessions (Release 13)
- **shipper:** Restore heartbeat dead-declaration to 2 missed (800 ms)

### Security

- Fix path traversal (VULN-001, VULN-003) and DoS (VULN-002)
- Fix path traversal in WAYLAND_DISPLAY and resource exhaustion in wayland-proxy
- Fix multiple critical vulnerabilities and regressions
- **server:** Implement bounded overflow and log sanitization (Release 14)

## [1.21.0] - 2026-04-20

### Added

- **ui:** Improve replay web UI accessibility and visual polish
- **gui:** Add Wayland proxy screen capture for GUI sudo sessions
- **distributed:** Implement ScreenFrameWriter/ScreenFrameStore for S3
- **replay:** Screen capture slideshow player for GUI sessions
- **shipper:** Config file replaces CLI flags; wayland toggle
- **selinux:** Bundle SELinux policy module in client RPM
- **wayland:** Force last-frame capture; configurable proxy_period
- **redaction:** Automatic secret masking before log transmission
- Implement automated session retention cleanup via Replay GUI
- Configurable disclaimer shown at sudo session start
- Disclaimer colour and \n/\t support
- Preserve NO_AT_BRIDGE in sudoers to suppress AT-SPI warnings
- Add idle_timeout to shipper — terminate sessions with no user input

### Changed

- **redaction:** Implement fast-path optimization for redactor

### Documentation

- Fix factual errors and improve structure in README and ARCHITECTURE
- Add AGENTS.md, JIT-TODO and code-review TODO
- Update developer guide with project context and fix instructions
- Update README for Wayland capture and shipper.conf config file
- **slides:** Add Wayland screen capture slide, move Ready to Deploy last
- Update README with surgical masking details
- Document idle_timeout in shipper.conf, README and man page

### Fixed

- **distributed:** Split multi-statement schema version upsert into two Exec calls
- **security:** Address CodeQL findings — log injection, SSRF, path injection
- **security:** Check raw TLS path for traversal before filepath.Clean
- **rpm:** Correct misplaced changelog date in replay spec (1.13.0 was Apr 06, should be Apr 05)
- **shipper:** Start wayland-proxy whenever WAYLAND_DISPLAY is set, not only when tty_path is empty
- **plugin:** Read WAYLAND_DISPLAY from /proc/self/environ, not user_env[]
- **selinux:** Allow sudo_shipper_t to exec wayland-proxy and connect to Wayland socket
- **client:** Install sudoers drop-in to preserve WAYLAND_DISPLAY through env_reset
- **shipper:** Run wayland-proxy as invoking user, not root
- **shipper:** Resolve wayland user IDs from XDG_RUNTIME_DIR, not NSS
- **selinux:** Allow setuid/setgid for wayland-proxy privilege drop
- **wayland:** Get invoking user UID/GID from sudo user_info[], not NSS
- **selinux:** Allow wayland-proxy to bind/unlink socket in /run/user/<uid>/
- **wayland:** Shipper creates proxy socket, passes fd to wayland-proxy
- **wayland:** Preserve proxy socket file after ln.Close()
- **wayland:** Connectto compositor + kill lingering proxy
- **service:** Allow wayland-proxy to connect to compositor socket
- **wayland:** Proxy socket in /run/user/<uid>/ for SELinux compatibility
- **wayland:** Protocol desync, mutex, linger mode, FD leak, plugin syslog
- **spec:** Add wayland-proxy to immutable chattr scriptlets
- **service:** Remove ProtectHome — breaks wayland-proxy /run/user access
- **config:** Accept legacy LOGSERVER key as alias for server
- **selinux:** Grant dac_override and dac_read_search to sudo_shipper_t
- **selinux:** Allow user_tmp_t file map/write and dri_device_t access
- **store:** Add JSON tags to ScreenFrameInfo struct
- **wayland-proxy:** Remove double lock in captureCommit
- **spec:** Correct changelog dates to silence RPM build warnings
- Warn user before idle timeout closes session
- Log idle warning failures and remove extra goroutine
- Resolve /dev/tty to actual PTY path for TTY banner writes
- **selinux:** Allow sudo_shipper_t to read /proc/<pid>/fd symlinks
- **selinux:** Allow sudo_shipper_t to write to user PTY devices
- Use yellow for idle termination banner, same as warning
- Stop watchdog goroutines when session ends via done channel

### Security

- Remediate CodeQL scanning alerts (SSRF, Path Traversal, Regex)
- Implement strict allow-list for TLS certificate paths (VULN-002)
- Sanitize user identity in session view logs (VULN-003)
- Harden SSRF protection and fix missing regex anchors (v2)
- Suppress CodeQL false positives with inline lgtm annotations

## [1.20.0] - 2026-04-14

### Changed

- Code review fixes — bug fixes, security hardening, deduplication

### Fixed

- **distributed:** Retry advisory lock on WatchSessions instead of blocking
- S2 S4 K4 K6 — TLS 1.3, payload limits, flag docs, schema versioning

## [1.19.4] - 2026-04-12

### Fixed

- **shipper:** Lower -freeze-timeout default from 5 min to 3 min
- **spec:** Correct bogus day-of-week in sudo-logger-client changelog

## [1.19.3] - 2026-04-12

### Fixed

- **client:** Prevent spurious SESSION_FREEZING on clean session end
- **replay:** OR command_base_any with content matching in matchesRule

## [1.19.2] - 2026-04-12

### Fixed

- **shipper:** Prevent spurious SESSION_FREEZING on clean session end

## [1.19.1] - 2026-04-12

### Fixed

- **freeze-banner:** Restore plugin FREEZE_MSG write as fallback

## [1.19.0] - 2026-04-12

### Documentation

- **architecture:** Add network-outage timeline to freeze section

### Fixed

- **freeze-banner:** Write FREEZE_MSG from shipper directly to TTY

## [1.18.0] - 2026-04-12

### Added

- **network-outage:** Distinguish network loss from shipper kill in replay UI

### Documentation

- **readme:** Document SESSION_ABANDON and freeze-timeout/shipper distinction
