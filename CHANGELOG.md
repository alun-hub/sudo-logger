# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.39.4] - 2026-07-16

Found while verifying v1.39.3 on a real host: an upgrade of `sudo-logger-client` deleted
its own ACK verification key and broke `sudo` system-wide. Not related to the v1.39.3 fix
itself — a separate, pre-existing packaging bug that this was the first upgrade to
actually trigger. **The official GoReleaser-built RPM/DEB releases (the actual GitHub
Release artifacts) were never affected** — this was specific to the local `rpmbuild`
path (`rpm/*.spec`), documented here for completeness and because the same pattern,
if ever copied into the release path, would be considerably worse for the server.

### Fixed
- **client/rpm**: `ack-verify.key` was marked `%ghost` in `rpm/sudo-logger-client.spec`. RPM erases `%ghost` files as part of *any* upgrade (the implicit erase-old-version step runs on every upgrade transaction, not just full removal) — not something `%config(noreplace)` protects against, since there's no payload to preserve. The agent has no way to re-fetch this key if it goes missing (`main.go:81` is a hard `log.Fatalf`), and it's provisioned once, manually, from the server's keypair. Confirmed on a real upgrade: `sudo-logger-agent` crash-looped on `load verify key: ... no such file or directory`, and `sudo` failed system-wide with `error initializing I/O plugin` for every user.
- **server/rpm**: same bug, worse — `rpm/sudo-logger-server.spec` marked *both* `ack-sign.key` (the private signing key) and `ack-verify.key` `%ghost`. Losing `ack-sign.key` on upgrade wouldn't have errored at all: the key-generation guard in `%post` only fires when the file is missing, so the next upgrade would have silently minted a brand new keypair, invalidating every already-distributed client's `ack-verify.key` fleet-wide with no visible symptom until ACKs started failing everywhere.
- Fixed by removing both files from `%files` entirely (not even `%ghost`), so rpm's own package-management erase logic never touches them regardless of upgrade/erase ordering. Cleanup on a genuine full uninstall (not an upgrade) is now handled explicitly in `%preun`, gated on `$1 -eq 0`. Verified with real upgrade cycles for both packages (not just build inspection, per the v1.39.3 lesson): installed, recorded the key's checksum, upgraded, confirmed the checksum was unchanged — for the client's manually-provisioned key and the server's `%post`-auto-generated keypair.
- `.goreleaser.yaml`'s `nfpm` config (the actual release-artifact path) never declared these files in its `contents:` list in the first place — already safe by omission — but gained explanatory comments so nobody adds them back without understanding the upgrade-erasure risk.

## [1.39.3] - 2026-07-16

v1.39.2's fix was inert on a real install — caught the same day by actually testing it against a live package transaction rather than trusting the packaging inspection that validated it before release.

### Fixed
- **client/rpm**: v1.39.2 shipped the `%_tmppath` redirect macro to `/etc/rpm/macros.d/macros.sudo-logger-tmppath`, which rpm 6 does not scan by default — confirmed empirically on Fedora 44 (every other vendor-shipped macro file on the system, `systemd-rpm-macros`, `selinux-policy`, etc., lives under `/usr/lib/rpm/macros.d`, none under `/etc/rpm/macros.d`). `%_tmppath` still evaluated to `/var/tmp` after installing 1.39.2, so the fix had no effect: a real `dnf install glances` on an upgraded host hit the exact `EXEC_BLOCK` the macro was meant to prevent, because `glances`'s own `%post` scriptlet still staged under `/var/tmp`. Moved to `/usr/lib/rpm/macros.d` (`%{_rpmmacrodir}`) in both packaging mechanisms.
- **client/rpm**: fixing the path above surfaced a second problem before it ever shipped — an unconditional `%_tmppath` redirect broke plain, non-root `rpmbuild` (e.g. a developer's own local package build), which also reads `%_tmppath` and has no access to the redirect target's root-only directory. The macro is now conditional on effective UID (`%{lua: ...}`, using rpm's embedded Lua and `posix.getprocessid().euid`): redirected only when running as root, since that's the only context the original sandbox collision could occur in — a non-root invocation was never affected by it. Verified both branches directly: `rpm --eval '%_tmppath'` returns `/var/tmp` unchanged as a regular user and `/var/lib/sudo-logger/rpm-tmp` under `sudo`, and a local non-root `rpmbuild` of this package succeeds again.
- This time verified with a real package install and `rpm --eval '%_tmppath'` against the installed macro under both root and non-root, not just inspecting the built package's contents and permissions as v1.39.2's testing did.
- Anyone who installed the v1.39.2 `sudo-logger-client` RPM should upgrade to this version — the underlying `noexec`/scriptlet issue described in v1.39.2's entry is still present until you do. The stray `/etc/rpm/macros.d/macros.sudo-logger-tmppath` file left behind by v1.39.2 is harmless and can be removed manually; it is not owned by this version's package.

## [1.39.2] - 2026-07-14

### Fixed
- **client/rpm**: the BPF sandbox's `noexec` rule on `/var/tmp` (meant to stop a copied-in forbidden binary from being executed under a fresh inode) also silently blocked RPM's own scriptlet execution — RPM stages every `%pre`/`%post`/`%preun`/`%postun`/`%posttrans` script under `%_tmppath` (`/var/tmp` by default) and execs it directly, which the sandbox's `bprm_check_security` hook treats identically to a user-copied forbidden binary. This could abort a package transaction mid-scriptlet, leaving `rpmdb` and SELinux policy state inconsistent — observed for real when an interrupted `selinux-policy-targeted` upgrade left duplicate `rpmdb` entries and a mislabeled agent binary, breaking `sudo` system-wide until manually recovered. Fixed by redirecting `%_tmppath` to a dedicated, root-only directory (`/var/lib/sudo-logger/rpm-tmp`, `0700`) that was never noexec-protected, rather than weakening the sandbox itself. An eBPF-level exemption for the package manager was considered and rejected: it would have required making the sandbox's exemption state inheritable across `fork()`, which the fork hook deliberately prevents ("even if the parent was the exempt leader"). Fixed in both packaging mechanisms: `rpm/sudo-logger-client.spec` (local `rpmbuild` path) and `.goreleaser.yaml`'s `nfpm` config (the actual GitHub Release RPM path, scoped `rpm`-only via `packager: rpm`) — not needed for the `deb` build, since dpkg's maintainer scripts run from `/var/lib/dpkg/info/` and never touch `/var/tmp`.

## [1.39.1] - 2026-07-12

An independent second security review of v1.39.0's changes (before it had been in the wild for even a day) found a real regression in that release's own fix. Caught and fixed immediately.

### Security
- **rpm/deb**: v1.39.0 separated the replay service onto its own `sudoreplay` OS user specifically so it couldn't read the log server's `ack-sign.key` via shared group membership — but granted that user `rwx` directly on the shared `/etc/sudo-logger` and `/var/log/sudoreplay` directories via ACL, with no sticky bit set. Under standard POSIX semantics, deleting or replacing a file only requires write+execute permission on its *containing directory*, not any permission on the file itself, unless the directory has the sticky bit — so this let `sudoreplay` delete and recreate `ack-sign.key`, `ca.crt`, `server.crt`/`.key`, or session recordings it had no business touching, even without ever having read access to them. Verified for real in a disposable container: with the bug present, `sudoreplay` could `rm` and replace `ack-sign.key` with attacker-controlled content; with the sticky bit added to both directories (`0770`/`0750` → `1770`/`1750`), the same operation is rejected with "Operation not permitted" while every legitimate `sudoreplay` operation (creating its own new config files, writing already-owned files, deleting files it created itself) continues to work unchanged. Fixed in both packaging mechanisms that produce these permissions: `rpm/sudo-logger-server.spec` (local `rpmbuild` path) and `.goreleaser.yaml`'s `nfpm` `contents:` (the actual GitHub Release RPM/DEB build path) — the latter also gained an explicit directory declaration for `/etc/sudo-logger` it was previously missing entirely, relying on nfpm's implicit (and differently-permissioned) parent-directory creation instead.
- Anyone who installed the v1.39.0 `sudo-logger-server`/`sudo-logger-replay` RPM or DEB packages should upgrade to this version. This does not affect Kubernetes/Helm deployments, which already isolated `ack-sign.key` to the log server container only.

## [1.39.0] - 2026-07-12

A full-project security/bug audit (C plugin, Go agent, log server, replay-server, frontend, infra/packaging) found no critical issues, 4 high-severity findings, 6 medium, and several low/info items. All fixed and verified — including a live redeploy to a production reference cluster, real spawned-process/signal testing for the cgroup fix, and a real self-signed-CA TLS handshake test (both correct- and wrong-hostname cases) for the admin API change.

### Security
- **server**: the JIT-approval REST API and the GDPR/audit `DELETE /api/sessions` endpoint were served on plain HTTP with a shared bearer token — anyone positioned to observe traffic to that port could capture the token and disable the approval gate or destroy audit evidence. The listener now serves TLS using the already-configured server certificate; the replay-server's proxy client verifies it via a CA-pinned, hostname-checked `crypto/tls` config (`-logserver-admin-ca`/`-logserver-admin-tls-name`, standard SNI-override — the same mechanism `curl --resolve` uses, no custom verification code), failing closed if either flag is missing. A `NetworkPolicy` restricting the admin port to the replay pod was added to both `k8s/` and the Helm chart as defense in depth.
- **replay**: `GET /api/siem-config` returned the real SIEM bearer/HEC token in plaintext to any caller with `config:read` — the OIDC client secret and approval webhook secret were already masked this way, this endpoint wasn't. Masked on GET, with a PUT-side restore so saving the settings form without touching the token field doesn't overwrite the real value with the literal string `"***"`.
- **replay**: `--trusted-user-header` (proxy) auth mode fell through to the same code path used for a genuinely open/unauthenticated deployment whenever a request arrived without the trusted header — serving every user's session recordings to an anonymous caller on a misconfigured or bypassed reverse proxy. Now fails closed (401), matching the fail-closed principle already used elsewhere in the same function.
- **agent**: the eBPF/plugin divergence-detection mechanism (meant to catch a bypassed plugin, e.g. via `sudo.conf` tampering) matched incoming `SESSION_START`s against the oldest pending eBPF execve entry regardless of which sudo invocation it actually belonged to — a second, unrelated, properly-logged sudo call from the same user could "confirm away" a real bypass. Now matches by the exact PID the plugin reports.
- **agent**: the eBPF sandbox's protected-inode refresh (triggered when a protected file is atomically replaced, e.g. an editor save) deleted the old inode's protection before inserting the new one, leaving a brief window where neither was enforced. Order swapped to insert-then-delete.
- **agent**: the cgroup freeze mechanism only sent `SIGSTOP` to escaped processes that were their own process-group leader, leaving the other side of an escaped pipeline running unstopped. Now signals the whole process group (`kill(-pgid, ...)`, standard job-control semantics) — verified with a test that spawns real processes sharing a group and checks actual kernel state.
- **rpm/deb**: the replay service ran as the same OS user (`sudologger`) as the log server, so a compromise of replay's much larger, browser-facing attack surface could read the log server's `ack-sign.key` off disk via shared group membership and forge ACKs. Replay now runs as its own `sudoreplay` user; access to directories shared with the log server is granted via POSIX ACL rather than group membership, so it can't accidentally regain read access to that key.
- **server**: a single agent connection could buffer up to ~48GB before backpressure engaged (`diskQueue` capacity × the protocol's 1MB max message size); reduced to a still-generous bound (~2GB) given real chunk sizes are far smaller in practice.
- **frontend**: the sudoers editor's alias-line serialization didn't collapse embedded newlines the way rule lines already did, so a pasted multi-line alias value could inject an extra sudoers directive line.
- **install**: the one-liner installer silently proceeded with an unverified package whenever `cosign` wasn't installed. Now prompts for confirmation (or requires `--insecure`) instead, failing closed in the non-interactive `curl | bash` case.

### Fixed
- **plugin**: a chunk of session I/O silently disappeared on a `malloc` failure with no log line; a JSON-escaped field could silently drop a character (and anything after it, if it also needed escaping) near a buffer boundary instead of marking truncation the way command-line fields already do; a real socket read error (as opposed to clean EOF) wasn't marked as a dead agent connection.
- **replay**: a permission check defaulted to "allow" for the brief window before `/api/me` resolves on page load, letting admin-only nav tabs flash visible to a low-privilege user.
- **helm**: `logserver`/`replay` Deployments had no `securityContext` at all — every other deployment path (raw k8s manifests, Docker Compose) already runs this image non-root with dropped capabilities and a read-only rootfs; the chart now matches.
- **k8s**: switching the admin/health listener to TLS meant the kubelet's plain-HTTP liveness/readiness probes against it started failing (`400`) — caught during the real gnarg deployment for this release. Probes now specify `scheme: HTTPS`.
- **k8s**: `deploy-local.sh` regenerated random MinIO/PostgreSQL credentials on every run, which would desync from an already-initialized backing store on re-run. Now reuses the existing Secret's values if present, matching the Helm chart's existing pattern for the same problem.
- **server**: `sanitizeName` accepted dot-only names (`"."`, `".."`) at the regex level; downstream path builders already re-check this independently, but the source-level check is now consistent with its own doc comment.

### Documentation
- Corrected the documented SIEM OCSF event class (3002 → 3003, matching the actual code), `ack-sign.key`'s real file permissions in the security/operations chapters (`root:sudologger 0640`, not `root:root 0600`), systemd unit names in the developer guide's deployment checklist, a broken cross-reference link, a wrong source-file reference for `handleMetrics`, a leftover Swedish word in the sudo-logsrvd comparison doc, and the SIEM config example's schema (`transport`/`https.url`, not a flat `url:` key).
- Documented the `--strict-cert-host` shared-cert-vs-per-host-cert tradeoff explicitly, recommending per-host certs for new or high-assurance deployments — the off-by-default behavior itself is intentional (see `rpm/sudo-logger-server.spec`'s own changelog) and was not changed.

## [1.38.0] - 2026-07-11

### Security
- **setup.sh**: The hostname/IP argument was embedded unvalidated into a generated OpenSSL config file (`DNS.1 = $SERVER_HOSTNAME`). A value containing an embedded newline could inject additional config directives — e.g. an extra `DNS.2 = ...` SAN entry the caller didn't intend — since OpenSSL config files support arbitrary sections/directives and nothing stopped such content from reaching one. Now validated against a plain hostname/IP character set before use; anything else is rejected with a clear error.

## [1.37.0] - 2026-07-11

### Fixed
- **docs**: INSTALLATION.md sections 1 (RPM/DEB local storage) and 3 (Kubernetes distributed) never explained how to actually obtain a CA/server/client certificate — just "have these files ready", assuming prior PKI knowledge a true beginner wouldn't have. Added a shared "Preparing TLS Certificates and Signing Keys" section presenting bring-your-own-CA and generate-your-own as explicit, equal options, referenced from every place that used to just assume the reader already had these files.
- **docs**: Section 2's own cert-generation snippet (added in the v1.35.0 pass) generated a server certificate with no SAN at all — would fail modern TLS clients' hostname verification in practice. Never caught because that section's own test reused a pre-existing secret rather than generating one fresh from the documented snippet. Fixed to match the SAN handling used everywhere else.
- **docs**: `setup.sh` was written entirely in Swedish (this project's documented policy requires English), produced a nested `ca/server/client` PKI directory layout incompatible with `create-secret.sh`'s now-fixed flat convention, used RSA where everything else now uses ed25519, and hardcoded stale `v1.20.x` RPM filenames in its output. Rewritten: English, flat layout, ed25519, and points to INSTALLATION.md for the actual install steps instead of duplicating them.

### Documentation
- Consolidated installation instructions into INSTALLATION.md. README.md had accumulated three separate, partially-duplicate install walkthroughs of its own (a full "Installation" section, "Container deployment (Podman)", and "Kubernetes deployment"), several with content that had drifted from reality (stale `v1.20.x` RPM filenames, a claim that local-storage k8s has no replay-server manifest that was fixed in v1.35.0, `setup.sh` referenced as a prerequisite producing a layout `create-secret.sh` no longer accepts). Trimmed all three down to short pointers at INSTALLATION.md, keeping only genuinely non-duplicate reference content (storage-mode comparison, security notes, production-readiness checklist, the `migrate-sessions` tool).
- Added a new "Docker Compose" section to INSTALLATION.md (previously undocumented there at all), migrating the genuinely useful, still-accurate parts of README's now-removed Container deployment walkthrough. Existing sections 4-9 renumbered to 5-10 accordingly.

## [1.36.0] - 2026-07-11

### Added
- **helm**: `cert-manager` TLS mode now requests a Certificate from an existing Issuer/ClusterIssuer instead of being a documented-but-unimplemented option (must be a CA-backed issuer — this system needs the `ca.crt` a CA issuer populates, to verify agent client certs; an ACME issuer's Secret won't have one). Schema-validated via `helm template` only; no cert-manager installation was available to test a real issuance against.
- **helm**: JIT Approval is now wired into both local and distributed storage — a new `logserver-admin` ClusterIP Service, an auto-generated shared bearer token (persisted across upgrades), and a chart-rendered `approval-policy` ConfigMap (disabled by default, matching the server's own default). Verified for real: replay successfully reaches logserver's admin API through the new Service.
- **helm**: The bundled PostgreSQL connection now uses `sslmode=verify-full` instead of `disable`. PostgreSQL gets its own independent CA/cert pair (a separate trust domain from the agent-facing mTLS CA — purely internal plumbing), but does not require a client certificate back from logserver/replay (Bitnami's image enforces mutual TLS whenever a server-side CA file is configured, which those Go clients don't present; server TLS + client-side verify-full already gets an encrypted, server-authenticated connection without that). Verified for real via `pg_stat_ssl` that connections are actually encrypted, not just configured.

### Fixed
- **helm**: The chart's `appVersion` was left at 1.34.0 after the v1.35.0 release — same class of bug the chart already had once before.
- **helm**: PostgreSQL's TLS `copy-certs` init container (runs whenever `tls.enabled=true`, regardless of `volumePermissions.enabled`) uses a second Bitnami image (`bitnami/os-shell`) hit by the same 2025 image deprecation as the main postgresql/minio images — now pinned to `bitnamilegacy` like those.

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
