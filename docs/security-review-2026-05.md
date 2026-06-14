# sudo-logger — Security Review & Remediation Proposal

**Date:** 2026-05-29
**Scope:** Full codebase (C plugin, wire protocol, log server, replay server + frontend,
store layer, agent TLS/IPC/eBPF sandbox, SIEM sender) plus a red-team assessment of a
root-capable adversary on a monitored host.
**Method:** Manual code review grounded in the implementation; no live exploitation.

## Severity scale

| Level | Meaning |
|-------|---------|
| **Critical** | Remotely triggerable, breaks core audit guarantee (integrity/availability) with little effort. |
| **High** | Serious impact (DoS, audit forgery, silent evasion) but needs a credential, local access, or a specific config. |
| **Medium** | Real weakness requiring privilege, chaining, or non-default config; or a control that silently does not work. |
| **Low** | Hardening / defense-in-depth / robustness; limited or theoretical impact. |

---

## Summary table

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | `ParseChunk` uint32 overflow → log-server crash (DoS) | **High** | ✅ Fixed (PR #1) |
| 2 | Sandbox escape produces **no alert** (systemd-run / raw device / bind-mount / list gaps) | **High** | Open |
| 3 | Self-asserted `user`/`host` → audit-record forgery (default config) | **Medium** | Open |
| 4 | No authorization model: any viewer can alter security policy & purge logs | **Medium** | Open |
| 5 | No off-host agent-liveness anchor (silent host undetected) | **Medium** | Open |
| 6 | Sandbox feature flags are dead code (YAML toggles are no-ops) | **Medium** | Open |
| 7 | CSRF on state-changing config endpoints (cert upload worst) | **Medium** | Open |
| 8 | SSRF allow/blocklist is bypassable (DNS / encodings) | **Medium** | Open |
| 9 | Agent Unix-socket TOCTOU (create→chmod window) | **Low** | ✅ Fixed (PR #1) |
| 10 | SIEM HTTPS client cached by path, ignores cert content change | **Low** | Open |
| 11 | `GetRiskCache`/`SaveRiskCache` path built without traversal guard | **Low** | Open |
| 12 | Redaction is per-chunk best-effort (secrets split across chunks leak) | **Low** | Open |
| 13 | Terminal-escape injection into replay info banner (cosmetic) | **Low** | Open |
| 14 | Plugin `\uXXXX` JSON unescape lacks hex validation / surrogates | **Low** | Open |

---

## Fixed this session

### 1 — `ParseChunk` integer overflow → remote DoS  *(High, fixed PR #1)*
**Problem (plain):** A chunk message carries a 4-byte "data length". The bounds check
added `21 + length` in 32-bit math, which *wraps around* for a length near 4 billion,
so the check passed when it should have failed. The server then either tried to allocate
~4 GB or sliced past the buffer and **crashed**. Anyone holding a valid client certificate
(i.e. any compromised monitored host) could crash the central log server with one message
— knocking out audit logging for the whole fleet.
**Solution (done):** Compare in 64-bit space (`uint64(dlen) > uint64(len(payload))-21`).
Added regression tests. *Consider also adding `recover()` around the per-connection handler
so no single message can ever take the process down.*

### 9 — Agent socket TOCTOU  *(Low, fixed PR #1)*
**Problem:** The plugin socket was created first and `chmod 0600` second, leaving a brief
window where a local non-root user could connect and inject/read session data.
**Solution (done):** Create the socket with `0600` atomically via `umask`; keep `chmod` as
a fallback.

---

## Open findings — proposals

### 2 — Sandbox escape is silent  *(High)*
**Problem (plain):** The sandbox is a **deny-list** (protected inodes, process names, and 3
capabilities) enforced by eBPF-LSM hooks. A session running as full root keeps almost all
capabilities and can still talk to unconfined root daemons. Several escapes bypass the model
entirely **and trigger no `SANDBOX_VIOLATION` alert** — which defeats the tool's value as a
tripwire:
- **systemd-run / D-Bus:** ask PID 1 to spawn the payload. It is not a descendant of a
  sandboxed PID and lands in a new cgroup, so every hook short-circuits on `!in_sandbox_pid()`.
- **Raw block device:** `mknod` a disk node in unprotected `/tmp` (CAP_MKNOD retained) and
  `dd` to it — writes below the VFS, so the inode hooks never fire.
- **Bind-mount over an unprotected parent** (e.g. `/etc` itself is not protected, only
  `/etc/*`) shadows protected files with fresh, writable inodes.
- **Plain list gaps:** any root-equivalent path not enumerated (verify `/root/.ssh`,
  `/etc/cron.d`, `/etc/systemd/system`, `/etc/ld.so.preload`).

**Solution (proposed):** Treat the sandbox as a *detection* layer first, *containment*
second, and close both:
- **Detection:** add a coarse "sandboxed process did something privileged outside the
  protected set" signal — e.g. alert when a sandboxed PID opens `/run/systemd/private` or
  the system D-Bus socket, calls `mount`/`mknod`, or creates a block/char device. These are
  rare in normal admin work and high-signal.
- **Containment (optional, breaks some workflows):** drop a capability bounding set for the
  session (at minimum CAP_MKNOD, CAP_SYS_RAWIO, CAP_SYS_ADMIN, CAP_NET_RAW), and recognise
  that the systemd-run vector cannot be closed per-process — it needs the spawned scope
  cgroup to be re-sandboxed or the bus socket denied.
- Document explicitly that the sandbox does **not** contain a determined root user; its job
  is to make tampering loud, not impossible.

### 3 — Self-asserted `user`/`host`  *(Medium)*
**Problem (plain):** With `-strict-cert-host` off (the default), the server trusts the
`user` and `host` the agent puts in `SESSION_START`. A compromised host can submit audit
records attributed to any user on any host — forging or framing.
**Solution (proposed):** Make `-strict-cert-host` the default (per-machine client certs),
or at minimum stamp every record with the certificate-derived identity and visibly flag
"host unverified" in the UI when the claimed host does not match the cert.

### 4 — No authorization model  *(Medium)*
**Problem (plain):** Auth is all-or-nothing (optional Basic Auth / proxy header). Any
authenticated viewer can `PUT` the sandbox policy, blocked-users, risk rules, SIEM config,
and **retention** — setting retention low purges sessions via `RemoveAll`, destroying
evidence.
**Solution (proposed):** Introduce two roles — read-only *auditor* and *admin* — and gate
all state-changing endpoints behind admin. Until then, document that the replay server must
sit behind a proxy that restricts write methods to administrators.

### 5 — No off-host agent-liveness anchor  *(Medium)*
**Problem (plain):** The server only knows a host exists when an agent opens a session. If
an agent stops, the host simply goes silent — indistinguishable from "nobody ran sudo".
(Disabling the agent is itself a logged sudo command, so this is not a full blind spot, but
a robust audit system should also alarm on silence.)
**Solution (proposed):** The agent already polls the server every 60 s for `sandbox.yaml`.
Have the server record a per-host "last seen" from those polls and alert when a known host
exceeds a threshold. No new transport needed; it reuses the existing check-in.

### 6 — Sandbox feature flags are dead code  *(Medium)*
**Problem (plain):** Go writes `deny_netlink / deny_mount / deny_ptrace / deny_cap_*` into
the `sandbox_config` BPF map (`sandbox.go:360-365`), but **no BPF hook ever reads it** —
`cfg_enabled()` is defined (`sandbox.bpf.c:224`) but never called. The hooks enforce
unconditionally (caps, mount) or with hardcoded logic (netlink). So the `sandbox.yaml`
toggles are silently no-ops; an operator who sets `deny_mount: false` still has it enforced,
and vice versa. The config does not reflect reality.
**Solution (proposed):** Either (a) call `cfg_enabled(CFG_...)` at the top of each gated
hook so the YAML toggle works, or (b) remove the flags from the schema and document that the
behaviour is hardcoded. (a) is preferable for operability.

### 7 — CSRF on config endpoints  *(Medium)*
**Problem (plain):** State-changing endpoints have no CSRF protection. JSON `PUT`s get some
protection from CORS preflight, but `POST /api/siem-cert` accepts `multipart/form-data` — a
simple cross-origin form can make an authenticated admin's browser upload a file to
`/etc/sudo-logger/`.
**Solution (proposed):** Require a CSRF token (or validate `Origin`/`Sec-Fetch-Site`) on all
non-GET endpoints, and require a non-simple content type for the cert upload.

### 8 — Bypassable SSRF protection  *(Medium)*
**Problem (plain):** The SIEM HTTPS sender blocks SSRF by string-matching a few hostnames
(`169.254.169.254`, `localhost`, …). It never resolves the name, so a DNS record pointing at
an internal IP (or a decimal/alternate-encoding IP, or other private ranges) bypasses it.
Combined with #4, a low-privilege user could redirect session data internally.
**Solution (proposed):** Resolve the destination and validate the actual IP against
loopback/link-local/RFC-1918 ranges, or use an allow-list of approved SIEM hosts. TLS
verification itself is already correct.

### 10 — SIEM client cached by path  *(Low)*
**Problem:** The HTTPS client is cached by certificate *file paths*. Rotating a cert (or
re-uploading with the same name) does not take effect until restart.
**Solution:** Key the cache on file content hash / mtime, or rebuild on config change.

### 11 — Risk-cache path lacks traversal guard  *(Low)*
**Problem:** `GetRiskCache`/`SaveRiskCache` build `filepath.Join(LogDir, tsid)` without the
`resolveSessionDir` validation used elsewhere. Today `tsid` is server-internal, so it is not
currently reachable, but it is missing defense-in-depth.
**Solution:** Route these through `resolveSessionDir` like the other read paths.

### 12 — Per-chunk redaction  *(Low)*
**Problem:** Secret redaction runs per chunk; a secret split across two chunks is not masked,
so it can land in the recording.
**Solution:** Document the limitation; optionally add a small sliding-window buffer for the
output stream. (No ReDoS risk — Go's RE2 is linear.)

### 13 — Terminal-escape injection in replay banner  *(Low)*
**Problem:** Session metadata is written raw into the xterm.js banner, so crafted escape
sequences in a command/user/host can manipulate the rendered banner (cosmetic only — no XSS;
the DOM rendering elsewhere correctly uses `textContent`).
**Solution:** Strip control bytes from metadata before writing it to the banner.

### 14 — Plugin `\uXXXX` unescape  *(Low)*
**Problem:** `json_unescape_into` does not validate hex digits and ignores surrogate pairs.
Input is server-controlled (the disclaimer), so impact is robustness, not security.
**Solution:** Validate hex and handle surrogate pairs, or restrict the disclaimer to a safe
character set.

---

## Recommended order of work

1. **#6** (dead flags) and **#5** (liveness) — small, high-value, no workflow impact.
2. **#3** (strict-cert default) and **#4** (roles) — restore audit integrity guarantees.
3. **#7 / #8** — web-facing hardening.
4. **#2** — reframe + add high-signal sandbox detections (the containment part is a product
   decision).
5. Low items as cleanup.

> The product is solid *while the agent is alive*: fail-closed sudo, the synchronous
> `SESSION_START → SERVER_READY` gate (a command is committed to the server before it runs),
> eBPF divergence witnessing, and INCOMPLETE-on-drop. The gaps above are about (a) detecting
> a silenced/degraded agent off-host, and (b) being honest that the sandbox is a loud
> tripwire, not a jail for root.
