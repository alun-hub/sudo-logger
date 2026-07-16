# YAML Configuration Reference

This chapter documents the YAML file formats used to configure sudo-logger's
policy, scoring, sandbox, SIEM forwarding, and approval features.

---

## Risk rules (risk-rules.yaml)

### Overview

Risk rules assign numeric scores to sudo sessions based on what was run,
who ran it, and how the session ended. Scores from all matching rules are
added together and capped at 100. The total determines the session's risk level
displayed in the replay UI.

| Risk level | Score range |
|------------|-------------|
| Low | 0 – 24 |
| Medium | 25 – 49 |
| High | 50 – 74 |
| Critical | 75 – 100 |

**File path:** `/etc/sudo-logger/risk-rules.yaml` (configured via the replay
server `--rules` flag).

The file is reloaded automatically when it changes on disk. Computed scores are
cached in a `risk.json` file per session; the cache is invalidated whenever the
rules file is modified.

### Schema

```yaml
rules:
  - id: string             # Unique rule identifier (snake_case recommended)
    score: int             # Points to add when this rule matches (1–100)
    reason: string         # Short label shown in the UI when this rule fires

    # Match conditions — all specified fields must match (AND logic).
    # command_base_any, command, and content are OR-ed with each other.

    command_base_any:      # List of exact binary basenames (OR within list)
      - bash
      - sh

    runas: string          # Run-as user required (e.g. "root")

    incomplete: bool       # true = only match sessions that ended without
                           #        a clean session_end event

    after_hours: bool      # true = only match sessions that started between
                           #        23:00 and 05:59 local time

    min_duration: int      # Minimum session length in seconds

    command:               # Substring match against the full sudo command line
      contains_any:        # At least one of these must match (OR)
        - string
      also_any:            # AND at least one of these must also match (AND+OR)
        - string

    content:               # Substring match against terminal output (ttyout)
      contains_any:
        - string
      also_any:
        - string
```

### Field reference

| Field | Type | Match target | Notes |
|-------|------|-------------|-------|
| `id` | string | — | Unique identifier; use `snake_case`; required |
| `score` | int | — | Points added to session total (1–100); required |
| `reason` | string | — | Displayed in the UI when this rule fires; required |
| `command_base_any` | []string | Exact basename of the executed binary | OR within the list; AND-ed with other conditions |
| `runas` | string | User the command runs as (e.g. `root`) | AND-ed with other conditions |
| `incomplete` | bool | Sessions without a clean `session_end` | Useful for detecting killed or forcibly disconnected sessions |
| `after_hours` | bool | Sessions starting 23:00–05:59 local time | AND-ed with other conditions |
| `min_duration` | int | Session length in seconds | Only fires when the session lasted at least this long |
| `command.contains_any` | []string | Full sudo command line (case-insensitive) | At least one string must appear |
| `command.also_any` | []string | Full sudo command line | AND: at least one of these must also appear |
| `content.contains_any` | []string | Terminal output (ttyout cast file) | At least one string must appear |
| `content.also_any` | []string | Terminal output | AND: at least one of these must also appear |

> **Note:** `command` and `content` are OR-ed at the rule level: a rule with
> both fields fires if either the command OR the content matches. Within each
> field, `contains_any` and `also_any` are AND-ed: both groups must match.

### Built-in default rules

The following rules ship with the default `risk-rules.yaml`. All rules are
evaluated independently; a session can accumulate score from multiple rules.

| ID | Score | Reason |
|----|-------|--------|
| `stop_sudo_logger` | 50 | sudo-logger stopped or disabled |
| `stop_auditd` | 45 | audit daemon stopped |
| `auditctl_disable` | 45 | audit logging disabled via auditctl |
| `systemd_run_delegation` | 60 | process spawned via systemd-run (escapes session sandbox) |
| `machinectl_shell` | 60 | machinectl shell/login (escapes session sandbox) |
| `dbus_transient_unit` | 60 | transient systemd unit started via D-Bus (sandbox escape vector) |
| `audit_log_tampered` | 40 | audit log file tampered |
| `history_suppressed` | 30 | shell history suppressed |
| `bash_history_tampered` | 30 | shell history file deleted or truncated |
| `cgroup_escape` | 75 | cgroup manipulation — possible freeze/container escape |
| `selinux_disabled` | 35 | SELinux set to permissive or disabled |
| `selinux_config_disabled` | 35 | SELinux disabled in config |
| `apparmor_disabled` | 35 | AppArmor disabled |
| `firewall_disabled` | 25 | firewall stopped or disabled |
| `iptables_flush` | 25 | iptables rules flushed |
| `nft_flush` | 25 | nftables ruleset flushed |
| `intrusion_prevention_stopped` | 25 | intrusion prevention service stopped |
| `visudo` | 60 | sudoers file edited via visudo |
| `sudoers_write` | 45 | sudoers file directly modified |
| `sudoers_read` | 15 | sudoers file read |
| `shadow_write` | 40 | shadow password file modified |
| `shadow_read` | 15 | shadow password file read |
| `suid_set` | 35 | SUID bit set on file |
| `usermod_privileged_group` | 25 | user added to privileged group |
| `user_created` | 15 | user account created |
| `user_deleted` | 15 | user account deleted |
| `password_changed` | 15 | user password changed |
| `pam_modified` | 25 | PAM configuration modified |
| `ssh_authorized_keys_write` | 30 | SSH authorized_keys modified |
| `ssh_authorized_keys_read` | 10 | SSH authorized_keys accessed |
| `sshd_config` | 20 | SSH server config accessed |
| `passwd_file_modified` | 25 | /etc/passwd modified |
| `crontab_write` | 20 | crontab modified |
| `cron_file_write` | 20 | cron config file written |
| `systemd_unit_write` | 20 | systemd unit file installed |
| `kernel_module_loaded` | 20 | kernel module loaded |
| `ld_preload` | 40 | LD_PRELOAD set — possible library injection |
| `core_pattern_write` | 40 | kernel core_pattern modified — known privilege escalation vector |
| `ssh_private_key_read` | 20 | SSH private key accessed |
| `remote_exec` | 40 | remote script piped to shell — possible supply-chain attack |
| `world_writable` | 15 | world-writable permissions set |
| `root_shell` | 10 | interactive root shell started |
| `incomplete_session` | 15 | session terminated unexpectedly |
| `after_hours` | 10 | access outside business hours |
| `long_session` | 5 | extended session (>2 h) |
| `dbus_polkit` | 25 | Polkit privilege authorization via D-Bus |
| `dbus_polkit_high_value` | 40 | High-value polkit action (exec/systemd/network/packages) |
| `dbus_polkit_denied` | 50 | Polkit authorization denied — possible privilege escalation probe |

### Writing effective rules

- All match conditions within a rule are optional; omit any condition to skip
  that check.
- Multiple conditions within one rule are AND-ed: all present conditions must
  match for the rule to fire.
- Multiple rules are evaluated independently: all matching rules contribute
  their scores to the total.
- `output` / content matching scans the terminal output in the cast file.
  Avoid standalone `content` rules without `also_any` — they can produce false
  positives when sensitive strings appear in `ps` output or log tails.
- Use `command_base_any` for known binaries: exact basename matching has no
  false positives from path variations.
- Read access to sensitive files should score low (10–20); confirmed writes
  should score higher (25–45).

### Example: custom rules

```yaml
rules:
  # Flag recursive forced deletion — high risk
  - id: rm_rf
    score: 40
    reason: "recursive forced delete (rm -rf)"
    command:
      contains_any: ["rm"]
      also_any: ["-rf", "-fr", "--force", "--recursive"]

  # Flag activity outside business hours (08:00–18:00 Mon–Fri)
  - id: weekend_access
    score: 20
    reason: "sudo access outside business hours"
    after_hours: true

  # Flag direct interactive root shell
  - id: root_shell_any
    score: 30
    reason: "interactive root shell"
    runas: root
    command_base_any: [bash, sh, zsh, fish, ksh]
```

---

## Sandbox policy (sandbox.yaml)

### Overview

The sandbox policy restricts what processes running inside recorded sudo
sessions can do at the kernel level. It is enforced by the agent's eBPF
subsystem using kernel LSM hooks.

- **File path:** configured by the `--sandbox` flag on the log server and replay server
- The file is served to agents at startup
- Requires `Ebpf = true` in `agent.conf` and a kernel 5.8+ with LSM hooks
- The `SandboxConfig` key in `agent.conf` must point to the same file path;
  leaving `SandboxConfig` empty disables the sandbox on the agent

### Schema

```yaml
enabled: true   # top-level switch; omit or set true to enforce, false disables the whole sandbox

features:
  deny_netlink: true
  deny_mount: true
  deny_ptrace: true
  deny_cap_audit_control: true
  deny_cap_net_admin: true
  deny_cap_sys_module: true
  deny_cap_mac_admin: true
  deny_cap_sys_rawio: true
  deny_cap_sys_boot: true
  deny_systemd_ipc: false   # NOTE: default is false — see warning below

protect:
  files:
    - /etc/sudoers
    - /etc/sudo.conf
  forbidden:
    - /etc/shadow
  noexec:
    - /tmp
  devices: []
  proc: []
  sockets: []
  processes: []
```

### Feature flags reference

| YAML key | Default | What it blocks | Notes |
|----------|---------|---------------|-------|
| `enabled` (top-level, not under `features`) | `true` | The entire sandbox subsystem | `nil`/absent → enforced (`true`); set `enabled: false` to disable sandbox enforcement entirely while keeping the file for reference |
| `deny_netlink` | `true` | Netlink socket creation (raw kernel interface access) | Blocks low-level network manipulation and iptables bypasses |
| `deny_mount` | `true` | `mount(2)` system calls | Prevents bind mounts and overlay filesystem escapes |
| `deny_ptrace` | `true` | `ptrace(2)` and `/proc/<pid>/mem` writes | Prevents process injection and credential dumping |
| `deny_cap_audit_control` | `true` | `CAP_AUDIT_CONTROL` capability | Prevents disabling or clearing the audit log |
| `deny_cap_net_admin` | `true` | `CAP_NET_ADMIN` capability | Prevents firewall rule changes, interface configuration |
| `deny_cap_sys_module` | `true` | `CAP_SYS_MODULE` capability | Prevents loading or unloading kernel modules |
| `deny_cap_mac_admin` | `true` | `CAP_MAC_ADMIN` capability | Prevents changes to MAC (SELinux/AppArmor) policy |
| `deny_cap_sys_rawio` | `true` | `CAP_SYS_RAWIO` capability | Prevents direct hardware I/O port and memory access |
| `deny_cap_sys_boot` | `true` | `CAP_SYS_BOOT` capability | Prevents `reboot(2)` and kernel signature loading |
| `deny_systemd_ipc` | `false` | D-Bus calls that create transient systemd units | **Default is false** — see warning below |

> **Note:** `deny_systemd_ipc` defaults to `false` because enabling it also
> blocks `systemctl` and `loginctl` commands inside recorded sessions. Enable
> it only when you are certain that operators in sudo sessions do not need to
> manage systemd units interactively. When `deny_systemd_ipc = true`, any D-Bus
> call that would start a transient unit (including `systemd-run`, `machinectl
> shell`, and some package manager operations) is blocked.

### Protect sections reference

| Section | What it does | Example paths |
|---------|-------------|---------------|
| `files` | Block modification of these files (inotify-watched; atomically-replaced files detected and re-protected automatically) | `/etc/sudoers`, `/etc/sudo.conf`, `/etc/audit/auditd.conf` |
| `forbidden` | Completely forbid any access (read, write, execute) to these paths | `/etc/shadow`, `/root/.ssh/authorized_keys` |
| `noexec` | Allow read access but block execution of files in these paths | `/tmp`, `/var/tmp`, `/dev/shm` |
| `devices` | Block access to these device paths | `/dev/mem`, `/dev/kmem` |
| `proc` | Block access to these `/proc` paths | `/proc/kcore`, `/proc/sysrq-trigger` |
| `sockets` | Block connections to these Unix socket paths | `/run/dbus/system_bus_socket` |
| `processes` | Block ptrace and signal delivery to processes matching these names | `auditd`, `sudo-logger-agent` |

> **Note:** `/var/tmp` is a common `noexec` entry, but it's also where RPM stages and
> executes every package scriptlet (`%pre`/`%post`/`%preun`/`%postun`/`%posttrans`) by
> default. `sudo-logger-client` 1.20.125+ (v1.39.2+) ships an RPM macro that redirects
> RPM's scriptlet staging to a dedicated, non-noexec directory so this doesn't collide.
> If you're on an older client, or see `dnf`/`rpm` transactions failing unexpectedly,
> see [Package manager transactions abort mid-scriptlet](11-troubleshooting.md#dnfrpm-transaction-aborts-mid-scriptlet-leaves-rpmdb-or-selinux-state-inconsistent).

### How inode protection works

The `files` section protects inodes, not path strings. When the agent starts,
it resolves each listed path to its current inode number and installs a kernel
hook that blocks writes to that inode.

Many editors (vim, emacs, sed -i) replace files atomically via rename rather
than writing in place. The agent detects these replacements via inotify and
immediately re-resolves the path to the new inode, keeping protection active
even after atomic file replacement.

---

## JIT Approval policy (approval-policy.yaml)

### Overview

Just-in-Time (JIT) approval requires an operator to obtain explicit permission
before running a sudo command. The approval feature is **disabled** when the
`--approval-policy` file is absent; no approval check occurs in that case.

- **File path:** `/etc/sudo-logger/approval-policy.yaml` (configured via log server `--approval-policy` flag)
- Reloaded every 30 seconds without restart
- Requires `--approval-token` on the log server and `--logserver-admin` +
  `--logserver-admin-token` on the replay server

### Schema

```yaml
enabled: true

# How long an approval window lasts once granted (default 30m)
default_window: 30m

# How long a pending approval request is kept before it expires (default 24h)
pending_ttl: 24h

# Maximum length of a single sudo session (optional; 0 = unlimited)
max_session_duration: 0s

# Users and hosts exempt from the approval requirement
exempt:
  - user: alice
    hosts: []          # empty = exempt on all hosts
  - user: bob
    hosts:
      - db-prod.example.com
      - db-standby.example.com

# Notification settings (Mattermost-compatible webhook)
notifications:
  webhook_url: https://mattermost.example.com/hooks/...
  webhook_secret: ""             # HMAC secret for verifying webhook deliveries
  mention_user: true             # @mention the requesting user in the message
  request_channel: "sudo-approvals"
  replay_web_app_url: https://replay.example.com
```

### Field reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable JIT approval enforcement |
| `default_window` | duration | `30m` | Duration of an approval window after it is granted |
| `pending_ttl` | duration | `24h` | How long a pending request is kept before it auto-expires |
| `max_session_duration` | duration | `0s` | Maximum allowed session length; `0` means no limit |
| `exempt` | []exemptRule | _(empty)_ | Rules listing users (and optional hosts) that bypass approval |
| `exempt[].user` | string | — | Username to exempt |
| `exempt[].hosts` | []string | _(empty = all)_ | List of hostnames where the exemption applies; empty list exempts on all hosts |
| `notifications.webhook_url` | string | _(empty)_ | Mattermost-compatible webhook URL for approval request notifications |
| `notifications.webhook_secret` | string | _(empty)_ | HMAC secret for signing webhook deliveries (masked when returned to the browser) |
| `notifications.mention_user` | bool | `false` | When true, the notification mentions the requesting user by name |
| `notifications.request_channel` | string | _(empty)_ | Mattermost channel to post notifications to |
| `notifications.replay_web_app_url` | string | _(empty)_ | Base URL of the replay UI; used to generate clickable session links in notifications |

### Exempt rules

Users listed in `exempt[]` bypass the JIT approval requirement entirely.
Their sudo sessions are still recorded — exemption only skips the approval
gate. Hosts may be omitted or left empty to exempt a user on all monitored
hosts.

Additionally, users listed in `whitelisted-users.yaml` (managed via the UI
or `PUT /api/whitelisted-users`) bypass JIT approval regardless of the
`exempt[]` list. The whitelisted-users file is intended for temporary
exceptions managed through the UI; the `exempt[]` list in the policy file
is for permanent infrastructure accounts.

### Notification webhook

Notifications use a Mattermost-compatible webhook payload format. When a sudo
session requires approval:

1. The log server POSTs a JSON notification to `webhook_url`.
2. If `webhook_secret` is set, the POST includes an `X-Hub-Signature-256`
   HMAC-SHA256 header for request verification.
3. The notification includes the requesting user's name, host, and command.
4. If `mention_user` is true, the requesting user is mentioned by Mattermost
   username (assumes the sudo username matches the Mattermost username).
5. If `replay_web_app_url` is set, the notification includes a clickable link
   to the Approvals tab.

> **Note:** `webhook_secret` is masked (replaced with `"***"`) when the
> approval policy is returned by the replay server's read API endpoints. Store
> the original value securely.

### Approval flow

The following sequence describes the complete JIT flow:

1. User runs `sudo <command>` on a monitored host.
2. The sudo plugin opens a connection to the agent. The agent connects to the
   log server and sends a `SESSION_START` message.
3. The log server calls `ApprovalManager.Check()`.
4. If the policy is disabled, the user is exempt, or an active approval window
   already exists for this user on this host, the session proceeds immediately.
5. If approval is required and the user has provided a justification (reason),
   the log server creates a pending request, fires the webhook notification, and
   returns `SESSION_DENIED` with the pending request ID. The user sees a
   "waiting for approval" message.
6. If approval is required and no justification was provided, the log server
   returns `SESSION_DENIED` asking the user to re-run with a `--reason` flag.
7. An approver opens the replay UI, navigates to the Approvals tab, and clicks
   Approve or Deny.
8. The replay server calls the log server approval REST API (Bearer token auth)
   at `POST /api/approvals/{id}/approve` or `/deny`.
9. **If approved:** the log server creates an approval window for the user on
   that host (duration = `default_window`). On the agent side, the pending
   `SESSION_DENIED` resolves to allow and the sudo session proceeds.
10. **If denied:** the session receives a final `SESSION_DENIED` and the user
    sees the denial reason (if provided by the approver).

---

## SIEM forwarding (siem.yaml)

### Overview

SIEM forwarding sends a structured event to an external security information
and event management system whenever a sudo session completes.

- **File path:** `/etc/sudo-logger/siem.yaml` (configured via replay server `--siem-config` flag)
- Reloaded every 30 seconds without restart
- Can be configured via the replay UI (Settings tab) or by editing the file directly
- TLS certificates may be uploaded via the UI (`POST /api/siem-cert`) and are
  stored alongside the YAML file

### Schema

```yaml
enabled: false
transport: https      # https | syslog | stdout
format: json          # json | cef | ocsf
replay_url_base: ""   # e.g. https://replay.example.com

https:
  url: ""             # Endpoint URL (e.g. Splunk HEC URL)
  token: ""           # Optional Bearer or Splunk HEC token
  tls:
    ca: ""            # CA certificate file path (for custom/internal CA)
    cert: ""          # Client certificate file path (mTLS)
    key: ""           # Client private key file path (mTLS)

syslog:
  addr: ""            # host:port (e.g. siem.example.com:514)
  protocol: udp       # udp | tcp | tcp-tls
  tls:
    ca: ""            # CA certificate for TCP-TLS
    cert: ""          # Client certificate for TCP-TLS mTLS
    key: ""           # Client private key for TCP-TLS mTLS
```

### Field reference

| Field | Type | Options | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable SIEM event forwarding |
| `transport` | string | `https`, `syslog`, `stdout` | Delivery mechanism for events |
| `format` | string | `json`, `cef`, `ocsf` | Event serialization format |
| `replay_url_base` | string | — | Base URL of the replay UI; used to construct clickable links in events |
| `https.url` | string | — | HTTPS endpoint URL (Splunk HEC, webhook, etc.) |
| `https.token` | string | — | Bearer token or Splunk HEC token sent as `Authorization: Bearer <token>` |
| `https.tls.ca` | string | — | Path to CA certificate file for verifying the HTTPS server |
| `https.tls.cert` | string | — | Path to client certificate for mTLS |
| `https.tls.key` | string | — | Path to client private key for mTLS |
| `syslog.addr` | string | — | Syslog server address in `host:port` form |
| `syslog.protocol` | string | `udp`, `tcp`, `tcp-tls` | Transport protocol for syslog |
| `syslog.tls.ca` | string | — | CA certificate for TCP-TLS syslog |
| `syslog.tls.cert` | string | — | Client certificate for TCP-TLS mTLS syslog |
| `syslog.tls.key` | string | — | Client private key for TCP-TLS mTLS syslog |

### Transport modes

#### HTTPS (Splunk HEC, webhooks)

Use the `https` transport to send events to a Splunk HTTP Event Collector,
a custom webhook, or any HTTP/HTTPS endpoint that accepts a POST body.

```yaml
enabled: true
transport: https
format: json
https:
  url: https://splunk.example.com:8088/services/collector/event
  token: Splunk 00000000-0000-0000-0000-000000000000
```

Test that the endpoint is reachable:

```bash
curl -k -H "Authorization: Splunk 00000000-0000-0000-0000-000000000000" \
  -d '{"event":"test"}' \
  https://splunk.example.com:8088/services/collector/event
```

#### Syslog

The `syslog` transport supports UDP, TCP, and TCP with TLS.

**UDP (simple, no delivery guarantee):**
```yaml
transport: syslog
syslog:
  addr: siem.example.com:514
  protocol: udp
```

**TCP (reliable delivery):**
```yaml
transport: syslog
syslog:
  addr: siem.example.com:6514
  protocol: tcp
```

**TCP-TLS (encrypted delivery):**
```yaml
transport: syslog
syslog:
  addr: siem.example.com:6514
  protocol: tcp-tls
  tls:
    ca: /etc/sudo-logger/siem-ca.crt
```

#### stdout

For debugging only. Events are printed to the replay server's standard output
in the configured format. Do not use in production.

```yaml
enabled: true
transport: stdout
format: json
```

### Output formats

#### JSON

A single JSON object per event, written to one HTTP POST body or one syslog
message. Fields include: `tsid` (session ID), `user`, `host`, `command`,
`runas`, `start_time`, `end_time`, `duration`, `exit_code`, `risk_score`,
`risk_level`, `risk_reasons`, and (when `replay_url_base` is set) `replay_url`.

#### CEF (Common Event Format)

ArcSight-style CEF format:

```
CEF:0|sudo-logger|sudo-logger|1.0|session_end|sudo session completed|<severity>|...
```

The CEF header severity is derived from the risk level (Low=1, Medium=4,
High=7, Critical=10). Extension fields map the same session metadata as the
JSON format.

#### OCSF (Open Cybersecurity Schema Framework)

Events are mapped to OCSF Class 3003 (System Activity / Process Activity).
Core fields include `class_uid`, `activity_id`, `time`, `actor.user`,
`process`, `device.hostname`, `severity_id`, and `metadata.product`.

### replay_url_base

When `replay_url_base` is set, SIEM events include a direct link to the
session in the replay UI. The link is constructed as:

```
<replay_url_base>/session/<tsid>
```

Example: with `replay_url_base: https://replay.example.com`, a session with
ID `alice_webserver_20260615-143022` would have a link of:

```
https://replay.example.com/session/alice_webserver_20260615-143022
```

---

## Blocked and whitelisted users

### blocked-users.yaml

The blocked users file contains a YAML list of usernames whose sudo commands
are denied at the log server level before execution begins.

```yaml
- mallory
- former-contractor
```

**Effect:** when a user in this list attempts a sudo command, the log server
returns `SESSION_DENIED` and the session is never started. The denial is logged.

**Management:** the file is managed via the replay UI (Blocked Users tab) or
the `PUT /api/blocked-users` endpoint. It is reloaded every 30 seconds without
restart.

**File path:** `/etc/sudo-logger/blocked-users.yaml` (configured via `--blocked-users`
on both the log server and replay server; both must point to the same file).

### whitelisted-users.yaml

The whitelisted users file contains a YAML list of usernames that bypass JIT
approval requirements.

```yaml
- deploy-robot
- monitoring-agent
- alice
```

**Effect:** users in this list proceed through sudo without waiting for
approval, even when the approval policy is enabled. All sessions are still
recorded — whitelisting only skips the approval gate.

**Management:** the file is managed via the replay UI or the
`PUT /api/whitelisted-users` endpoint. It is reloaded every 30 seconds.

**File path:** `/etc/sudo-logger/whitelisted-users.yaml` (configured via
`--whitelisted-users` on both the log server and replay server).

> **Note:** The difference between `whitelisted-users.yaml` and the `exempt[]`
> list in `approval-policy.yaml` is one of management interface. Both bypass
> JIT approval. Use `exempt[]` for permanent service accounts (version-controlled
> in the policy file). Use `whitelisted-users.yaml` for temporary exceptions
> managed through the UI without editing files on the server.
