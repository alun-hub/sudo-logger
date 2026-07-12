#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now sudo-replay.service >/dev/null 2>&1 || true
# Ensure the replay service can write its own config files.
chown root:sudoreplay /etc/sudo-logger/risk-rules.yaml 2>/dev/null || true
chmod 0664             /etc/sudo-logger/risk-rules.yaml 2>/dev/null || true
chown root:sudoreplay /etc/sudo-logger/siem.yaml 2>/dev/null || true
chmod 0664             /etc/sudo-logger/siem.yaml 2>/dev/null || true

# Grant the sudoreplay user access to directories shared with the log
# server (session data, general config) via ACL rather than group
# membership -- group membership would also grant read access to
# ack-sign.key (root:sudologger 0640), which sudoreplay must NOT be able
# to read. ACLs only grant directory traverse/create rights; they do not
# widen any individual file's own owning-group.
if command -v setfacl >/dev/null 2>&1; then
    for d in /var/log/sudoreplay /etc/sudo-logger; do
        [ -d "$d" ] || continue
        setfacl -m u:sudoreplay:rwx -m d:u:sudoreplay:rwx "$d" 2>/dev/null || true
    done
    # One-time migration: session.json was previously written 0640
    # (owner+group only); widen existing files to match session.cast's
    # already-world-readable mode so sudoreplay can read them without
    # falling back to the slower session.cast-header parse path. Safe --
    # /var/log/sudoreplay's own directory permissions (0750 + the ACL
    # above) are the real access gate, not individual file modes.
    if [ -d /var/log/sudoreplay ]; then
        find /var/log/sudoreplay -maxdepth 3 -name session.json -exec chmod 0644 {} + 2>/dev/null || true
    fi
else
    echo "sudo-logger-replay: setfacl not found (install the 'acl' package) -- sudoreplay may lack write access to /var/log/sudoreplay and /etc/sudo-logger" >&2
fi
