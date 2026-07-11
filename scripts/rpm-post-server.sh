#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now sudo-logserver.service sudo-logserver-restart.timer >/dev/null 2>&1 || true
# Generate ed25519 signing key on first install
if [ ! -f /etc/sudo-logger/ack-sign.key ]; then
    if ! command -v openssl >/dev/null 2>&1; then
        echo "sudo-logger-server: openssl not found — cannot generate ack-sign.key/ack-verify.key." >&2
        echo "sudo-logger-server: install openssl, then run this to generate them manually:" >&2
        echo "sudo-logger-server:   openssl genpkey -algorithm ed25519 -out /etc/sudo-logger/ack-sign.key" >&2
        echo "sudo-logger-server:   openssl pkey -in /etc/sudo-logger/ack-sign.key -pubout -out /etc/sudo-logger/ack-verify.key" >&2
    else
        openssl genpkey -algorithm ed25519 -out /etc/sudo-logger/ack-sign.key 2>/dev/null
        chown root:sudologger /etc/sudo-logger/ack-sign.key 2>/dev/null || true
        chmod 0640 /etc/sudo-logger/ack-sign.key 2>/dev/null || true
        openssl pkey -in /etc/sudo-logger/ack-sign.key -pubout -out /etc/sudo-logger/ack-verify.key 2>/dev/null
        chmod 0644 /etc/sudo-logger/ack-verify.key 2>/dev/null || true
    fi
fi
