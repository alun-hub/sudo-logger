#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now sudo-replay.service >/dev/null 2>&1 || true
# Ensure the replay service can write config files
chown root:sudologger /etc/sudo-logger/risk-rules.yaml 2>/dev/null || true
chmod 0664            /etc/sudo-logger/risk-rules.yaml 2>/dev/null || true
chown root:sudologger /etc/sudo-logger/siem.yaml 2>/dev/null || true
chmod 0664            /etc/sudo-logger/siem.yaml 2>/dev/null || true
