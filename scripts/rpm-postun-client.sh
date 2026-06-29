#!/bin/sh
# On upgrade: reload unit and signal the running agent to restart.
if [ $1 -ge 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl kill sudo-logger-agent.service >/dev/null 2>&1 || true
else
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
