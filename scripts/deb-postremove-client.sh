#!/bin/sh
if [ "$1" = "upgrade" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl kill sudo-logger-agent.service >/dev/null 2>&1 || true
else
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
