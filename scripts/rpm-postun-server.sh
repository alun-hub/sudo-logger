#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
if [ $1 -ge 1 ]; then
    systemctl try-restart sudo-logserver.service >/dev/null 2>&1 || true
fi
