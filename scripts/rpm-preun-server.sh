#!/bin/sh
if [ $1 -eq 0 ]; then
    systemctl disable --now sudo-logserver.service sudo-logserver-restart.timer >/dev/null 2>&1 || true
fi
