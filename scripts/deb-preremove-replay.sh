#!/bin/sh
if [ "$1" = "remove" ]; then
    systemctl disable --now sudo-replay.service >/dev/null 2>&1 || true
fi
