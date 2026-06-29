#!/bin/sh
# Remove immutable flag so package manager can delete the files.
if command -v chattr >/dev/null 2>&1; then
    chattr -i /usr/libexec/sudo/sudo_logger_plugin.so 2>/dev/null || true
    chattr -i /usr/bin/sudo-logger-agent 2>/dev/null || true
fi
if [ "$1" = "remove" ]; then
    systemctl disable sudo-logger-agent.service >/dev/null 2>&1 || true
    systemctl kill sudo-logger-agent.service >/dev/null 2>&1 || true
    sed -i '/Plugin sudo_logger_plugin sudo_logger_plugin\.so/d' /etc/sudo.conf 2>/dev/null || true
fi
