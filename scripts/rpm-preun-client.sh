#!/bin/sh
# Remove immutable flag so RPM can delete the files on uninstall.
chattr -i /usr/libexec/sudo/sudo_logger_plugin.so 2>/dev/null || true
chattr -i /usr/bin/sudo-logger-agent 2>/dev/null || true
# On full uninstall (not upgrade):
if [ $1 -eq 0 ]; then
    systemctl disable sudo-logger-agent.service >/dev/null 2>&1 || true
    systemctl kill sudo-logger-agent.service >/dev/null 2>&1 || true
    semodule -r sudo_logger 2>/dev/null || true
    sed -i '/Plugin sudo_logger_plugin sudo_logger_plugin\.so/d' /etc/sudo.conf 2>/dev/null || true
fi
