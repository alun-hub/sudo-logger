#!/bin/sh
# Add plugin line to sudo.conf if not already present
if ! grep -q 'Plugin sudo_logger_plugin sudo_logger_plugin.so' /etc/sudo.conf 2>/dev/null; then
    echo 'Plugin sudo_logger_plugin sudo_logger_plugin.so' >> /etc/sudo.conf
fi
# Load SELinux policy module if it exists
if [ -f /usr/share/selinux/packages/sudo_logger.pp ]; then
    semodule -i /usr/share/selinux/packages/sudo_logger.pp 2>/dev/null || true
fi
# On fresh install or upgrade: enable and start the service
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now sudo-logger-agent.service >/dev/null 2>&1 || true
# Make plugin binary and agent immutable
chattr +i /usr/libexec/sudo/sudo_logger_plugin.so 2>/dev/null || true
chattr +i /usr/bin/sudo-logger-agent 2>/dev/null || true
# Relabel contexts
restorecon -R /usr/bin/sudo-logger-agent /usr/libexec/sudo/sudo_logger_plugin.so /etc/sudo-logger 2>/dev/null || true
