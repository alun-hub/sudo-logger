#!/bin/sh
# Migrate legacy shipper.conf -> agent.conf BEFORE RPM installs new files.
if [ ! -f /etc/sudo-logger/agent.conf ] && [ -f /etc/sudo-logger/shipper.conf ]; then
    cp -p /etc/sudo-logger/shipper.conf /etc/sudo-logger/agent.conf
fi
# Clear any stale BPF hooks/maps before the new agent starts.
rm -rf /sys/fs/bpf/sudo-logger 2>/dev/null || true
# Remove immutable flag from our binaries before package writes new files.
chattr -i /usr/libexec/sudo/sudo_logger_plugin.so 2>/dev/null || true
chattr -i /usr/bin/sudo-logger-agent 2>/dev/null || true
