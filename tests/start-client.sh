#!/bin/bash
# tests/start-client.sh — Starts the agent in the client container.

# Wait for certificates to be available in /etc/sudo-logger
# (Mounted from a volume during the system test)
while [ ! -f /etc/sudo-logger/client.crt ]; do
    echo "Client: Waiting for /etc/sudo-logger/client.crt..."
    sleep 1
done

cat > /tmp/agent.conf <<EOF
server     = localhost:9876
socket     = /run/sudo-logger/plugin.sock
cert       = /etc/sudo-logger/client.crt
key        = /etc/sudo-logger/client.key
ca         = /etc/sudo-logger/ca.crt
verify_key = /etc/sudo-logger/ack-verify.key
debug      = true
freeze_timeout = 3s
EOF

# Start the agent in the background
/usr/local/bin/sudo-logger-agent -config=/tmp/agent.conf &

echo "Agent started. Client ready for sudo commands."

# Keep the container running
exec tail -f /dev/null
