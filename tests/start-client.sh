#!/bin/bash
# tests/start-client.sh — Starts the shipper in the client container.

# Wait for certificates to be available in /etc/sudo-logger
# (Mounted from a volume during the system test)
while [ ! -f /etc/sudo-logger/client.crt ]; do
    echo "Client: Waiting for /etc/sudo-logger/client.crt..."
    sleep 1
done

# Start the shipper in the background
/usr/local/bin/sudo-shipper \
    -server=localhost:9876 \
    -socket=/run/sudo-logger/plugin.sock \
    -cert=/etc/sudo-logger/client.crt \
    -key=/etc/sudo-logger/client.key \
    -ca=/etc/sudo-logger/ca.crt \
    -verifykey=/etc/sudo-logger/ack-verify.key \
    -debug &

echo "Shipper started. Client ready for sudo commands."

# Keep the container running
exec tail -f /dev/null
