#!/bin/bash

echo "[*] Setting up iptables rule for NFQUEUE..."
sudo iptables -I INPUT -j NFQUEUE --queue-num 0

echo "[*] Starting MiniNetGuard firewall..."
sudo ./firewall &
FIREWALL_PID=$!

echo "[*] Firewall running with PID: $FIREWALL_PID"
echo "[*] Use Ctrl+C to stop the firewall and clean up"

# Wait for user to stop
trap "echo '[*] Stopping firewall...'; sudo kill $FIREWALL_PID; sudo iptables -F; exit" INT
wait
