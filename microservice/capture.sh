#!/bin/bash

# Output pcap file
PCAP_FILE="flask_capture_$(date +%s).pcap"

# Start tcpdump in background
echo "[*] Starting tcpdump..."
sudo tcpdump -i any port 5000 -w "$PCAP_FILE" &
TCPDUMP_PID=$!

# Optional: Give tcpdump time to start
sleep 2

# Simulate some traffic (or call curl, attack scripts, etc.)
echo "[*] Simulating API request..."
curl -X POST http://localhost:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"password"}'

# Wait a bit or run your DoS scripts here
sleep 20

# Stop tcpdump
echo "[*] Stopping tcpdump..."
sudo kill "$TCPDUMP_PID"

echo "[✓] Packet capture saved as $PCAP_FILE"
