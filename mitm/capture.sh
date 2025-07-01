#!/bin/bash

# Set output paths
PCAP_FILE="output_traffic.pcap"
CSV_OUTPUT_FILE="output.csv"

# Create output dir
touch $CSV_OUTPUT_FILE

# Step 1: Capture traffic from Flask evil portal (port 8082)
echo "[🔴] Capturing traffic for 20 seconds on port 8082..."
sudo tcpdump -i lo0 -w $PCAP_FILE port 8082 &
TCPDUMP_PID=$!

# Wait 20 seconds
sleep 20

# Stop capture
sudo kill $TCPDUMP_PID
echo "[✅] Capture saved to $PCAP_FILE"

# Step 2: Convert to flows using Python cicflowmeter
echo "[🔄] Converting pcap to flows using cicflowmeter (Python)..."
cicflowmeter -f $PCAP_FILE -c $CSV_OUTPUT_FILE

echo "[📊] Done! Flow CSV saved in $CSV_OUTPUT_FILE"

