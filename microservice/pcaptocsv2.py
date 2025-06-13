import subprocess
import glob
import csv
import sys
import os

# Step 1: Find the latest PCAP file
pcap_files = sorted(glob.glob("flask_capture_*.pcap"))
if not pcap_files:
    print("❌ No PCAP files found matching 'flask_capture_*.pcap'")
    sys.exit(1)

latest_pcap = pcap_files[-1]
print(f"📄 Found latest PCAP: {latest_pcap}")

# Step 2: Check if tshark is installed
if subprocess.run(["which", "tshark"], stdout=subprocess.PIPE).returncode != 0:
    print("❌ tshark not found. Install it with 'sudo apt install tshark'")
    sys.exit(1)

# Step 3: Run tshark to extract packet details
fields = [
    "-e", "frame.time",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "_ws.col.Protocol",
    "-e", "frame.len"
]

cmd = ["tshark", "-r", latest_pcap, "-T", "fields"] + fields + ["-E", "separator=,", "-E", "quote=d"]
result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

if result.stderr:
    print("⚠️ tshark error output:")
    print(result.stderr)

lines = result.stdout.strip().split("\n")

# Step 4: Write to CSV
output_file = f"{os.path.splitext(latest_pcap)[0]}.csv"
with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Packet Length"])
    for line in lines:
        writer.writerow(line.strip().split(","))

print(f"✅ CSV saved as: {output_file}")
