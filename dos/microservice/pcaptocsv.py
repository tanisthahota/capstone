import re
import csv
import subprocess
import glob
import sys

# Step 1: Find the latest matching pcap file
pcap_files = sorted(glob.glob("flask_capture_*.pcap"))
if not pcap_files:
    print("❌ No matching PCAP files found: flask_capture_*.pcap")
    sys.exit(1)

latest_pcap = pcap_files[-1]
print(f"📄 Processing: {latest_pcap}")

# Step 2: Run tcpdump and get output
result = subprocess.run(
    ["tcpdump", "-tttt", "-n", "-r", latest_pcap],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

# Step 3: Regex to parse lines
pattern = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<proto>IP6|IP)\s+"
    r"(?P<src>[^\s>]+)\s+>\s+"
    r"(?P<dst>[^\s:]+):\s+"
    r"(?P<info>.+)"
)

# Step 4: Write to CSV
csv_file = "packets.csv"
with open(csv_file, "w", newline="") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(["Time", "Protocol", "Source", "Destination", "Info"])

    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if match:
            writer.writerow([
                match.group("time"),
                match.group("proto"),
                match.group("src"),
                match.group("dst"),
                match.group("info")
            ])

print(f"✅ Done. Output written to {csv_file}")
