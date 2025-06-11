import re
import csv
import subprocess

# Step 1: Run tcpdump and capture output
pcap_file = "flask_capture_1749651659.pcap"
print(f"Running tcpdump on {pcap_file}...")

result = subprocess.run(
    ["tcpdump", "-tttt", "-n", "-r", pcap_file],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

# Step 2: Define regex
pattern = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<proto>IP6|IP)\s+"
    r"(?P<src>[^\s>]+)\s+>\s+"
    r"(?P<dst>[^\s:]+):\s+"
    r"(?P<info>.+)"
)

# Step 3: Write to CSV
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
