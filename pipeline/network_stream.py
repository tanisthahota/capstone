#!/usr/bin/env python3
"""
Real-time Network Flow Producer (host-driven CSV)
--------------------------------
Runs inside python-scripts container.

Flow:
1. Capture rotating PCAP chunks from eth0 (container-to-container traffic)
2. WAIT for matching CSV to appear in CSV_DIR (you run cicflowmeter on host and copy CSV back)
3. Streams each CSV row to Kafka topic `network-flows`
"""

import os
import json
import subprocess
from datetime import datetime
from kafka import KafkaProducer
import time
import pandas as pd
import shlex
import glob

# Directories inside container
PCAP_DIR = "/app/pcaps"
CSV_DIR = "/app/flow_csvs"
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(CSV_DIR, exist_ok=True)

# How long to wait (seconds) for a host-produced CSV to appear after a pcap is captured.
# Tune this depending on how quickly you run cicflowmeter on host and copy files back.
CSV_WAIT_TIMEOUT = int(os.getenv("HOST_CSV_WAIT_TIMEOUT", "300"))
CSV_POLL_INTERVAL = float(os.getenv("HOST_CSV_POLL_INTERVAL", "2.0"))


def produce_csv_rows_to_kafka(csv_path, producer):
    """Reads generated CSV and streams each row to Kafka."""
    try:
        df = pd.read_csv(csv_path)

        for _, row in df.iterrows():
            msg = {
                "timestamp": datetime.utcnow().isoformat(),
                "flow": row.to_dict(),
                "event_type": "network_flow",
                "source": os.path.basename(csv_path)
            }
            producer.send("network-flows", value=msg)

        producer.flush()
        print(f"[Flow Stream] ✔ Sent {len(df)} flows to Kafka")

    except Exception as e:
        print(f"[Flow Stream] ❌ Error streaming CSV {csv_path}: {e}")


def _most_recent_file_matching(pattern, since_seconds=360):
    files = glob.glob(pattern)
    if not files:
        return None
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    now = time.time()
    for f in files:
        if now - os.path.getmtime(f) <= since_seconds:
            return f
    return files[0]


def _list_dir_debug(path):
    try:
        items = os.listdir(path)
    except Exception as e:
        return f"<ls failed: {e}>"
    out = []
    for fn in items:
        p = os.path.join(path, fn)
        try:
            st = os.stat(p)
            m = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
            out.append(f"{fn} (size={st.st_size} mtime={m})")
        except Exception:
            out.append(fn + " (stat failed)")
    return "\n".join(out)


def wait_for_csv_for_pcap(pcap_path, csv_dir, timeout=CSV_WAIT_TIMEOUT, poll_interval=CSV_POLL_INTERVAL):
    """
    Wait (poll) for a CSV corresponding to the given pcap to appear in csv_dir.
    This function expects that you will run cicflowmeter on the host and then copy
    the resulting CSV into csv_dir (or that a host-mounted directory is used).

    Matching strategies (in order):
      1) exact: <pcap_basename>_flows.csv
      2) any "*_flows.csv" in csv_dir modified after pcap mtime
      3) any "*.csv" in csv_dir modified after pcap mtime
    Returns path to CSV if found, otherwise None after timeout.
    """
    base = os.path.basename(pcap_path)
    expected_name = base + "_flows.csv"
    expected_path = os.path.join(csv_dir, expected_name)

    start = time.time()
    pcap_mtime = 0
    try:
        pcap_mtime = os.path.getmtime(pcap_path)
    except Exception:
        pcap_mtime = time.time()

    print(f"[FlowGen] ▶ Waiting up to {timeout}s for CSV for {base} in {csv_dir}...")

    while True:
        # 1) exact match
        if os.path.exists(expected_path):
            print(f"[FlowGen] ✔ Found exact CSV: {expected_path}")
            return expected_path

        # 2) any *_flows.csv created/modified after pcap mtime
        candidate = _most_recent_file_matching(os.path.join(csv_dir, "*_flows.csv"), since_seconds=timeout + 10)
        if candidate:
            try:
                if os.path.getmtime(candidate) >= pcap_mtime - 1:
                    print(f"[FlowGen] ⚠ Found candidate *_flows.csv: {candidate}")
                    return candidate
            except Exception:
                pass

        # 3) any CSV in csv_dir modified after pcap mtime
        any_csv = _most_recent_file_matching(os.path.join(csv_dir, "*.csv"), since_seconds=timeout + 10)
        if any_csv:
            try:
                if os.path.getmtime(any_csv) >= pcap_mtime - 1:
                    print(f"[FlowGen] ⚠ Found candidate *.csv: {any_csv}")
                    return any_csv
            except Exception:
                pass

        # timed out?
        elapsed = time.time() - start
        if elapsed > timeout:
            print(f"[FlowGen] ❌ Timeout waiting for CSV for {base} (waited {elapsed:.1f}s). Directory listing:\n{_list_dir_debug(csv_dir)}")
            return None

        time.sleep(poll_interval)


def capture_pcap_segment(segment_id, iface="eth0", duration=10):
    """
    Capture a PCAP segment using tcpdump for `duration` seconds.
    Returns the path to the captured pcap file.
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(PCAP_DIR, f"seg_{segment_id}_{ts}.pcap")

    print(f"[PCAP] 🎥 Capturing {pcap_file} for {duration}s on iface {iface}...")

    # tcpdump rotates (-G) and writes to the specified file; we run it for `duration` seconds
    cmd = [
        "tcpdump",
        "-i", iface,
        "-w", pcap_file,
        "-s", "0"       # full packet capture
    ]

    # run tcpdump in background for the specified duration then kill it
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(duration)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # sanity check: ensure file was created and is non-empty
    if not os.path.exists(pcap_file):
        print(f"[PCAP] ❌ tcpdump failed to create {pcap_file}")
        return None
    try:
        size = os.path.getsize(pcap_file)
        if size == 0:
            print(f"[PCAP] ❌ empty pcap created: {pcap_file}")
            return None
    except Exception as e:
        print(f"[PCAP] ⚠ could not stat pcap: {e}")

    print(f"[PCAP] ✔ Captured {pcap_file} (size ~{size} bytes)")
    return pcap_file


def main():
    """Main continuous pipeline."""
    try:
        producer = KafkaProducer(
            bootstrap_servers=os.getenv("KAFKA_BROKER", "kafka:9092"),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            retries=3
        )
        print("[Kafka] ✔ Connected to broker")
    except Exception as e:
        print(f"[Kafka] ❌ Connection failed: {e}")
        return

    print("[Network Stream] 🚀 Starting PCAP → CSV → Kafka pipeline...\n")

    segment = 0
    while True:
        # 1. Capture one PCAP chunk
        pcap_path = capture_pcap_segment(segment)
        if not pcap_path:
            # capture failed; wait a bit and retry
            time.sleep(2)
            continue

        # 2. Wait for host to process PCAP and copy CSV back into CSV_DIR
        csv_path = wait_for_csv_for_pcap(pcap_path, CSV_DIR)
        if csv_path:
            # 3. Stream CSV rows to Kafka
            produce_csv_rows_to_kafka(csv_path, producer)
        else:
            print(f"[FlowGen] ⚠ No CSV for pcap {pcap_path}; skipping streaming for this segment.")

        # Metadata event (always send so you have an audit trail)
        try:
            producer.send("network-logs", value={
                "timestamp": datetime.utcnow().isoformat(),
                "pcap_file": pcap_path,
                "csv_file": csv_path,
                "event": "segment_completed"
            })
            producer.flush()
        except Exception as e:
            print(f"[Kafka] ❌ Failed to send metadata event: {e}")

        segment += 1
        # small delay to avoid tight-looping if host is slow; adjust if you want continuous capture
        time.sleep(1)


if __name__ == "__main__":
    main()
