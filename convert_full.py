import pandas as pd
import socket
import numpy as np

df = pd.read_csv(r'C:\Users\zwano\OneDrive\Desktop\capstone\pcap.csv')

source_ip = "10.14.143.218"
dest_ip = "224.0.0.251"

def get_client_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

client_ip = get_client_ip()
df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
df = df.dropna(subset=["Time"])

# FLOW LEVEL FEATURES
def flow_duration(): return (df["Time"].max() - df["Time"].min()).total_seconds()
def total_fwd_packets(): return len(df[df["Source"] == source_ip])
def total_bwd_packets(): return len(df[df["Source"] == dest_ip])
def total_length_fwd(): return df[df["Source"] == source_ip]["Length"].sum()
def total_length_bwd(): return df[df["Source"] == dest_ip]["Length"].sum()
def total_length(): return df["Length"].sum()

# PACKET LENGTH STATISTICS
def packet_length_stats():
    pl = df["Length"]
    return pl.mean(), pl.std(), pl.min(), pl.max(), pl.var()

# FORWARD/BACKWARD MEAN LENGTH
def fwd_bwd_packet_length_mean():
    fwd = df[df["Source"] == source_ip]["Length"]
    bwd = df[df["Source"] == dest_ip]["Length"]
    return fwd.max(), fwd.min(), fwd.mean(), fwd.std(), bwd.max(), bwd.min(), bwd.mean(), bwd.std()

# INTER-ARRIVAL TIME (IAT) STATS
def iat_stats():
    times = df["Time"].sort_values().diff().dt.total_seconds().dropna()
    return times.mean(), times.std(), times.min(), times.max()

# PROTOCOL COUNTS
def protocol_count(protocol="TCP"):
    return len(df[df["Protocol"] == protocol])

# HEADER LENGTH APPROXIMATION
def header_length_estimate():
    # Assuming Ethernet (14) + IP (20) + TCP (20) = 54 bytes
    return 54 * len(df)

# AVERAGE PACKET SIZE & RATE
def flow_bytes_per_sec():
    duration = flow_duration()
    return total_length() / duration if duration > 0 else 0

def flow_packets_per_sec():
    duration = flow_duration()
    return len(df) / duration if duration > 0 else 0

def average_packet_size():
    return total_length() / len(df) if len(df) > 0 else 0

def download_upload_ratio():
    # Total length of data received by the destination (download)
    download = df[df["Destination"] == dest_ip]["Length"].sum()
    
    # Total length of data sent from the source (upload)
    upload = df[df["Source"] == source_ip]["Length"].sum()
    
    # Avoid division by zero
    return download / upload if upload > 0 else 0

# All 72 features from the CICIDS dataset
fwd_max, fwd_min, fwd_mean, fwd_std, bwd_max, bwd_min, bwd_mean, bwd_std = fwd_bwd_packet_length_mean()
iat_mean, iat_std, iat_min, iat_max = iat_stats()
mean_pl, std_pl, min_pl, max_pl, var_pl = packet_length_stats()

# The final row of extracted features
row = [
    80,  # Destination Port (example value)
    flow_duration(),
    total_fwd_packets(),
    total_bwd_packets(),
    total_length_fwd(),
    total_length_bwd(),
    fwd_max, fwd_min, fwd_mean, fwd_std,
    bwd_max, bwd_min, bwd_mean, bwd_std,
    flow_bytes_per_sec(), flow_packets_per_sec(),
    iat_mean, iat_std, iat_max, iat_min,
    fwd_mean * 1000, fwd_mean, fwd_std, fwd_max, fwd_min,
    bwd_mean * 1000, bwd_mean, bwd_std, bwd_max, bwd_min,
    protocol_count("PSH"), protocol_count("PSH"),
    protocol_count("URG"), protocol_count("URG"),
    header_length_estimate(), header_length_estimate(),
    flow_packets_per_sec(), flow_packets_per_sec(),
    min_pl, max_pl, mean_pl, std_pl, var_pl,
    protocol_count("FIN"), protocol_count("SYN"),
    protocol_count("RST"), protocol_count("PSH"),
    protocol_count("ACK"), protocol_count("URG"),
    protocol_count("CWE"), protocol_count("ECE"),
    download_upload_ratio(), average_packet_size(),
    fwd_mean, bwd_mean, header_length_estimate(),
    fwd_mean / 2, fwd_mean / 3, fwd_mean / 4,  # Placeholder for avg bytes/bulk
    bwd_mean / 2, bwd_mean / 3, bwd_mean / 4,  # Placeholder for avg bytes/bulk
    total_fwd_packets(), total_length_fwd(),
    total_bwd_packets(), total_length_bwd(),
    65535,  # Init_Win_bytes_forward
    65535,  # Init_Win_bytes_backward
    1024,  # act_data_pkt_fwd
    1024,  # min_seg_size_forward
    iat_mean, iat_std, iat_max, iat_min,  # Active Mean, Active Std, Active Max, Active Min
    iat_mean, iat_std, iat_max, iat_min,  # Idle Mean, Idle Std, Idle Max, Idle Min
    "Label"  # Placeholder for the label
]

# Headers as per the given format
headers = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"
]

# Ensure that the row has the same number of items as the headers
if len(row) != len(headers):
    print(f"Row length: {len(row)}, Headers length: {len(headers)}")
else:
    df_out = pd.DataFrame([row], columns=headers)
    df_out.to_csv("cicids_72_features.csv", index=False)
    print("✅ Extracted 72 CICIDS-style features to 'cicids_72_features.csv'")
