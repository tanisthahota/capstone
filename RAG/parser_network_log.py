import sys
import pandas as pd

# ============================
# EXPECTED COLUMN ORDER
# ============================
EXPECTED_COLS = [
    "src_ip","dst_ip","src_port","dst_port","protocol","timestamp",
    "flow_duration","flow_byts_s","flow_pkts_s","fwd_pkts_s","bwd_pkts_s",
    "tot_fwd_pkts","tot_bwd_pkts","totlen_fwd_pkts","totlen_bwd_pkts",
    "fwd_pkt_len_max","fwd_pkt_len_min","fwd_pkt_len_mean","fwd_pkt_len_std",
    "bwd_pkt_len_max","bwd_pkt_len_min","bwd_pkt_len_mean","bwd_pkt_len_std",
    "pkt_len_max","pkt_len_min","pkt_len_mean","pkt_len_std","pkt_len_var",
    "fwd_header_len","bwd_header_len","fwd_seg_size_min","fwd_act_data_pkts",
    "flow_iat_mean","flow_iat_max","flow_iat_min","flow_iat_std",
    "fwd_iat_tot","fwd_iat_max","fwd_iat_min","fwd_iat_mean","fwd_iat_std",
    "bwd_iat_tot","bwd_iat_max","bwd_iat_min","bwd_iat_mean","bwd_iat_std",
    "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
    "fin_flag_cnt","syn_flag_cnt","rst_flag_cnt","psh_flag_cnt","ack_flag_cnt",
    "urg_flag_cnt","ece_flag_cnt","down_up_ratio","pkt_size_avg",
    "init_fwd_win_byts","init_bwd_win_byts","active_max","active_min",
    "active_mean","active_std","idle_max","idle_min","idle_mean","idle_std",
    "fwd_byts_b_avg","fwd_pkts_b_avg","bwd_byts_b_avg","bwd_pkts_b_avg",
    "fwd_blk_rate_avg","bwd_blk_rate_avg","fwd_seg_size_avg","bwd_seg_size_avg",
    "cwr_flag_count","subflow_fwd_pkts","subflow_bwd_pkts",
    "subflow_fwd_byts","subflow_bwd_byts"
]

DROP_COLS = ['Label','src_ip','dst_ip','src_port','dst_port','timestamp']


def convert_row_to_text(row, feature_cols):
    parts = []
    for col in feature_cols:
        val = row[col]
        if pd.api.types.is_numeric_dtype(type(val)) and pd.notnull(val):
            parts.append(f"{col}:{int(val)}")
        else:
            parts.append(f"{col}:{val}")
    return " ".join(parts)


def parse_as_key_value(raw):
    parsed = {}
    tokens = raw.split()

    for token in tokens:
        if ":" not in token:
            continue
        key, val = token.split(":", 1)
        try:
            if "." in val or "e" in val.lower():
                parsed[key] = float(val)
            else:
                parsed[key] = int(val)
        except:
            parsed[key] = val
    return parsed


def parse_as_csv(raw):
    fields = raw.split(",")
    if len(fields) != len(EXPECTED_COLS):
        print(f"CSV column mismatch: got {len(fields)}, expected {len(EXPECTED_COLS)}")
        print("Raw string received:", raw)
        raise ValueError("Incorrect CSV field count")

    row = {}
    for col, val in zip(EXPECTED_COLS, fields):
        try:
            if "." in val or "e" in val.lower():
                row[col] = float(val)
            else:
                row[col] = int(val)
        except:
            row[col] = val
    return row


def main():

    if len(sys.argv) < 2:
        print("Usage: python parser_network_log.py '<raw log>'")
        sys.exit(1)

    # 🔥 FIX: join all args, restoring the full CSV including spaces
    raw = " ".join(sys.argv[1:]).strip()

    # Detect format
    if ":" in raw and "," not in raw:
        print("Detected key:value log format")
        row_dict = {col: None for col in EXPECTED_COLS}
        parsed = parse_as_key_value(raw)
        for k, v in parsed.items():
            if k in row_dict:
                row_dict[k] = v
    else:
        print("Detected CSV-style log format")
        row_dict = parse_as_csv(raw)

    # Build DataFrame
    df = pd.DataFrame([row_dict])
    feature_cols = [c for c in EXPECTED_COLS if c not in DROP_COLS]
    df["text"] = df.apply(lambda r: convert_row_to_text(r, feature_cols), axis=1)

    # print("\n=== Parsed Ordered Row ===")
    # print(df.iloc[0].to_dict())

    print("\n=== Converted Sentence ===")
    print(df["text"].iloc[0])


if __name__ == "__main__":
    main()
