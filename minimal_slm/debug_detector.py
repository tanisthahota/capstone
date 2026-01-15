import json
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import ast

# Copied directly from network_detector.py
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
FEATURE_COLS = [c for c in EXPECTED_COLS if c not in DROP_COLS]

def preprocess_network_log(log_data):
    features = []
    for col in FEATURE_COLS:
        val = log_data.get(col)
        if val is None:
            continue
        try:
            if isinstance(val, float) and (np.isnan(val) or np.isinf(val)):
                continue
        except (TypeError, ValueError):
            pass
        if isinstance(val, (int, float, np.number)):
            features.append(f"{col}:{int(val) if isinstance(val, (int, np.integer)) else val}")
        else:
            features.append(f"{col}:{val}")
    return " ".join(features)


def main():
    # The raw log string from the original threat alert
    raw_log_str = "{'timestamp': '2025-11-23T07:56:20.640575', 'flow': {'src_ip': '172.19.0.3', 'dst_ip': '172.19.0.4', 'src_port': 56834, 'dst_port': 9092, 'protocol': 6, 'timestamp': '2025-11-23 13:25:58', 'flow_duration': 0.0, 'flow_byts_s': 0.0, 'flow_pkts_s': 0.0, 'fwd_pkts_s': 0.0, 'bwd_pkts_s': 0.0, 'tot_fwd_pkts': 2, 'tot_bwd_pkts': 0, 'totlen_fwd_pkts': 132, 'totlen_bwd_pkts': 0, 'fwd_pkt_len_max': 66, 'fwd_pkt_len_min': 66, 'fwd_pkt_len_mean': 66.0, 'fwd_pkt_len_std': 0.0, 'bwd_pkt_len_max': 0, 'bwd_pkt_len_min': 0, 'bwd_pkt_len_mean': 0.0, 'bwd_pkt_len_std': 0.0, 'pkt_len_max': 66, 'pkt_len_min': 66, 'pkt_len_mean': 66.0, 'pkt_len_std': 0.0, 'pkt_len_var': 0.0, 'fwd_header_len': 40, 'bwd_header_len': 0, 'fwd_seg_size_min': 20, 'fwd_act_data_pkts': 0, 'flow_iat_mean': 0.0, 'flow_iat_max': 0.0, 'flow_iat_min': 0.0, 'flow_iat_std': 0.0, 'fwd_iat_tot': 0.0, 'fwd_iat_max': 0.0, 'fwd_iat_min': 0.0, 'fwd_iat_mean': 0.0, 'fwd_iat_std': 0.0, 'bwd_iat_tot': 0.0, 'bwd_iat_max': 0.0, 'bwd_iat_min': 0.0, 'bwd_iat_mean': 0.0, 'bwd_iat_std': 0.0, 'fwd_psh_flags': 0, 'bwd_psh_flags': 0, 'fwd_urg_flags': 0, 'bwd_urg_flags': 0, 'fin_flag_cnt': 0, 'syn_flag_cnt': 0, 'rst_flag_cnt': 0, 'psh_flag_cnt': 0, 'ack_flag_cnt': 2, 'urg_flag_cnt': 0, 'ece_flag_cnt': 0, 'down_up_ratio': 0.0, 'pkt_size_avg': 66.0, 'init_fwd_win_byts': 63, 'init_bwd_win_byts': 0, 'active_max': 0, 'active_min': 0, 'active_mean': 0, 'active_std': 0, 'idle_max': 0, 'idle_min': 0, 'idle_mean': 0, 'idle_std': 0, 'fwd_byts_b_avg': 0, 'fwd_pkts_b_avg': 0, 'bwd_byts_b_avg': 0, 'bwd_pkts_b_avg': 0, 'fwd_blk_rate_avg': 0, 'bwd_blk_rate_avg': 0, 'fwd_seg_size_avg': 66.0, 'bwd_seg_size_avg': 0.0, 'cwr_flag_count': 0, 'subflow_fwd_pkts': 2, 'subflow_bwd_pkts': 0, 'subflow_fwd_byts': 132, 'subflow_bwd_byts': 0}, 'event_type': 'network_flow', 'source': 'seg_0_20251123_075558_flows.csv'}"
    
    # Use ast.literal_eval for safe parsing of the string representation of the dictionary
    log_data = ast.literal_eval(raw_log_str)
    flow_data = log_data.get('flow', {})

    # Load Model
    print("Loading model...")
    model_path = "/workspace/slm/network_model_new"
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path, num_labels=4)
    device = torch.device("cpu")
    model.to(device)
    model.eval()
    label_map = {0: "BENIGN", 1: "BRUTE_FORCE", 2: "DOS", 3: "PORTSCAN"}
    print("Model loaded.")

    # Preprocess the log data
    print("\n--- Preprocessing Input ---")
    text = preprocess_network_log(flow_data)
    print(text)

    # Tokenize and Predict
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True).to(device)
    with torch.no_grad():
        outputs = model(**inputs)
    
    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    
    print("\n--- Model Prediction --- ")
    print(f"Prediction: {label_map[torch.argmax(probs).item()]}")
    print("\n--- Confidence Scores ---")
    for i, label in label_map.items():
        print(f"{label}: {probs[0][i].item():.4f}")

if __name__ == '__main__':
    main()
