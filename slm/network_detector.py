#!/usr/bin/env python3
"""
Network Layer Threat Detector with Preprocessing
Consumes from network-logs topic and detects threats
Publishes threats to threat-alerts topic
"""

import json
import torch
import uuid
import numpy as np
from kafka import KafkaConsumer, KafkaProducer
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datetime import datetime

THREAT_CONFIDENCE_THRESHOLD = 0.7

# Define the column order and columns to drop, based on the model's training
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
    """
    Preprocesses a dictionary of network flow data into a feature string.
    Ensures a consistent column order and format based on the model's training data.
    """
    features = []
    for col in FEATURE_COLS:
        val = log_data.get(col)

        # Skip if value is None or NaN/inf
        if val is None:
            continue
        try:
            if isinstance(val, float) and (np.isnan(val) or np.isinf(val)):
                continue
        except (TypeError, ValueError):
            pass

        # Format as "column:value"
        if isinstance(val, (int, float, np.number)):
            # Format integers without decimal points
            features.append(f"{col}:{int(val) if isinstance(val, (int, np.integer)) else val}")
        else:
            features.append(f"{col}:{val}")
            
    return " ".join(features)

def main():
    # Load Network Model
    print("\n🟢 NETWORK LAYER: Loading model...")
    try:
        model_path = "/workspace/slm/network_model_new"
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSequenceClassification.from_pretrained(model_path, num_labels=4)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        label_map = {0: "BENIGN", 1: "BRUTE_FORCE", 2: "DOS", 3: "PORTSCAN"}
        print(f"  ✅ Network model loaded on {device}")
    except Exception as e:
        print(f"  ❌ Failed to load model: {e}")
        return
    
    # Connect to Kafka Consumer
    print("\n🟢 NETWORK LAYER: Connecting to Kafka topic 'network-flows'...")
    try:
        consumer = KafkaConsumer(
            'network-flows',
            bootstrap_servers='kafka:9092',
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            group_id='network-detector'
        )
        print("  ✅ Connected to Kafka Consumer")
    except Exception as e:
        print(f"  ❌ Failed to connect: {e}")
        return
    
    # Connect to Kafka Producer for threat alerts
    print("\n🟢 NETWORK LAYER: Connecting to Kafka Producer for threat-alerts...")
    try:
        threat_producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        print("  ✅ Connected to Kafka Producer")
    except Exception as e:
        print(f"  ❌ Failed to connect to producer: {e}")
        return
    
    print("\n🟢 NETWORK LAYER: Listening for network events...\n")
    
    for message in consumer:
        try:
            log_data = message.value
            
            # Preprocess the log
            # Extract the nested 'flow' dictionary for preprocessing
            flow_data = log_data.get('flow', {})
            text = preprocess_network_log(flow_data)
            
            # Tokenize and predict
            inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=1024).to(device)
            with torch.no_grad():
                outputs = model(**inputs)
            
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            conf, pred_idx = torch.max(probs, dim=1)
            
            threat_type = label_map[pred_idx.item()]
            confidence = conf.item()
            
            # Alert if threat
            if threat_type != "BENIGN" and confidence > THREAT_CONFIDENCE_THRESHOLD:
                print(f"🚨 [THREAT DETECTED] Network Layer")
                print(f"   Type: {threat_type}")
                print(f"   Source: {flow_data.get('src_ip')}")
                print(f"   Destination: {flow_data.get('dst_ip')}")
                print(f"   Confidence: {confidence:.2%}")
                print(f"   Timestamp: {log_data.get('timestamp')}\n")
                
                # Create and publish threat alert
                threat_alert = {
                    'alert_id': str(uuid.uuid4()),
                    'threat_name': threat_type,
                    'source_ip': flow_data.get('src_ip', 'unknown'),
                    'target_container': 'api-gateway',  # Network threats target gateway
                    'confidence': confidence,
                    'layer': 'network',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {
                        'raw_log': str(log_data),
                        'model_output': f'Threat: {threat_type}, Confidence: {confidence:.2%}'
                    }
                }
                threat_producer.send('threat-alerts', value=threat_alert)
                print(f"📤 Threat alert published to Kafka\n")
            else:
                print(f"✅ [BENIGN] {threat_type} | {flow_data.get('src_ip')} → {flow_data.get('dst_ip')} | Conf: {confidence:.2%}")
        
        except Exception as e:
            print(f"Error processing message: {e}")

if __name__ == '__main__':
    main()