import json
from kafka import KafkaProducer
import time

# The threat alert JSON you provided
threat_alert_json = '''
{
    "alert_id": "477a17ef-b3e6-43b3-8962-b9e88d399d52",
    "threat_name": "PORTSCAN",
    "source_ip": "unknown",
    "target_container": "api-gateway",
    "confidence": 0.9319459795951843,
    "layer": "network",
    "timestamp": "2025-11-23T08:24:40.615239",
    "details": {
        "raw_log": "{'timestamp': '2025-11-23T07:56:20.640575', 'flow': {'src_ip': '172.19.0.3', 'dst_ip': '172.19.0.4', 'src_port': 56834, 'dst_port': 9092, 'protocol': 6, 'timestamp': '2025-11-23 13:25:58', 'flow_duration': 0.0, 'flow_byts_s': 0.0, 'flow_pkts_s': 0.0, 'fwd_pkts_s': 0.0, 'bwd_pkts_s': 0.0, 'tot_fwd_pkts': 2, 'tot_bwd_pkts': 0, 'totlen_fwd_pkts': 132, 'totlen_bwd_pkts': 0, 'fwd_pkt_len_max': 66, 'fwd_pkt_len_min': 66, 'fwd_pkt_len_mean': 66.0, 'fwd_pkt_len_std': 0.0, 'bwd_pkt_len_max': 0, 'bwd_pkt_len_min': 0, 'bwd_pkt_len_mean': 0.0, 'bwd_pkt_len_std': 0.0, 'pkt_len_max': 66, 'pkt_len_min': 66, 'pkt_len_mean': 66.0, 'pkt_len_std': 0.0, 'pkt_len_var': 0.0, 'fwd_header_len': 40, 'bwd_header_len': 0, 'fwd_seg_size_min': 20, 'fwd_act_data_pkts': 0, 'flow_iat_mean': 0.0, 'flow_iat_max': 0.0, 'flow_iat_min': 0.0, 'flow_iat_std': 0.0, 'fwd_iat_tot': 0.0, 'fwd_iat_max': 0.0, 'fwd_iat_min': 0.0, 'fwd_iat_mean': 0.0, 'fwd_iat_std': 0.0, 'bwd_iat_tot': 0.0, 'bwd_iat_max': 0.0, 'bwd_iat_min': 0.0, 'bwd_iat_mean': 0.0, 'bwd_iat_std': 0.0, 'fwd_psh_flags': 0, 'bwd_psh_flags': 0, 'fwd_urg_flags': 0, 'bwd_urg_flags': 0, 'fin_flag_cnt': 0, 'syn_flag_cnt': 0, 'rst_flag_cnt': 0, 'psh_flag_cnt': 0, 'ack_flag_cnt': 2, 'urg_flag_cnt': 0, 'ece_flag_cnt': 0, 'down_up_ratio': 0.0, 'pkt_size_avg': 66.0, 'init_fwd_win_byts': 63, 'init_bwd_win_byts': 0, 'active_max': 0, 'active_min': 0, 'active_mean': 0, 'active_std': 0, 'idle_max': 0, 'idle_min': 0, 'idle_mean': 0, 'idle_std': 0, 'fwd_byts_b_avg': 0, 'fwd_pkts_b_avg': 0, 'bwd_byts_b_avg': 0, 'bwd_pkts_b_avg': 0, 'fwd_blk_rate_avg': 0, 'bwd_blk_rate_avg': 0, 'fwd_seg_size_avg': 66.0, 'bwd_seg_size_avg': 0.0, 'cwr_flag_count': 0, 'subflow_fwd_pkts': 2, 'subflow_bwd_pkts': 0, 'subflow_fwd_byts': 132, 'subflow_bwd_byts': 0}, 'event_type': 'network_flow', 'source': 'seg_0_20251123_075558_flows.csv'}",
        "model_output": "Threat: PORTSCAN, Confidence: 93.19%"
    }
}
'''

def main():
    # 1. Parse the threat alert to get the raw log
    threat_alert = json.loads(threat_alert_json)
    raw_log_str = threat_alert['details']['raw_log']
    
    # The raw_log is a string representation of a dict, so we use eval to parse it.
    # In a real-world scenario, you'd want a safer parsing method.
    try:
        original_message = eval(raw_log_str)
    except Exception as e:
        print(f"Error parsing raw_log: {e}")
        return

    # 2. Connect to Kafka Producer
    print("Connecting to Kafka producer...")
    try:
        producer = KafkaProducer(
            bootstrap_servers='kafka:9092',
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            api_version=(0, 10, 1) # Specify a compatible API version
        )
        print("Connected to Kafka!")
    except Exception as e:
        print(f"Failed to connect to Kafka: {e}")
        return

    # 3. Send the original message to the 'network-flows' topic
    try:
        print(f"Sending message to 'network-flows' topic...")
        producer.send('network-flows', value=original_message)
        producer.flush() # Ensure the message is sent
        print("Message sent successfully!")
        print("Check the logs of the 'network_detector' container to see the result.")
    except Exception as e:
        print(f"Failed to send message: {e}")
    finally:
        producer.close()

if __name__ == '__main__':
    main()
