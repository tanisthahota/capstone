#!/usr/bin/env python3
"""
Network Layer Threat Detector with Preprocessing
Consumes from network-logs topic and detects threats
Publishes threats to threat-alerts topic
"""

import json
import torch
import uuid
from kafka import KafkaConsumer, KafkaProducer
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datetime import datetime

THREAT_CONFIDENCE_THRESHOLD = 0.7

def preprocess_network_log(log_data):
    """
    Preprocess network logs similar to network_slm.ipynb
    Converts numeric features to "feature:value" format
    """
    features = []
    
    # Extract all numeric fields and format as "field:value"
    numeric_fields = [
        'src_port', 'dst_port', 'bytes_sent', 'bytes_received',
        'packet_id', 'src_ip', 'dst_ip', 'protocol'
    ]
    
    for field in numeric_fields:
        if field in log_data:
            value = log_data[field]
            if isinstance(value, (int, float)):
                features.append(f"{field}:{int(value)}")
            else:
                features.append(f"{field}:{value}")
    
    # Join all features like the notebook does
    text = " ".join(features)
    return text.strip()

def main():
    # Load Network Model
    print("\n🟢 NETWORK LAYER: Loading model...")
    try:
        model_path = "/app/network_model"
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        label_map = {0: "BENIGN", 1: "BRUTE_FORCE", 2: "DOS", 3: "PORTSCAN"}
        print(f"  ✅ Network model loaded on {device}")
    except Exception as e:
        print(f"  ❌ Failed to load model: {e}")
        return
    
    # Connect to Kafka Consumer
    print("\n🟢 NETWORK LAYER: Connecting to Kafka topic 'network-logs'...")
    try:
        consumer = KafkaConsumer(
            'network-logs',
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
            text = preprocess_network_log(log_data)
            
            # Tokenize and predict
            inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512).to(device)
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
                print(f"   Source: {log_data.get('src_ip')}")
                print(f"   Destination: {log_data.get('dst_ip')}")
                print(f"   Confidence: {confidence:.2%}")
                print(f"   Timestamp: {log_data.get('timestamp')}\n")
                
                # Create and publish threat alert
                threat_alert = ThreatAlert(
                    threat_name=threat_type,
                    source_ip=log_data.get('src_ip', 'unknown'),
                    target_container='api-gateway',  # Network threats target gateway
                    confidence=confidence,
                    layer='network',
                    details={
                        'raw_log': str(log_data),
                        'model_output': f'Threat: {threat_type}, Confidence: {confidence:.2%}'
                    }
                )
                threat_producer.send('threat-alerts', value=threat_alert.to_dict())
                print(f"📤 Threat alert published to Kafka\n")
            else:
                print(f"✅ [BENIGN] {threat_type} | {log_data.get('src_ip')} → {log_data.get('dst_ip')} | Conf: {confidence:.2%}")
        
        except Exception as e:
            print(f"Error processing message: {e}")

if __name__ == '__main__':
    main()