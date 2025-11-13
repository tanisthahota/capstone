#!/usr/bin/env python3
"""
Container Layer Threat Detector with Preprocessing
Consumes from container-logs topic and detects threats
Publishes threats to threat-alerts topic
"""

import json
import torch
import uuid
from kafka import KafkaConsumer, KafkaProducer
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datetime import datetime

THREAT_CONFIDENCE_THRESHOLD = 0.95

def preprocess_container_log(log_data):
    """
    Preprocess container logs similar to CONT_SLM.ipynb
    Joins all fields into a single text string
    """
    action = log_data.get('action', '')
    actor_id = log_data.get('actor_id', '')
    actor_attributes = log_data.get('actor_attributes', {})
    event_type = log_data.get('event_type', '')
    
    # Convert attributes dict to string
    attr_str = ' '.join([f"{k}:{v}" for k, v in actor_attributes.items()])
    
    # Join all fields like the notebook does
    text = f"{action} {actor_id} {attr_str} {event_type}"
    return text.strip()

def main():
    # Load Container Model
    print("\n🔴 CONTAINER LAYER: Loading model...")
    try:
        model_path = "/app/container_model"
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        label_map = {0: "benign", 1: "reverse_shell", 2: "priv_esc"}
        print(f"  ✅ Container model loaded on {device}")
    except Exception as e:
        print(f"  ❌ Failed to load model: {e}")
        return
    
    # Connect to Kafka Consumer
    print("\n🔴 CONTAINER LAYER: Connecting to Kafka topic 'container-logs'...")
    try:
        consumer = KafkaConsumer(
            'container-logs',
            bootstrap_servers='kafka:9092',
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            group_id='container-detector'
        )
        print("  ✅ Connected to Kafka Consumer")
    except Exception as e:
        print(f"  ❌ Failed to connect: {e}")
        return
    
    # Connect to Kafka Producer for threat alerts
    print("\n🔴 CONTAINER LAYER: Connecting to Kafka Producer for threat-alerts...")
    try:
        threat_producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        print("  ✅ Connected to Kafka Producer")
    except Exception as e:
        print(f"  ❌ Failed to connect to producer: {e}")
        return
    
    print("\n🔴 CONTAINER LAYER: Listening for container events...\n")
    
    for message in consumer:
        try:
            log_data = message.value
            
            # Preprocess the log
            text = preprocess_container_log(log_data)
            
            # Tokenize and predict
            inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=256).to(device)
            with torch.no_grad():
                outputs = model(**inputs)
            
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            conf, pred_idx = torch.max(probs, dim=1)
            
            threat_type = label_map[pred_idx.item()]
            confidence = conf.item()
            
            # Alert if threat (high confidence threshold to avoid false positives)
            if threat_type != "benign" and confidence > THREAT_CONFIDENCE_THRESHOLD:
                print(f"🚨 [THREAT DETECTED] Container Layer")
                print(f"   Type: {threat_type}")
                print(f"   Action: {log_data.get('action')}")
                print(f"   Container: {log_data.get('actor_id')}")
                print(f"   Confidence: {confidence:.2%}")
                print(f"   Timestamp: {log_data.get('timestamp')}\n")
                
                # Create and publish threat alert
                threat_alert = {
                    'alert_id': str(uuid.uuid4()),
                    'threat_name': threat_type,
                    'source_ip': log_data.get('actor_id', 'unknown'),
                    'target_container': log_data.get('actor_id', 'unknown'),
                    'confidence': confidence,
                    'layer': 'container',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {
                        'raw_log': str(log_data),
                        'model_output': f'Threat: {threat_type}, Confidence: {confidence:.2%}'
                    }
                }
                threat_producer.send('threat-alerts', value=threat_alert)
                print(f"📤 Threat alert published to Kafka\n")
            else:
                print(f"✅ [BENIGN] {threat_type} | {log_data.get('action')} | Conf: {confidence:.2%}")
        
        except Exception as e:
            print(f"Error processing message: {e}")

if __name__ == '__main__':
    main()