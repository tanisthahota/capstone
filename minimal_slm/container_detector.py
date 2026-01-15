#!/usr/bin/env python3
"""
Container Layer Threat Detector with Preprocessing
Consumes from container-logs topic and detects threats
Publishes threats to threat-alerts topic
"""

import json
import re
import torch
import uuid
import os
from pathlib import Path
from kafka import KafkaConsumer, KafkaProducer
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from datetime import datetime
    
THREAT_CONFIDENCE_THRESHOLD = 0.7

# Auto-detect environment (Docker vs local)
def get_model_path():
    """Detect model path based on environment"""
    docker_path = "/workspace/slm/container_final_model"
    local_path = os.path.join(os.path.dirname(__file__), "container_final_model")
    
    if os.path.exists(docker_path):
        return docker_path
    elif os.path.exists(local_path):
        return local_path
    else:
        raise FileNotFoundError(f"Model not found at {docker_path} or {local_path}")

def get_kafka_broker():
    """Detect Kafka broker based on environment"""
    # Check if we're in Docker (kafka hostname exists) or local (use localhost)
    try:
        import socket
        socket.gethostbyname('kafka')
        return 'kafka:9092'  # Docker environment
    except:
        return 'localhost:9092'  # Local environment

def preprocess_container_log(log):
    """Convert a Docker JSON event log into flattened text format."""

    # Parse JSON if passed as a string
    if isinstance(log, str):
        log = json.loads(log)

    event_type = log.get("Action", "")
    image = log.get("from", "")
    container_id = log.get("id", "")
    actor = log.get("Actor", {})
    attributes = actor.get("Attributes", {})
    container_name = attributes.get("name", "")
    scope = log.get("scope", "")
    time = log.get("time", "")
    time_nano = log.get("timeNano", "")

    # Flatten attributes similar to your example
    attr_str = re.sub(r'\s+', ' ', str({
        "ID": actor.get("ID", ""),
        "Attributes": attributes
    }))

    return (
        f"{event_type}: {image} {container_id} {container_name} container "
        f"{event_type}: {image} {attr_str} {scope} {time} {time_nano}"
    )

def main():
    # Load Container Model
    print("\n🔴 CONTAINER LAYER: Loading model...")
    try:
        model_path = get_model_path()
        print(f"  📍 Using model path: {model_path}")
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
    kafka_broker = get_kafka_broker()
    print(f"\n🔴 CONTAINER LAYER: Connecting to Kafka topic 'container-logs' at {kafka_broker}...")
    try:
        consumer = KafkaConsumer(
            'container-logs',
            bootstrap_servers=kafka_broker,
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            group_id='container-detector'
        )
        print("  ✅ Connected to Kafka Consumer")
    except Exception as e:
        print(f"  ❌ Failed to connect: {e}")
        print(f"  💡 Make sure Kafka is running and accessible at {kafka_broker}")
        return
    
    # Connect to Kafka Producer for threat alerts
    print(f"\n🔴 CONTAINER LAYER: Connecting to Kafka Producer for threat-alerts at {kafka_broker}...")
    try:
        threat_producer = KafkaProducer(
            bootstrap_servers=[kafka_broker],
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
                    'source_ip': log_data.get('actor_id', '172.19.0.12'),
                    'target_container': log_data.get('actor_id', 'api-gateway'),
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