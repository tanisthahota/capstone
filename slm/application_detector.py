#!/usr/bin/env python3
"""
Application Layer Threat Detector
Consumes from application-logs topic and detects SQLi/XSS threats
Publishes threats to threat-alerts topic
"""

import json
import torch
import uuid
from kafka import KafkaConsumer, KafkaProducer
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel
from datetime import datetime

THREAT_CONFIDENCE_THRESHOLD = 0.7

def main():
    # Load Application Model (DistilBERT + LoRA)
    print("\n🔵 APPLICATION LAYER: Loading DistilBERT + LoRA model...")
    try:
        adapter_path = "/workspace/slm/application_model_new"
        base_model_name = "answerdotai/ModernBERT-base"
        label_map = {0: "Normal", 1: "SQLi", 2: "XSS"}
        
        tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        base_model = AutoModelForSequenceClassification.from_pretrained(base_model_name, num_labels=3)
        model = PeftModel.from_pretrained(base_model, adapter_path)
        
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        print(f"  ✅ Application model loaded on {device}")
    except Exception as e:
        print(f"  ❌ Failed to load model: {e}")
        return
    
    # Connect to Kafka Consumer
    print("\n🔵 APPLICATION LAYER: Connecting to Kafka topic 'application-logs'...")
    try:
        consumer = KafkaConsumer(
            'application-logs',
            bootstrap_servers='kafka:9092',
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            group_id='application-detector'
        )
        print("  ✅ Connected to Kafka Consumer")
    except Exception as e:
        print(f"  ❌ Failed to connect: {e}")
        return
    
    # Connect to Kafka Producer for threat alerts
    print("\n🔵 APPLICATION LAYER: Connecting to Kafka Producer for threat-alerts...")
    try:
        threat_producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        print("  ✅ Connected to Kafka Producer")
    except Exception as e:
        print(f"  ❌ Failed to connect to producer: {e}")
        return
    
    print("\n🔵 APPLICATION LAYER: Listening for application events...\n")
    
    for message in consumer:
        try:
            log_data = message.value
            
            # Extract content
            content = log_data.get('content', '')
            method = log_data.get('Method', '')
            url = log_data.get('URL', '')
            
            # Parse JSON content if it's a string
            try:
                if isinstance(content, str) and content:
                    content_dict = json.loads(content)
                    # Extract email/password fields which contain the payload
                    email = content_dict.get('email', '')
                    password = content_dict.get('password', '')
                    # Combine for better context
                    content_text = f"{email} "
                else:
                    content_text = str(content)
            except:
                content_text = str(content)
            
            # Prepare text for model - include more context
            text = f"{content_text}"
            
            # Tokenize and predict
            inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=1024).to(device)
            with torch.no_grad():
                outputs = model(**inputs)
            
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            conf, pred_idx = torch.max(probs, dim=1)
            
            threat_type = label_map[pred_idx.item()]
            confidence = conf.item()
            
            # Get all probabilities for debugging
            all_probs = probs[0].cpu().numpy()
            prob_normal = all_probs[0]
            prob_sqli = all_probs[1]
            prob_xss = all_probs[2]
            
            # Alert if threat
            if threat_type != "Normal" and confidence > THREAT_CONFIDENCE_THRESHOLD:
                print(f"🚨 [THREAT DETECTED] Application Layer")
                print(f"   Type: {threat_type}")
                print(f"   Method: {method}")
                print(f"   URL: {url}")
                print(f"   Content: {content_text[:100]}...")
                print(f"   Confidence: {confidence:.2%}")
                print(f"   Probabilities - Normal: {prob_normal:.2%}, SQLi: {prob_sqli:.2%}, XSS: {prob_xss:.2%}")
                print(f"   Timestamp: {log_data.get('timestamp')}\n")
                
                # Create and publish threat alert
                threat_alert = {
                    'alert_id': str(uuid.uuid4()),
                    'threat_name': threat_type,
                    'source_ip': log_data.get('source_ip', log_data.get('client_ip', '172.19.0.3')),
                    'target_container': 'api-gateway',
                    'confidence': confidence,
                    'layer': 'application',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': {
                        'raw_log': f"{method} {url}",
                        'model_output': f'Threat: {threat_type}, Confidence: {confidence:.2%}'
                    }
                }
                threat_producer.send('threat-alerts', value=threat_alert)
                print(f"📤 Threat alert published to Kafka\n")
            else:
                # Show detailed probabilities for debugging
                if threat_type != "Normal":
                    print(f"⚠️  [LOW CONFIDENCE] {threat_type} | {method} {url}")
                    print(f"   Probabilities - Normal: {prob_normal:.2%}, SQLi: {prob_sqli:.2%}, XSS: {prob_xss:.2%}")
                else:
                    print(f"✅ [BENIGN] {method} {url} | Conf: {confidence:.2%}")
        
        except Exception as e:
            print(f"Error processing message: {e}")

if __name__ == '__main__':
    main()
