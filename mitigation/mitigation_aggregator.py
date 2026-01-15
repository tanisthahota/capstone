#!/usr/bin/env python3
"""
Mitigation Aggregator
Collects threat alerts from all layers and sends to mitigation topic
Extracts: source_ip, threat_name, target_container
"""

import json
import sys
from kafka import KafkaConsumer, KafkaProducer

def main():
    print("\n🛑 MITIGATION AGGREGATOR: Starting...")
    print("Listening for threat alerts from all layers\n")
    
    # Connect to Kafka Consumer for threat-alerts
    try:
        consumer = KafkaConsumer(
            'threat-alerts',
            bootstrap_servers='kafka:9092',
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            group_id='mitigation-aggregator'
        )
        print("  ✅ Connected to threat-alerts topic")
    except Exception as e:
        print(f"  ❌ Failed to connect: {e}")
        return
    
    # Connect to Kafka Producer for mitigation
    try:
        producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        print("  ✅ Connected to mitigation producer\n")
    except Exception as e:
        print(f"  ❌ Failed to connect to producer: {e}")
        return
    
    print("\n🛑 MITIGATION AGGREGATOR: Listening for threats...\n")
    
    threat_count = 0
    
    for message in consumer:
        try:
            threat_alert = message.value
            
            # Extract all fields
            source_ip = threat_alert.get('source_ip', 'N/A')
            threat_name = threat_alert.get('threat_name', 'unknown')
            target_container = threat_alert.get('target_container', 'N/A')
            layer = threat_alert.get('layer', 'unknown')
            confidence = threat_alert.get('confidence', 0)
            
            # Always include threat_name in mitigation record
            mitigation_record = {
                'threat_name': threat_name,
                'layer': layer,
                'confidence': confidence,
                'timestamp': threat_alert.get('timestamp')
            }
            
            # Add fields based on threat type
            if threat_name.lower() in ['dos', 'ddos', 'portscan', 'bruteforce']:
                # Only source_ip
                mitigation_record['source_ip'] = source_ip
                mitigation_record['target_container'] = 'N/A'
                print(f"🚨 [THREAT #{threat_count + 1}] {layer.upper()} LAYER")
                print(f"   Threat: {threat_name}")
                print(f"   Source IP: {source_ip}")
                print(f"   Confidence: {confidence:.2%}\n")
            
            elif threat_name.lower() in ['xss', 'sqli', 'reverse_shell']:
                # source_ip + target_container
                mitigation_record['source_ip'] = source_ip
                mitigation_record['target_container'] = target_container
                print(f"🚨 [THREAT #{threat_count + 1}] {layer.upper()} LAYER")
                print(f"   Threat: {threat_name}")
                print(f"   Source IP: {source_ip}")
                print(f"   Target: {target_container}")
                print(f"   Confidence: {confidence:.2%}\n")
            
            elif threat_name.lower() in ['priv_esc', 'privilege_escalation']:
                # Only target_container
                mitigation_record['source_ip'] = 'N/A'
                mitigation_record['target_container'] = target_container
                print(f"🚨 [THREAT #{threat_count + 1}] {layer.upper()} LAYER")
                print(f"   Threat: {threat_name}")
                print(f"   Target: {target_container}")
                print(f"   Confidence: {confidence:.2%}\n")
            
            else:
                # Unknown threat - include all fields
                mitigation_record['source_ip'] = source_ip
                mitigation_record['target_container'] = target_container
                print(f"🚨 [THREAT #{threat_count + 1}] {layer.upper()} LAYER")
                print(f"   Threat: {threat_name}")
                print(f"   Source IP: {source_ip}")
                print(f"   Target: {target_container}")
                print(f"   Confidence: {confidence:.2%}\n")
            
            # Send to mitigation topic
            producer.send('mitigation', value=mitigation_record)
            threat_count += 1
        
        except Exception as e:
            print(f"Error processing threat: {e}")
            continue

if __name__ == '__main__':
    main()