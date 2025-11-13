#!/usr/bin/env python3
"""
Network Layer Logger - Generates synthetic flows
Streams to Kafka for threat detection
"""

import json
import sys
import time
import random
from kafka import KafkaProducer
from datetime import datetime

def main():
    try:
        producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=3
        )
        print("[Network Stream] ✅ Connected to Kafka broker")
    except Exception as e:
        print(f"[Network Stream] ❌ Failed to connect: {e}")
        sys.exit(1)
    
    print("[Network Stream] 👂 Generating network flows...")
    print("[Network Stream] Press Ctrl+C to stop\n")
    
    try:
        flow_count = 0
        while True:
            flow = {
                'timestamp': datetime.utcnow().isoformat(),
                'src_ip': f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'dst_ip': f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'src_port': random.randint(40000, 65535),
                'dst_port': random.choice([22, 80, 443]),
                'protocol': 'TCP',
                'bytes_sent': random.randint(100, 1000),
                'bytes_received': random.randint(0, 5000),
                'packets': random.randint(1, 100)
            }
            
            producer.send('network-logs', value=flow)
            print(f"[Network Stream] ✅ {flow['src_ip']}:{flow['src_port']} → {flow['dst_ip']}:{flow['dst_port']}")
            
            flow_count += 1
            time.sleep(2)
    
    except KeyboardInterrupt:
        print(f"\n[Network Stream] 🛑 Shutting down... (sent {flow_count} flows)")
        producer.close()
        sys.exit(0)

if __name__ == '__main__':
    main()