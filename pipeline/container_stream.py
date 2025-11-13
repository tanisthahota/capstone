#!/usr/bin/env python3
"""
Real-time Container Layer Logger
Streams Docker container events to Kafka continuously
"""

import json
import sys
import docker
from kafka import KafkaProducer
from datetime import datetime

def main():
    try:
        producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=3
        )
        print("[Container Stream] ✅ Connected to Kafka broker")
    except Exception as e:
        print(f"[Container Stream] ❌ Failed to connect: {e}")
        sys.exit(1)
    
    try:
        client = docker.from_env()
        print("[Container Stream] ✅ Connected to Docker")
    except Exception as e:
        print(f"[Container Stream] ❌ Failed to connect to Docker: {e}")
        sys.exit(1)
    
    print("[Container Stream] 👂 Listening for container events...")
    print("[Container Stream] Press Ctrl+C to stop\n")
    
    try:
        for event in client.events(filters={'type': 'container'}, decode=True):
            try:
                log_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'type': event.get('Type'),
                    'action': event.get('Action'),
                    'actor_id': event.get('Actor', {}).get('ID', '')[:12],
                    'actor_attributes': event.get('Actor', {}).get('Attributes', {})
                }
                producer.send('container-logs', value=log_data)
                print(f"[Container Stream] {event.get('Action')} - {log_data['actor_id']}")
            except Exception as e:
                pass
    
    except KeyboardInterrupt:
        print("\n[Container Stream] 🛑 Shutting down...")
        producer.close()
        print("[Container Stream] ✅ Closed")
        sys.exit(0)

if __name__ == '__main__':
    main()
