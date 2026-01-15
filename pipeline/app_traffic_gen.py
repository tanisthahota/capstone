#!/usr/bin/env python3
"""
Application Layer Traffic Generator
Makes API calls to generate application logs continuously
Streams logs to Kafka topic 'application-logs'
"""

import requests
import time
import json
import os
from datetime import datetime
from kafka import KafkaProducer

API_BASE = "http://api-gateway:80/api"

# Auto-detect Kafka broker
def get_kafka_broker():
    """Detect Kafka broker based on environment"""
    try:
        import socket
        socket.gethostbyname('kafka')
        return 'kafka:9092'  # Docker environment
    except:
        return 'localhost:9092'  # Local environment

# Initialize Kafka Producer
kafka_broker = get_kafka_broker()
producer = None
kafka_connected = False

def init_kafka():
    """Initialize Kafka producer"""
    global producer, kafka_connected
    try:
        producer = KafkaProducer(
            bootstrap_servers=[kafka_broker],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            retries=3
        )
        kafka_connected = True
        print(f"[Kafka] ✅ Connected to {kafka_broker}")
        return True
    except Exception as e:
        print(f"[Kafka] ❌ Failed to connect: {e}")
        kafka_connected = False
        return False

def send_log_to_kafka(method, endpoint, data=None, event_type="Normal", response=None):
    """Create and send log entry to Kafka application-logs topic"""
    if not kafka_connected:
        return
    
    try:
        timestamp = datetime.utcnow().isoformat()
        url = f"{API_BASE}{endpoint}"
        content = json.dumps(data) if data else ''
        
        # Create log object matching the service format
        log_object = {
            'timestamp': timestamp,
            'Method': method,
            'URL': endpoint,
            'User-Agent': 'AppTrafficGenerator/1.0',
            'Pragma': '-',
            'Cache-Control': '-',
            'Accept': 'application/json',
            'Accept-encoding': 'gzip, deflate',
            'Accept-charset': 'utf-8',
            'language': 'en-US',
            'host': 'api-gateway:80',
            'cookie': '-',
            'content-type': 'application/json' if method == 'POST' else '-',
            'connection': 'keep-alive',
            'lenght': str(len(content)),
            'content': content,
            'event': event_type,
            'status_code': response.status_code if response else None,
            'source': 'app_traffic_gen'
        }
        
        # Send to Kafka
        producer.send('application-logs', value=log_object)
        producer.flush()  # Ensure message is sent
        
    except Exception as e:
        print(f"[Kafka] Error sending log: {e}")

def make_request(method, endpoint, data=None, event_type="Normal"):
    """Make an API request, log it, and send to Kafka"""
    url = f"{API_BASE}{endpoint}"
    response = None
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=5)
        else:
            return None
        
        # Send log to Kafka
        send_log_to_kafka(method, endpoint, data, event_type, response)
        
        return response
    except Exception as e:
        print(f"[App Traffic] Request failed: {e}")
        # Still send log even if request failed
        send_log_to_kafka(method, endpoint, data, f"{event_type}_Failed", None)
        return None

def main():
    print("[App Traffic] 🚀 Starting application traffic generator...")
    print("[App Traffic] Press Ctrl+C to stop\n")
    
    # Initialize Kafka
    if not init_kafka():
        print("[App Traffic] ⚠️  Warning: Kafka not connected. Logs won't be streamed.")
        print("[App Traffic] Continuing anyway...\n")
    
    request_id = 0
    
    try:
        while True:
            print(f"[App Traffic] {request_id}: Health check - auth-service")
            make_request("GET", "/auth/health", event_type="HealthCheck")
            
            print(f"[App Traffic] {request_id}: Health check - payment-service")
            make_request("GET", "/payment/health", event_type="HealthCheck")
            
            print(f"[App Traffic] {request_id}: Health check - notification-service")
            make_request("GET", "/notification/health", event_type="HealthCheck")
            
            user_data = {
                "email": f"user{request_id}@example.com",
                "password": "password123"
            }
            print(f"[App Traffic] {request_id}: Register user")
            make_request("POST", "/auth/register", user_data, event_type="RegistrationAttempt")
            
            login_data = {
                "email": f"user{request_id}@example.com",
                "password": "password123"
            }
            print(f"[App Traffic] {request_id}: Login")
            make_request("POST", "/auth/login", login_data, event_type="LoginAttempt")
            
            payment_data = {
                "userId": request_id,
                "amount": 100.00,
                "currency": "USD"
            }
            print(f"[App Traffic] {request_id}: Process payment")
            make_request("POST", "/payment/process", payment_data, event_type="PaymentProcessingAttempt")
            
            request_id += 1
            time.sleep(0.2)
    
    except KeyboardInterrupt:
        print("\n[App Traffic] 🛑 Shutting down...")
        print(f"[App Traffic] ✅ Generated {request_id} request cycles")
        if kafka_connected and producer:
            producer.close()
            print("[App Traffic] ✅ Kafka producer closed")

if __name__ == '__main__':
    main()
