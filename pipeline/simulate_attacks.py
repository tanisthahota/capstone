#!/usr/bin/env python3
"""
Attack Simulation Script
Simulates XSS and SQLi attacks to test the application detector
"""

import requests
import json
import time
from datetime import datetime
from kafka import KafkaProducer

API_BASE = "http://api-gateway:80/api"

# Auto-detect Kafka broker
def get_kafka_broker():
    """Detect Kafka broker based on environment"""
    try:
        import socket
        socket.gethostbyname('kafka')
        return 'kafka:9092'
    except:
        return 'localhost:9092'

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
        return False

def send_log_to_kafka(method, endpoint, data=None, event_type="Attack", response=None):
    """Send attack log to Kafka"""
    if not kafka_connected:
        return
    
    try:
        timestamp = datetime.utcnow().isoformat()
        content = json.dumps(data) if data else ''
        
        log_object = {
            'timestamp': timestamp,
            'Method': method,
            'URL': endpoint,
            'User-Agent': 'AttackSimulator/1.0',
            'Pragma': '-',
            'Cache-Control': '-',
            'Accept': 'application/json',
            'Accept-encoding': 'gzip, deflate',
            'Accept-charset': 'utf-8',
            'language': 'en-US',
            'host': 'api-gateway:80',
            'cookie': '-',
            'content-type': 'application/json',
            'connection': 'keep-alive',
            'lenght': str(len(content)),
            'content': content,
            'event': event_type,
            'status_code': response.status_code if response else None,
            'source': 'attack_simulator'
        }
        
        producer.send('application-logs', value=log_object)
        producer.flush()
        
    except Exception as e:
        print(f"[Kafka] Error sending log: {e}")

# SQL Injection Payloads
SQLI_PAYLOADS = [
    # Classic SQLi
    {"email": "admin' OR '1'='1", "password": "anything"},
    {"email": "admin'--", "password": ""},
    {"email": "' OR 1=1--", "password": "test"},
    {"email": "admin' UNION SELECT NULL--", "password": "test"},
    {"email": "test@test.com' OR 'x'='x", "password": "password"},
    # Boolean-based SQLi
    {"email": "admin' AND 1=1--", "password": "test"},
    {"email": "admin' AND 1=2--", "password": "test"},
    # Time-based SQLi
    {"email": "admin'; WAITFOR DELAY '00:00:05'--", "password": "test"},
    # Union-based SQLi
    {"email": "' UNION SELECT username, password FROM users--", "password": "test"},
    # Custom payload        
    {"email": "select * from users where id = 1 +$+ or 1 = 1 -- 1", "password": "test"},
    {"email": "1\" ) union all select null,null,null,null,null--", "password": "test"}
]

# XSS Payloads
XSS_PAYLOADS = [
    # Basic XSS
    {"email": "<script>alert('XSS')</script>", "password": "test"},
    {"email": "test@test.com", "password": "<img src=x onerror=alert('XSS')>"},
    # Event handler XSS
    {"email": "<body onload=alert('XSS')>", "password": "test"},
    {"email": "<svg onload=alert('XSS')>", "password": "test"},
    # JavaScript protocol
    {"email": "javascript:alert('XSS')", "password": "test"},
    # Encoded XSS
    {"email": "%3Cscript%3Ealert('XSS')%3C/script%3E", "password": "test"},
    # DOM-based XSS
    {"email": "<iframe src=javascript:alert('XSS')>", "password": "test"},
    # Stored XSS attempt
    {"email": "<script>document.cookie</script>", "password": "test"},
]

def simulate_sqli_attack():
    """Simulate SQL Injection attacks"""
    print("\n" + "="*60)
    print("🔥 SIMULATING SQL INJECTION ATTACKS")
    print("="*60 + "\n")
    
    for i, payload in enumerate(SQLI_PAYLOADS, 1):
        print(f"[SQLi #{i}] Attempting: {payload['email'][:50]}...")
        
        try:
            # Try login with SQLi payload
            response = requests.post(
                f"{API_BASE}/auth/login",
                json=payload,
                timeout=5
            )
            
            # Send log to Kafka
            send_log_to_kafka("POST", "/auth/login", payload, "SQLi_Attack", response)
            
            print(f"   Status: {response.status_code}")
            print(f"   ✅ Log sent to Kafka\n")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            send_log_to_kafka("POST", "/auth/login", payload, "SQLi_Attack_Failed", None)
        
        time.sleep(1)

def simulate_xss_attack():
    """Simulate Cross-Site Scripting attacks"""
    print("\n" + "="*60)
    print("🔥 SIMULATING XSS ATTACKS")
    print("="*60 + "\n")
    
    for i, payload in enumerate(XSS_PAYLOADS, 1):
        print(f"[XSS #{i}] Attempting: {payload['email'][:50]}...")
        
        try:
            # Try registration with XSS payload
            response = requests.post(
                f"{API_BASE}/auth/register",
                json=payload,
                timeout=5
            )
            
            # Send log to Kafka
            send_log_to_kafka("POST", "/auth/register", payload, "XSS_Attack", response)
            
            print(f"   Status: {response.status_code}")
            print(f"   ✅ Log sent to Kafka\n")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            send_log_to_kafka("POST", "/auth/register", payload, "XSS_Attack_Failed", None)
        
        time.sleep(1)

def simulate_mixed_attacks():
    """Simulate a mix of attacks"""
    print("\n" + "="*60)
    print("🔥 SIMULATING MIXED ATTACKS")
    print("="*60 + "\n")
    
    # Mix SQLi and XSS
    mixed_payloads = [
        {"email": "<script>alert('XSS')</script>' OR '1'='1", "password": "test"},
        {"email": "admin' UNION SELECT '<script>alert(1)</script>'--", "password": "test"},
        {"email": "<img src=x onerror='alert(1)'>' OR 1=1--", "password": "test"},
    ]
    
    for i, payload in enumerate(mixed_payloads, 1):
        print(f"[Mixed #{i}] Attempting: {payload['email'][:50]}...")
        
        try:
            response = requests.post(
                f"{API_BASE}/auth/login",
                json=payload,
                timeout=5
            )
            
            send_log_to_kafka("POST", "/auth/login", payload, "Mixed_Attack", response)
            print(f"   Status: {response.status_code}")
            print(f"   ✅ Log sent to Kafka\n")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            send_log_to_kafka("POST", "/auth/login", payload, "Mixed_Attack_Failed", None)
        
        time.sleep(1)

def send_threat_alert(threat_type, description):
    """Send a simulated threat alert to Kafka."""
    if not kafka_connected:
        return

    try:
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'threat_type': threat_type,
            'description': description,
            'source_ip': '127.0.0.1',
            'status': 'detected'
        }
        producer.send('threat-alerts', value=alert)
        producer.flush()
        print(f"[Kafka] ✅ Sent threat alert: {threat_type}")

    except Exception as e:
        print(f"[Kafka] Error sending threat alert: {e}")

def simulate_threat_alerts():
    """Simulate sending threat alerts to Kafka."""
    print("\n" + "="*60)
    print("🔥 SIMULATING THREAT ALERTS")
    print("="*60 + "\n")

    while True:
        send_threat_alert("SQLi", "Simulated SQL injection attempt")
        time.sleep(5)
        send_threat_alert("XSS", "Simulated cross-site scripting attempt")
        time.sleep(5)

def main():
    print("\n🚨 ATTACK SIMULATION SCRIPT")
    print("This will simulate XSS and SQLi attacks to test detection\n")
    
    # Initialize Kafka
    if not init_kafka():
        print("⚠️  Warning: Kafka not connected. Logs won't be streamed.")
        print("Continuing anyway...\n")
    
    import sys
    
    if len(sys.argv) > 1:
        attack_type = sys.argv[1].lower()
        
        if attack_type == "sqli":
            simulate_sqli_attack()
        elif attack_type == "xss":
            simulate_xss_attack()
        elif attack_type == "mixed":
            simulate_mixed_attacks()
        elif attack_type == "threats":
            simulate_threat_alerts()
        else:
            print(f"Unknown attack type: {attack_type}")
            print("Usage: python simulate_attacks.py [sqli|xss|mixed|all]")
    else:
        # Run all attacks
        simulate_sqli_attack()
        time.sleep(2)
        simulate_xss_attack()
        time.sleep(2)
        simulate_mixed_attacks()
    
    if kafka_connected and producer:
        producer.close()
        print("\n✅ Attack simulation complete!")
        print("📊 Check application_detector.py output for threat detection")

def send_threat_alert(threat_type, description):
    """Send a simulated threat alert to Kafka."""
    if not kafka_connected:
        return

    try:
        alert = {
            'timestamp': datetime.utcnow().isoformat(),
            'threat_type': threat_type,
            'description': description,
            'source_ip': '127.0.0.1',
            'status': 'detected'
        }
        producer.send('threat-alerts', value=alert)
        producer.flush()
        print(f"[Kafka] ✅ Sent threat alert: {threat_type}")

    except Exception as e:
        print(f"[Kafka] Error sending threat alert: {e}")

def simulate_threat_alerts():
    """Simulate sending threat alerts to Kafka."""
    print("\n" + "="*60)
    print("🔥 SIMULATING THREAT ALERTS")
    print("="*60 + "\n")

    while True:
        send_threat_alert("SQLi", "Simulated SQL injection attempt")
        time.sleep(5)
        send_threat_alert("XSS", "Simulated cross-site scripting attempt")
        time.sleep(5)

if __name__ == '__main__':
    main()

