from flask import Flask, render_template, jsonify, request
from kafka import KafkaConsumer, KafkaAdminClient, BrokerConnection
import json
import threading
from collections import deque
import time

app = Flask(__name__)

# Store recent threats (in-memory, consider Redis for production)
recent_threats = deque(maxlen=100)
threat_stats = {
    'total_threats': 0,
    'threats_by_type': {},
    'blocked_ips': set()
}

def list_available_topics(bootstrap_servers):
    """List all available Kafka topics with detailed error info"""
    try:
        print(f"Attempting to list topics from {bootstrap_servers}...")
        admin = KafkaAdminClient(
            bootstrap_servers=bootstrap_servers,
            api_version_auto_timeout_ms=3000,
            security_protocol='PLAINTEXT'
        )
        topics = admin.list_topics()
        admin.close()
        print(f"Successfully listed topics: {topics}")
        return topics
    except Exception as e:
        error_msg = f"Error listing topics: {str(e)}"
        print(error_msg)
        # Try to get more detailed error info
        try:
            conn = BrokerConnection(bootstrap_servers, 9092, None)
            connected = conn.connected()
            conn.close()
            print(f"Broker connection test: {'Connected' if connected else 'Failed'}")
        except Exception as conn_e:
            print(f"Broker connection test failed: {str(conn_e)}")
        return error_msg

def consume_kafka_messages():
    print("🔌 Attempting to connect to Kafka at kafka:9092...")
    print("Available topics:", list_available_topics('kafka:9092'))
    
    consumer = None
    while True:  # Keep trying to connect
        try:
            consumer = KafkaConsumer(
                'threat-alerts',
                bootstrap_servers='kafka:9092',
                auto_offset_reset='earliest',
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                group_id='dashboard-consumer-group',
                consumer_timeout_ms=5000,
                api_version_auto_timeout_ms=30000,
                security_protocol='PLAINTEXT'
            )
            print("✅ Successfully connected to Kafka")
            break
        except Exception as e:
            print(f"❌ Failed to connect to Kafka: {str(e)}")
            print("Retrying in 5 seconds...")
            time.sleep(5)
            continue

    print("👂 Listening for messages on 'threat-alerts' topic...")
    while True:  # Outer loop for reconnection
        try:
            for message in consumer:
                try:
                    print(f"📩 Received message: {message.value}")
                    threat = message.value
                    
                    if not isinstance(threat, dict):
                        print(f"⚠️ Unexpected message format: {type(threat)}")
                        continue
                        
                    threat['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
                    recent_threats.appendleft(threat)
                    
                    # Update stats
                    threat_stats['total_threats'] += 1
                    threat_type = threat.get('threat_name', 'unknown')
                    threat_stats['threats_by_type'][threat_type] = threat_stats['threats_by_type'].get(threat_type, 0) + 1
                    print(f"📊 Updated stats - Total: {threat_stats['total_threats']}, Type: {threat_type}")
                    
                    # If this was a block action, track the IP
                    #if 'block-ip' in str(threat.get('action', '')).lower():
                    ip = threat.get('source_ip')
                    if ip and ip != 'unknown':
                        threat_stats['blocked_ips'].add(ip)
                        print(f"🔒 Blocked IP: {ip}")
                            
                except Exception as e:
                    print(f"⚠️ Error processing message: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"⚠️ Error in consumer loop: {str(e)}")
            print("Attempting to reconnect in 5 seconds...")
            time.sleep(5)
            return consume_kafka_messages()  # Reconnect

# Use a lock to ensure the thread is started only once
kafka_thread_started = threading.Lock()

@app.before_first_request
def start_kafka_consumer():
    """Start the Kafka consumer in a background thread before the first request."""
    # The lock ensures this block is executed only by the first worker process
    if kafka_thread_started.locked():
        return
    with kafka_thread_started:
        print("🚀 Starting Kafka consumer thread...")
        kafka_thread = threading.Thread(target=consume_kafka_messages, daemon=True)
        kafka_thread.start()
        print("✅ Kafka consumer thread started.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    try:
        # Try to list topics as a health check
        admin = KafkaAdminClient(
            bootstrap_servers='kafka:9092',
            api_version_auto_timeout_ms=3000,
            security_protocol='PLAINTEXT'
        )
        topics = admin.list_topics()
        admin.close()
        return jsonify({
            'status': 'healthy',
            'kafka_connected': True,
            'topics': topics
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'kafka_connected': False,
            'error': str(e)
        }), 500

@app.route('/api/threats')
def get_threats():
    return jsonify({
        'recent': list(recent_threats),
        'stats': {
            'total': threat_stats['total_threats'],
            'by_type': threat_stats['threats_by_type'],
            'blocked_ips_count': len(threat_stats['blocked_ips']),
            'blocked_ips': list(threat_stats['blocked_ips'])
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)