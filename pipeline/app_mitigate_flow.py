import json
import time
import subprocess
from kafka import KafkaConsumer
from prefect import flow, task
from typing import Dict, Any

# Configuration
KAFKA_BOOTSTRAP_SERVERS = 'kafka:9092'
KAFKA_TOPIC = 'threat-alerts'
MITIGATION_CONTAINER = "python-scripts"
MITIGATION_SCRIPT_PATH = "/workspace/mitigation/mitigation.py"
CONSUMER_TIMEOUT_MS = 5000  # 5 seconds timeout for consumer

@task(name="process_alert", retries=3, retry_delay_seconds=5)
def process_alert(alert_data: Dict[str, Any]) -> None:
    """Process a single alert by triggering the mitigation script"""
    try:
        print(f"🚨 Processing threat alert: {alert_data}")
        
        # Construct the docker exec command
        cmd = [
            "docker", "exec", "-i", MITIGATION_CONTAINER,
            "python3", MITIGATION_SCRIPT_PATH,
            "--threat", str(alert_data.get('threat_name', 'unknown')),
            "--ip", str(alert_data.get('source_ip', '0.0.0.0')),
            "--target", str(alert_data.get('target_container', 'unknown')),
            "--confidence", str(alert_data.get('confidence', 0.0))
        ]
        
        print(f"▶ Executing: {' '.join(cmd)}")
        
        # Run the mitigation script
        print("🚀 Starting mitigation process...")
        result = subprocess.run(
            cmd,
            input="yes\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Print the output in real-time
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"ERROR: {result.stderr}")
        
        # Log the output
        if result.stdout:
            print(f"✅ Mitigation output:\n{result.stdout}")
        if result.stderr:
            print(f"❌ Mitigation errors:\n{result.stderr}")
            
    except Exception as e:
        print(f"❌ Error in mitigation: {str(e)}")
        raise  # Re-raise for Prefect retry

@flow(name="threat-mitigation-flow", log_prints=True)
def threat_mitigation_flow():
    """Main Prefect flow that consumes messages from Kafka and processes alerts"""
    print("🚀 Starting threat mitigation service...")
    
    while True:  # Keep the flow running
        try:
            print(f"🔌 Connecting to Kafka at {KAFKA_BOOTSTRAP_SERVERS}...")
            
            consumer = KafkaConsumer(
                KAFKA_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                auto_offset_reset='latest',
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                consumer_timeout_ms=CONSUMER_TIMEOUT_MS,
                group_id='mitigation-service-group'
            )
            
            print(f"🎧 Listening for threats on topic: {KAFKA_TOPIC}")
            
            try:
                for message in consumer:
                    try:
                        alert_data = message.value
                        print(f"\n📨 Received alert: {alert_data}")
                        process_alert(alert_data)
                    except json.JSONDecodeError as e:
                        print(f"⚠️ Failed to decode message: {e}")
                    except Exception as e:
                        print(f"⚠️ Error processing message: {str(e)}")
                        
            except Exception as e:
                print(f"⚠️ Kafka consumer error: {str(e)}")
                time.sleep(5)  # Wait before reconnecting
                
            finally:
                if 'consumer' in locals():
                    consumer.close()
                    
        except KeyboardInterrupt:
            print("\n👋 Shutting down gracefully...")
            break
        except Exception as e:
            print(f"❌ Fatal error in main loop: {str(e)}")
            time.sleep(5)  # Prevent tight loop on errors

if __name__ == "__main__":
    threat_mitigation_flow()