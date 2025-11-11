#!/usr/bin/env python
"""
Kafka Producer: Reads logs from sqli.log and sends them to Kafka.
This allows you to replay attack logs in real-time for testing NEWFLOW.py
"""

import time
import json
from kafka import KafkaProducer

def send_logs_from_file_to_kafka(log_file_path: str, delay_between_logs: float = 1.0):
    """
    Reads logs from a file and sends them to Kafka's 'app-logs' topic.
    
    Args:
        log_file_path: Path to the log file (e.g., sqli.log)
        delay_between_logs: Delay in seconds between sending each log
    """
    
    print(f"📂 Reading logs from: {log_file_path}")
    print(f"⏱️  Delay between logs: {delay_between_logs}s\n")
    
    # Initialize Kafka producer
    try:
        producer = KafkaProducer(
            bootstrap_servers='localhost:9092',
            value_serializer=lambda v: v.encode('utf-8')
        )
        print("✅ Connected to Kafka at localhost:9092\n")
    except Exception as e:
        print(f"❌ Failed to connect to Kafka: {e}")
        return

    # Read and send logs
    try:
        with open(log_file_path, 'r') as f:
            logs = f.readlines()
        
        print(f"📊 Found {len(logs)} logs in file\n")
        print("=" * 80)
        print("Starting to send logs to Kafka...")
        print("=" * 80 + "\n")
        
        for i, log_line in enumerate(logs, 1):
            log_line = log_line.strip()
            if not log_line:
                continue
            
            # Send to Kafka
            try:
                producer.send('app-logs', value=log_line)
                print(f"[{i}] ✅ Sent log to Kafka")
                print(f"    Content preview: {log_line[:100]}...")
                
                if i < len(logs):
                    print(f"    ⏳ Waiting {delay_between_logs}s before next log...\n")
                    time.sleep(delay_between_logs)
                else:
                    print("\n✅ All logs sent successfully!\n")
                    
            except Exception as e:
                print(f"[{i}] ❌ Failed to send log: {e}\n")
        
        producer.flush()
        producer.close()
        print("Kafka producer closed.")
        
    except FileNotFoundError:
        print(f"❌ Log file not found: {log_file_path}")
    except Exception as e:
        print(f"❌ Error reading file: {e}")

if __name__ == "__main__":
    # Path to your SQLi/XSS logs
    log_file = "/home/uday/Desktop/PayPal/prefect-project/sqli.log"
    
    # Send logs with 1 second delay between each
    send_logs_from_file_to_kafka(log_file, delay_between_logs=1.0)
