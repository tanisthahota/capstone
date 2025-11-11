#!/usr/bin/env python
"""
Debug script to see what logs are actually coming from Kafka
and how they're being parsed.
"""

import re
import json
from kafka import KafkaConsumer

def extract_content_from_log(log_line: str) -> str:
    """
    Parses a single log line and extracts the 'content' field.
    """
    content_match = re.search(r'content="((?:\\.|[^"\\])*)"', log_line)
    
    if content_match:
        content = content_match.group(1)
        # Unescape any escaped quotes (e.g., \\" becomes ")
        return content.replace('\\"', '"')
    
    return None

if __name__ == "__main__":
    print("🔍 Connecting to Kafka to debug incoming logs...")
    
    try:
        consumer = KafkaConsumer(
            'app-logs',
            bootstrap_servers='localhost:9092',
            auto_offset_reset='latest'
        )
    except Exception as e:
        print(f"❌ Could not connect to Kafka: {e}")
        exit(1)

    print("✅ Connected. Waiting for logs...\n")
    
    count = 0
    for message in consumer:
        log_line = message.value.decode('utf-8')
        extracted_content = extract_content_from_log(log_line)
        
        count += 1
        print(f"\n--- Log #{count} ---")
        print(f"Raw log line:\n{log_line}\n")
        print(f"Extracted content:\n{extracted_content}\n")
        
        if extracted_content:
            # Try to parse as JSON if it looks like JSON
            if extracted_content.startswith('{') or extracted_content.startswith('['):
                try:
                    parsed = json.loads(extracted_content)
                    print(f"Parsed JSON: {json.dumps(parsed, indent=2)}\n")
                except:
                    print("Could not parse as JSON\n")
        
        if count >= 10:
            break
    
    print("Debug session ended.")
