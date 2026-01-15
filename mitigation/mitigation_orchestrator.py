#!/usr/bin/env python3
"""
Mitigation Orchestrator
Reads threat alerts from Kafka and triggers mitigation pipeline
Handles Tier 1 (auto) and Tier 2 (manual approval) workflows
"""

import json
import sys
import subprocess
import chromadb
import re
from kafka import KafkaConsumer
from typing import Tuple, List

CHROMA_PATH = "/app/chroma_db"
CHROMA_COLLECTION = "mitigation_plans"
HIGH_CONF_THRESHOLD = 0.75

class Color:
    Y = "\033[93m"
    G = "\033[92m"
    R = "\033[91m"
    B = "\033[94m"
    E = "\033[0m"

def lookup_threat_tier(threat_name: str) -> Tuple[int, str]:
    """
    Query ChromaDB to get tier and full KB entry
    Returns: (tier, kb_entry_text)
    """
    try:
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        collection = client.get_collection(CHROMA_COLLECTION)
        result = collection.query(query_texts=[threat_name], n_results=1)
        
        if not result["documents"]:
            print(f"❌ No KB entry found for threat: {threat_name}")
            return None, None
        
        doc = result["documents"][0]
        entry_text = doc[0] if isinstance(doc, list) and len(doc) > 0 else doc
        
        # Extract tier
        tier_match = re.search(r"Tier:\s*(\d+)", entry_text, re.IGNORECASE)
        tier = int(tier_match.group(1)) if tier_match else 2
        
        return tier, entry_text
    except Exception as e:
        print(f"❌ ChromaDB lookup failed: {e}")
        return None, None

def trigger_mitigation(threat_name: str, source_ip: str, target_container: str, confidence: float, tier: int):
    """
    Trigger mitigation.py with threat details
    """
    # Handle N/A values
    ip_arg = source_ip if source_ip != 'N/A' else 'N/A'
    target_arg = target_container if target_container != 'N/A' else 'N/A'
    
    cmd = [
        "python", "/app/mitigation.py",
        "--threat", threat_name,
        "--ip", ip_arg,
        "--target", target_arg,
        "--confidence", str(confidence)
    ]
    
    print(f"\n▶ Triggering mitigation: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    
    return result.returncode == 0

def main():
    print("\n🛡️  MITIGATION ORCHESTRATOR: Starting...")
    print("Listening for threat alerts from Kafka\n")
    
    # Connect to Kafka Consumer
    try:
        consumer = KafkaConsumer(
            'threat-alerts',
            bootstrap_servers='kafka:9092',
            auto_offset_reset='earliest',
            value_deserializer=lambda v: json.loads(v.decode('utf-8')),
            group_id='mitigation-orchestrator'
        )
        print("  ✅ Connected to threat-alerts topic\n")
    except Exception as e:
        print(f"  ❌ Failed to connect: {e}")
        return
    
    print("🛡️  ORCHESTRATOR: Listening for threats...\n")
    
    threat_count = 0
    
    for message in consumer:
        try:
            threat_alert = message.value
            
            threat_name = threat_alert.get('threat_name', 'unknown')
            source_ip = threat_alert.get('source_ip', 'N/A')
            target_container = threat_alert.get('target_container', 'N/A')
            layer = threat_alert.get('layer', 'unknown')
            confidence = threat_alert.get('confidence', 0)
            
            threat_count += 1
            print(f"\n🚨 [THREAT #{threat_count}] {layer.upper()} LAYER")
            print(f"   Threat: {threat_name}")
            print(f"   Source IP: {source_ip}")
            print(f"   Target: {target_container}")
            print(f"   Confidence: {confidence:.2%}")
            
            # Lookup threat tier
            tier, kb_entry = lookup_threat_tier(threat_name)
            
            if tier is None:
                print("   ⚠️  No mitigation found in KB. Skipping.")
                continue
            
            print(f"   📌 Tier: {tier}")
            
            # Tier 1: Auto mitigation
            if tier == 1:
                print("   ✅ Tier 1: Auto mitigation (sandbox → production)")
                trigger_mitigation(threat_name, source_ip, target_container, confidence, tier)
            
            # Tier 2: Manual approval required
            else:
                print("   ⚠️  Tier 2: Manual approval required")
                approval = input("   Approve mitigation? (yes/no): ")
                
                if approval.lower() == "yes":
                    trigger_mitigation(threat_name, source_ip, target_container, confidence, tier)
                else:
                    print("   ❌ Mitigation cancelled by user")
        
        except Exception as e:
            print(f"Error processing threat: {e}")
            continue

if __name__ == '__main__':
    main()