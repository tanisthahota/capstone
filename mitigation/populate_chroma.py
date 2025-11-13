#!/usr/bin/env python3
"""
Populate ChromaDB with threat mitigation entries
"""

import chromadb

CHROMA_PATH = "/app/chroma_db"
CHROMA_COLLECTION = "mitigation_plans"

# Threat mitigation knowledge base
THREAT_KB = [
    {
        "threat": "reverse_shell",
        "entry": """Threat: reverse_shell
Description: Reverse shell execution in container
Tier: 1
Playbook: stop-container.yml
Required_Vars: threat_name, source_ip, target_container
Actions: Stop the compromised container immediately"""
    },
    {
        "threat": "priv_esc",
        "entry": """Threat: priv_esc
Description: Privilege escalation attempt
Tier: 1
Playbook: stop-container.yml
Required_Vars: threat_name, target_container
Actions: Stop the container with privilege escalation"""
    },
    {
        "threat": "portscan",
        "entry": """Threat: portscan
Description: Network port scanning activity
Tier: 2
Playbook: block-ip-nginx.yml
Required_Vars: threat_name,source_ip
Actions: Block source IP at API Gateway"""
    },
    {
        "threat": "XSS",
        "entry": """Threat: XSS
Description: Cross-site scripting attack
Tier: 1
Playbook: block-ip-nginx.yml
Required_Vars: threat_name, source_ip, target_container
Actions: Block malicious source IP at gateway"""
    },
    {
        "threat": "SQLi",
        "entry": """Threat: SQLi
Description: SQL injection attack
Tier: 1
Playbook: block-ip-nginx.yml
Required_Vars: threat_name, source_ip, target_container
Actions: Block SQL injection source IP"""
    },
    {
        "threat": "DDoS",
        "entry": """Threat: DDoS
Description: Distributed denial of service
Tier: 2
Playbook: block-ip-nginx.yml
Required_Vars: threat_name, source_ip
Actions: Rate limit and block source IP"""
    }
]

def populate_chroma():
    print("\n📚 Populating ChromaDB with threat mitigation entries...\n")
    
    try:
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        
        # Delete collection if exists
        try:
            client.delete_collection(CHROMA_COLLECTION)
            print(f"  ♻️  Deleted existing collection: {CHROMA_COLLECTION}")
        except:
            pass
        
        # Create new collection
        collection = client.create_collection(CHROMA_COLLECTION)
        print(f"  ✅ Created collection: {CHROMA_COLLECTION}")
        
        # Add threat entries
        for i, threat_data in enumerate(THREAT_KB):
            threat_name = threat_data["threat"]
            kb_entry = threat_data["entry"]
            
            collection.add(
                ids=[f"threat_{i}"],
                documents=[kb_entry],
                metadatas=[{"threat": threat_name}]
            )
            print(f"  ✅ Added: {threat_name}")
        
        print(f"\n✅ ChromaDB populated with {len(THREAT_KB)} threat entries!\n")
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
    
    return True

if __name__ == '__main__':
    populate_chroma()