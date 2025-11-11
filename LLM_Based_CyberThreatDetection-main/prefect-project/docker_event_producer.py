# 1. Install the required Python libraries
# pip install docker kafka-python

import docker
import kafka
import json

# Connect to Kafka (running on localhost from Step 1)
producer = kafka.KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Connect to the Docker daemon
client = docker.from_env()

print("🚀 Docker Event Producer is running...")
print("Streaming 'exec_create' and 'start' events to Kafka topic: docker-events")

# Filter for the events you want
event_filters = {
    'type': 'container',
    'event': ['exec_create', 'start']
}

# Stream events
for event in client.events(filters=event_filters, decode=True):
    try:
        # Create a clean JSON log
        log_entry = {
            "timestamp": event.get("timeNano"),
            "action": event.get("Action"),
            "container_name": event["Actor"]["Attributes"].get("name"),
            "image": event["Actor"]["Attributes"].get("image"),
            "attributes": event["Actor"]["Attributes"]
        }
        
        print(f"SENDING LOG: {log_entry['action']}")
        
        # Send the log to your Kafka topic
        producer.send('docker-events', log_entry)

    except Exception as e:
        print(f"Error processing event: {e}")
