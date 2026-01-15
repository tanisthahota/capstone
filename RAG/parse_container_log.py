#!/usr/bin/env python3
import json
import re
import sys

def flatten_docker_event(log):
    """Convert a Docker JSON event log into flattened text format."""

    # Parse JSON if passed as a string
    if isinstance(log, str):
        log = json.loads(log)

    event_type = log.get("Action", "")
    image = log.get("from", "")
    container_id = log.get("id", "")
    actor = log.get("Actor", {})
    attributes = actor.get("Attributes", {})
    container_name = attributes.get("name", "")
    scope = log.get("scope", "")
    time = log.get("time", "")
    time_nano = log.get("timeNano", "")

    # Flatten attributes similar to your example
    attr_str = re.sub(r'\s+', ' ', str({
        "ID": actor.get("ID", ""),
        "Attributes": attributes
    }))

    return (
        f"{event_type}: {image} {container_id} {container_name} container "
        f"{event_type}: {image} {attr_str} {scope} {time} {time_nano}"
    )


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python file.py '<json-log>'")
        sys.exit(1)

    json_input = sys.argv[1]

    try:
        output = flatten_docker_event(json_input)
        print("\n")
        print(output)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
