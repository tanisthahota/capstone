
class Agent:
    def __init__(self, name, instructions, handoffs=None, handoff_description=None):
        self.name = name
        self.instructions = instructions
        self.handoff_description = handoff_description
        self.handoffs = handoffs or []

    def run(self, log_entry):
        print(f"[{self.name}] Processing:\n{log_entry}")
        # Basic DoS detection logic based on log_entry features
        # This assumes log_entry is a CSV string matching dos.csv columns
        fields = log_entry.split(',')
        # Example indices (adjust as needed for your schema):
        # [src_ip, dst_ip, src_port, dst_port, pkt_size, timestamp, ...]
        try:
            pkt_size = float(fields[4])
            req_rate = float(fields[7])
            concurrency = float(fields[12])
        except (IndexError, ValueError):
            return {"attack_detected": False, "attack_type": None, "reason": "Malformed log entry."}

        # Simple rules for demo purposes
        if req_rate > 1000000:
            # HULK: extremely high request rate
            return {"attack_detected": True, "attack_type": "hulk", "reason": "High request rate detected."}
        elif concurrency > 100:
            # GoldenEye: high concurrency
            return {"attack_detected": True, "attack_type": "goldeneye", "reason": "High concurrency detected."}
        elif pkt_size < 50 and req_rate < 10:
            # Slowloris: small packets, low rate
            return {"attack_detected": True, "attack_type": "slowloris", "reason": "Small packets and low request rate detected."}
        else:
            return {"attack_detected": False, "attack_type": None, "reason": "No DoS pattern detected."}


class Runner:
    def __init__(self, agent):
        self.agent = agent

    def execute(self, log_entry):
        return self.agent.run(log_entry)
