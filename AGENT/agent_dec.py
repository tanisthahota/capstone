
class Agent:
    def __init__(self, name, instructions, handoffs=None, handoff_description=None):
        self.name = name
        self.instructions = instructions
        self.handoff_description = handoff_description
        self.handoffs = handoffs or []

    def run(self, log_entry):
        print(f"[{self.name}] Processing:\n{log_entry}")
        try:
            fields = [float(x) if x.replace('.', '', 1).isdigit() else x for x in log_entry.strip().split(",")]
            total_bytes = float(fields[16]) if len(fields) > 16 and str(fields[16]).replace('.', '', 1).isdigit() else 0
            request_rate = float(fields[7]) if len(fields) > 7 and str(fields[7]).replace('.', '', 1).isdigit() else 0
            # DoS detection
            if total_bytes > 500 or request_rate > 100:
                # Handoff logic for DoS type
                for agent in self.handoffs:
                    # Slowloris: long-lived connections, low request rate
                    if agent.name == "slowloris_detector" and request_rate < 10 and total_bytes > 500:
                        return {
                            "attack_detected": True,
                            "attack_type": "slowloris",
                            "reason": "Long-lived connection with low request rate and high bytes."
                        }
                    # Hulk: high request rate
                    if agent.name == "hulk_detector" and request_rate > 100:
                        return {
                            "attack_detected": True,
                            "attack_type": "hulk",
                            "reason": "Extremely high request rate detected."
                        }
                    # GoldenEye: high concurrency and large payloads
                    if agent.name == "goldeneye_detector" and total_bytes > 1000:
                        return {
                            "attack_detected": True,
                            "attack_type": "goldeneye",
                            "reason": "Large payloads and possible concurrency detected."
                        }
                # Default DoS
                return {
                    "attack_detected": True,
                    "attack_type": "dos",
                    "reason": f"High total bytes ({total_bytes}) or request rate ({request_rate}) detected."
                }
            else:
                return {
                    "attack_detected": False,
                    "attack_type": None,
                    "reason": "No DoS patterns detected."
                }
        except Exception as e:
            return {
                "attack_detected": False,
                "attack_type": None,
                "reason": f"Error parsing log entry: {e}"
            }


class Runner:
    def __init__(self, agent):
        self.agent = agent

    def execute(self, log_entry):
        return self.agent.run(log_entry)
