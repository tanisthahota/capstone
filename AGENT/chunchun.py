
class Agent:
    def __init__(self, name, instructions, handoffs=None, handoff_description=None):
        self.name = name
        self.instructions = instructions
        self.handoff_description = handoff_description
        self.handoffs = handoffs or []

    def run(self, log_entry):
        print(f"[{self.name}] Processing:\n{log_entry}")
        # Placeholder: You can hook LLMs or logic here
        return {"attack_detected": False}


class Runner:
    def __init__(self, agent):
        self.agent = agent

    def execute(self, log_entry):
        return self.agent.run(log_entry)
