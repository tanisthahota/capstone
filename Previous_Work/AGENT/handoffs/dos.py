import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from agent_dec import Agent
import pandas as pd

ref_data = pd.read_csv(r"C:\Users\zwano\OneDrive\Desktop\cappy\capstone\dos.csv")

slowloris = Agent(
    name="slowloris_detector",
    handoff_description="Detects Slowloris-style DoS attacks",
    instructions=(
        "If you see very long-lived connections from the same IP, "
        "with incomplete headers and very low request rate per connection, "
        "it's a Slowloris attack. Return: attack_type: slowloris"
    )
)

hulk = Agent(
    name="hulk_detector",
    handoff_description="Detects HULK-style DoS attacks",
    instructions=(
        "If you see extremely high request rate from one IP, "
        "with many unique URLs and randomized headers (User-Agent, Referrer), "
        "it's a HULK attack. Return: attack_type: hulk"
    )
)

goldeneye = Agent(
    name="goldeneye_detector",
    handoff_description="Detects GoldenEye-style DoS attacks",
    instructions=(
        "If you see a mix of GET and POST requests with Keep-Alive headers, "
        "high concurrency from a single IP, and large POST payloads, "
        "it's a GoldenEye attack. Return: attack_type: goldeneye"
    )
)

def dos(logs):
    identifier = Agent(
        name="dos_triage_agent",
        instructions=(
            f"You are a DoS triage agent. Determine if the following logs represent a DoS attack using the schema {list(ref_data.columns)}. "
            f"If yes, hand off to the appropriate agent to classify the type of DoS attack."
        ),
        handoffs=[slowloris, hulk, goldeneye]
    )
    return identifier.run(logs)
