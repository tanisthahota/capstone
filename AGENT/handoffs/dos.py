from agents import Agent
import pandas as pd

ref_data = pd.read_csv(r"/Users/vishnu.v/Desktop/me/capstone/capstone/dos.csv")

slowloris = Agent(
    name = "lookup writer",
    handoff_description = "tells what kind of a DoS attack the logs represent",
    instructions = (
        "If you see very long-lived connections from the same IP, "
        "with incomplete headers and very low request rate per connection, "
        "it's a Slowloris attack. Then say 'slowloris yes'"
    )
)

hulk = Agent(
    name = "lookup writer",
    handoff_description = "tells what kind of a DoS attack the logs represent",
    instructions = (
        "If you see extremely high request rate from one IP, "
        "with many unique URLs and randomized headers (User-Agent, Referrer), "
        "it's a HULK attack. Then say 'hulk yes'"
    )
)

goldeneye = Agent(
    name = "lookup writer",
    handoff_description = "tells what kind of a DoS attack the logs represent",
    instructions = (
        "If you see a mix of GET and POST requests with Keep-Alive headers, "
        "high concurrency from a single IP, and large POST payloads, "
        "it's a GoldenEye attack. Then say 'goldeneye yes'"
    )
)


def dos(logs):
    identifier = Agent(
        name = "triage agent",
        instructions = (
            f"You determine if the following {logs} represent a DoS attack using the dataset schema {list(ref_data.columns)}. "
            f"If yes, use the handoffs to identify the correct type of DoS attack."
        ),
        handoffs = [goldeneye, hulk, slowloris],
    )
    return identifier
