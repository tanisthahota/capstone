# capstone/AGENT/handoffs/router.py

from handoffs.dos import dos_agent

def handoff(log_entry):
    log_lower = log_entry.lower()

    if "flood" in log_lower or "syn" in log_lower:
        return dos_agent(log_entry)
    
    return {
        "agent": None,
        "detected": False,
        "reason": "No known pattern matched in handoff"
    }
