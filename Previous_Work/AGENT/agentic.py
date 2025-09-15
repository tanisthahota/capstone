
# Focused on OpenAI API usage for threat analysis
from openai import OpenAI
from dotenv import load_dotenv
from handoffs.dos import dos
import os

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
print(f"Loaded OPENAI_API_KEY: {OPENAI_API_KEY}")
if not OPENAI_API_KEY or OPENAI_API_KEY.strip() == "":
    raise ValueError("OPENAI_API_KEY is missing or empty. Please check your .env file.")

client = OpenAI(
    api_key=OPENAI_API_KEY,
    base_url="https://openrouter.ai/api/v1"
)

def run_threat_analysis(log_entry):
    dos_result = dos(log_entry)
    prompt = f"""
You are an intelligent cybersecurity agent.
Analyze this log entry:
{log_entry}
Detection result: {dos_result}
Return a JSON object with keys: attack_detected, attack_type, and reason.
"""
    response = client.chat.completions.create(
        model="openai/gpt-4o",
        messages=[
            {"role": "system", "content": "You are a threat detection agent."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
        max_tokens=1000,
    )
    print("\nOpenAI API Response:")
    print(response.choices[0].message.content)

def main():
    test_log ="127.0.0.1,127.0.0.1,54204,8082,6,2025-07-01 20:14:47,0.012497,116908.05793390414,1200.2880691365929,640.1536368728495,560.1344322637433,8,7,555,906,139,56,69.375,26.799895055764676,384,56,129.42857142857142,119.67916293497514,384,56,97.4,89.24557878871836,7964.773333333336,160,140,20,1,0.0008926428571428571,0.011056,0.0,0.002830697329713825,0.01244,0.011112,0.0,0.0017771428571428571,0.0038282949367112484,0.012362,0.011064,1.1e-05,0.0020603333333333333,0.0040422460615630795,1,2,0,0,2,3,0,3,13,0,0,0.875,97.4,65535,65535,0,0,0,0,0,0,0,0,0,0,0,0,0,0,69.375,129.42857142857142,0,8,7,555,906"
    run_threat_analysis(test_log)

if __name__ == "__main__":
    main()
