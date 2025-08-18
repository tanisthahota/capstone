
# Focused on OpenAI API usage for threat analysis
from openai import OpenAI
from dotenv import load_dotenv
from handoffs.dos import dos
import os

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

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
    test_log =" 172.19.0.3,172.19.0.2,32982,5000,2048,2025-06-13 12:04:46,3.691548,390.080259013292,4.605114168906919,2.438001618833075,2.167112550073844,9,8,848,592,160,72,94.22222222222223,35.33263451440318,80,72,74.0,3.4641016151377544,160,72,84.70588235294117,27.720802776514144,768.4429065743943,180,160,20,2,0.23072175,3.68692,0.0,0.8923870461395591,3.691524,3.687601,0.0,0.4614405,1.219374715789203,3.6915310000000003,3.68692,1e-06,0.5273615714285714,1.2898850060581655,2,0,0,0,4,5,0,2,14,0,0,0.8888888888888888,84.70588235294117,64240,65160,0,0,0,0,0,0,0,0,0,0,0,0,0,0,94.22222222222223,74.0,0,9,8,848,592"
    run_threat_analysis(test_log)

if __name__ == "__main__":
    main()
