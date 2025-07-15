print("hello")

import tensorflow_probability as tfp
import tensorflow as tf
import jax
import os
import pandas as pd
import asyncio
from openai import OpenAI
from dotenv import load_dotenv
from handoffs.dos import dos

tfd = tfp.distributions

print("TF devices:", tf.config.list_physical_devices())
print("JAX version:", jax.__version__)

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("❌ OPENAI_API_KEY not found. Check your .env file.")

client = OpenAI(
    api_key=OPENAI_API_KEY,
    base_url="https://openrouter.ai/api/v1"
)
def run_threat_analysis(log_entry):
    prompt = f"""
You are an intelligent cybersecurity agent.
Analyze this log entry:
{log_entry}
Determine if it contains a potential attack.
Return a JSON object with keys: `attack_detected`, `attack_type`, and `reason`.
"""

    response = client.chat.completions.create(
        model="openai/gpt-4o",  # or "mistralai/mistral-7b-instruct"
        messages=[
            {"role": "system", "content": "You are a threat detection agent."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
        max_tokens=1000,
    )

    print("\n📊 GPT Response:")
    print(response.choices[0].message.content)

def main():
    test_log = "172.19.0.3,172.19.0.2,32958,5000,2048,2025-06-13 12:04:45,3.570123,671.1253365780394,7.002559855780879,3.641331125006057,3.361228730774822,13,12,1136,1260,160,72,87.38461538461539,31.136272346273273,238,72,105.0,60.08604940694082,238,72,95.84,48.10960818797011,2314.5344000000005,260,240,20,2,0.14875512500000002,2.791981,0.0,0.5725810406166182,3.570079,2.792258,0.0,0.2975065833333333,0.7820384541452611,3.569984,2.791995,1e-06,0.324544,0.8113351827174087,2,4,0,0,4,5,0,6,22,0,0,0.9230769230769231,95.84,64240,65160,0,0,0,0,0,0,0,0,0,0,380.0,4.0,0,3.04E+6,87.38461538461539,105.0,0,13,12,1136,1260"
    run_threat_analysis(test_log)

if __name__ == "__main__":
    main()
