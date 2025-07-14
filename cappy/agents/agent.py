import os
import requests
from dotenv import load_dotenv
import pandas as pd 

env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(dotenv_path=env_path)


ref_data = pd.read_csv(r"C:\Users\zwano\OneDrive\Desktop\capstone\csv collected\dos.csv")
API_KEY = os.getenv("OPENAI_API_KEY") 

def detect_threat(log_entry):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "http://localhost",
        "X-Title": "CapstoneThreatDetector",
        "Content-Type": "application/json"
    }

    data = {
        "model": "google/gemini-2.0-flash-001",
        "messages": [
            {
                "role": "user",
                "content": f"You are a cybersecurity analyst. read the file contents anc compare with the data in ${ref_data} and tell whether it a ddos attack or not? Give yes/no:\n\nLog: {log_entry}. and also ignore the Label in the entry Logs"
            }
        ]
    }

    response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=data)

    if response.status_code != 200:
        print("❌ Error:", response.status_code, response.text)
        return None

    result = response.json()
    return result['choices'][0]['message']['content']


log = pd.read_csv("cicids_72_features.csv")

print(detect_threat(log))