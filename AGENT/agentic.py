print("hello")
import tensorflow as tf
import jax

print("TF devices:", tf.config.list_physical_devices())
print("JAX version:", jax.__version__)
from agents import Agent, Runner
import os
import pandas as pd
# from handoffs.dos import dos
import asyncio
import openai



API_KEY = os.getenv("OpenAI_API_KEY")  


try:
        openai.api_key =API_KEY
        openai.Model.list()  # A lightweight call to list models
        print("[SUCCESS] OpenAI API key is valid ✅")
        
except Exception as e:
        print("[ERROR] Invalid OpenAI API key ❌")
        print(e)
        
def td(logs):
    threat_detector = Agent(
        name="triage agent",
        instructions=f"You determine if theres an attack. If yes, identify the correct attack using the tools:\n{logs}",
        # handoffs=[dos(logs)],
    )
    return threat_detector

async def main():
    print("[INFO] Starting threat detection...")  # DEBUG
    logs = "172.19.0.3,172.19.0.2,32958,5000,2048,2025-06-13 12:04:45,3.570123,671.1253365780394,7.002559855780879,3.641331125006057,3.361228730774822,13,12,1136,1260,160,72,87.38461538461539,31.136272346273273,238,72,105.0,60.08604940694082,238,72,95.84,48.10960818797011,2314.5344000000005,260,240,20,2,0.14875512500000002,2.791981,0.0,0.5725810406166182,3.570079,2.792258,0.0,0.2975065833333333,0.7820384541452611,3.569984,2.791995,1e-06,0.324544,0.8113351827174087,2,4,0,0,4,5,0,6,22,0,0,0.9230769230769231,95.84,64240,65160,0,0,0,0,0,0,0,0,0,0,380.0,4.0,0,3.04E+6,87.38461538461539,105.0,0,13,12,1136,1260"
    agent = td(logs)
    
    
    print("[INFO] Agent created, running...") 
    runner = Runner(agent, api_key=API_KEY, model="gpt-4o")# DEBUG

    result = await runner.run_async()
    print("[INFO] Agent finished!")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
