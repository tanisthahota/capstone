# full_flow.py

import re
from typing import List, Optional, Dict
from prefect import flow, task
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel

# --- 1. Helper Function for Preprocessing ---

def extract_content_from_log(log_line: str) -> Optional[str]:
    """
    Parses a single log line and extracts the 'content' field using a
    more robust regex that handles escaped characters.
    """
    # This new regex correctly handles escaped quotes inside the content string.
    content_match = re.search(r'content="((?:\\.|[^"\\])*)"', log_line)
    
    if content_match:
        content = content_match.group(1)
        # Unescape any escaped quotes (e.g., \\" becomes ")
        return content.replace('\\"', '"')
    
    return None# --- 2. Prefect Tasks ---

@task
def collect_logs_from_file(log_path: str) -> List[str]:
    """
    Reads all lines from a specified log file.
    """
    print(f"TASK: Collecting logs from file: {log_path}...")
    try:
        with open(log_path, "r", encoding='utf-8', errors='ignore') as f:
            raw_logs = f.readlines()
        print(f"Collected {len(raw_logs)} log entries.")
        return raw_logs
    except FileNotFoundError:
        print(f"⚠️ ERROR: Log file not found at {log_path}!")
        return []

@task
def preprocess_logs_for_llm(logs: List[str]) -> List[str]:
    """
    Takes a list of raw log lines and extracts only the 'content'
    field required by the new model.
    """
    print("TASK: Preprocessing logs for the new model...")
    
    processed_contents = []
    for log in logs:
        content = extract_content_from_log(log)
        if content: # Only include logs that have a content field
            processed_contents.append(content)
            
    print(f"Successfully extracted content from {len(processed_contents)} logs.")
    
    if processed_contents:
        print("\n--- Example of Processed Content ---")
        print(processed_contents[0])
        print("------------------------------------\n")
        
    return processed_contents

@task
def analyze_with_llm(processed_contents: List[str]) -> List[Dict]:
    """
    Loads the local LLM and analyzes the preprocessed log contents for threats.
    """
    if not processed_contents:
        print("TASK: No content to analyze.")
        return []
        
    print(f"TASK: Loading model and analyzing {len(processed_contents)} log contents...")

    # --- ⚠️ IMPORTANT: UPDATE THIS PATH FOR YOUR NEW MODEL ---
    adapter_path = "/home/uday/Downloads/sqli_benign_xss/content/model_output/final_lora_model" 

    # --- Model Loading Configuration ---
    base_model_name = "distilbert-base-uncased"
    label_map = {0: "Normal", 1: "SQLi", 2: "XSS"} # Verify this order from training!

    # Load the tokenizer from the base model
    tokenizer = AutoTokenizer.from_pretrained(base_model_name)
    
    # Load the base model, ensuring it has 3 labels to match the trained adapter
    base_model = AutoModelForSequenceClassification.from_pretrained(
        base_model_name,
        num_labels=len(label_map) # Set to 3
    )
    
    # Apply the trained LoRA adapter
    model = PeftModel.from_pretrained(base_model, adapter_path)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    results = []
    print("--- Inference Results ---")
    for content in processed_contents:
        inputs = tokenizer(content, return_tensors="pt", truncation=True, padding=True).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        
        prediction_index = torch.argmax(outputs.logits, dim=1).item()
        label = label_map.get(prediction_index, "Unknown")
        
        results.append({"content": content, "prediction": label})
        print(f"Prediction: {label} ==> Content: \"{content[:80]}...\"")
        
    print("-------------------------")
    return results


# --- 3. The Main Prefect Flow ---

@flow(log_prints=True)
def log_analysis_flow():
    """
    Orchestrates the entire threat detection pipeline from log file to prediction.
    """
    # --- ⚠️ UPDATE THIS PATH to your actual log file ---
    log_file_path = "/home/uday/Desktop/PayPal/prefect-project/sqli.log"

    raw_logs = collect_logs_from_file(log_path=log_file_path)
    
    if raw_logs:
        processed_contents = preprocess_logs_for_llm(logs=raw_logs)
        predictions = analyze_with_llm(processed_contents=processed_contents)
        
        # Any prediction that is NOT "Normal" is considered an attack.
        attacks_found = [p for p in predictions if p["prediction"] != "Normal"]

        if attacks_found:
            print(f"🚨 SECURITY ALERT! Detected {len(attacks_found)} potential attack(s).")
        else:
            print("✅ Flow finished. No threats detected in log contents.")
    else:
        print("Flow finished: No logs were collected.")

# --- 4. Script Entry Point ---

if __name__ == "__main__":
    log_analysis_flow()
