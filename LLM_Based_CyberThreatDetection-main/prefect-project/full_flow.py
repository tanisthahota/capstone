import re
from prefect import flow, task
from typing import List, Dict
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel


# ==============================================================================
# ✨ UPDATED PARSING FUNCTION ✨
# This is the only function that needs to change.
# ==============================================================================

def parse_log_line(log_line: str) -> Dict[str, str]:
    """
    Parses a key-value formatted log line into a dictionary.
    Example: timestamp="..." Method="..." -> {"timestamp": "...", "Method": "..."}
    """
    # Regex to find all key="value" pairs
    pattern = re.compile(r'(\w+)="([^"]*)"')
    matches = pattern.findall(log_line)
    log_dict = {key: value for key, value in matches}
    
    # Ensure essential keys exist, even if empty, to prevent errors
    log_dict.setdefault('Method', 'GET')
    log_dict.setdefault('URL', '')
    log_dict.setdefault('User-Agent', '')
    log_dict.setdefault('host', 'localhost')
    
    return log_dict

# ==============================================================================
# UNCHANGED FUNCTIONS (from your training script)
# ==============================================================================

def extract_url_features(url: str) -> list:
    """Detects known attack patterns in a URL."""
    # (This function is identical to your training script)
    url_str = str(url).lower()
    features = []
    if any(x in url_str for x in ['<script', 'javascript:', 'onerror', 'onload', 'alert(']):
        features.append('XSS')
    if any(x in url_str for x in ['select', 'union', 'drop', 'insert', '--', 'or 1=1', " or ", "' or '1'='1"]):
        features.append('SQLi')
    if any(x in url_str for x in ['../', '/etc/', 'passwd', 'windows']):
        features.append('PathTraversal')
    if any(x in url_str for x in ['|', ';', '&&', '`', '$(', 'cmd']):
        features.append('CmdInjection')
    if any(x in url_str for x in ['%00', '%20%20', 'null', '\x00']):
        features.append('NullByte')
    return features

def create_text_input(row: dict) -> str:
    """Creates the final text string for the model from a structured dictionary."""
    # (This function is identical to your training script)
    method = str(row.get('Method', 'GET')).upper()
    url = str(row.get('URL', ''))
    host = str(row.get('host', 'localhost'))
    ua = str(row.get('User-Agent', ''))
    path, query = url.split('?', 1) if '?' in url else (url, '')
    path = path[:300]
    query = query[:300]
    ua = ua[:200]
    features = extract_url_features(url)
    feature_str = ', '.join(features) if features else 'none'
    text = (
        f"Request: {method} {path}. "
        f"Host: {host}. "
        f"Query: {query if query else 'none'}. "
        f"User-Agent: {ua if ua else 'none'}. "
        f"Detected patterns: {feature_str}."
    )
    return text

def preprocess_log_for_model(raw_log_line: str) -> str:
    """Full pipeline: raw log -> parsed dictionary -> formatted model input string."""
    parsed_data = parse_log_line(raw_log_line)
    formatted_text = create_text_input(parsed_data)
    return formatted_text
# (Paste all the functions from the section above here)

@task
def collect_logs() -> List[str]:
    """Collects raw log lines from your PayPal clone ecosystem."""
    print("TASK: Collecting logs...")
    # Using your provided logs as an example
    return [
        'payment-service-1       | timestamp="2025-10-15T15:01:28.915Z" Method="POST" URL="/process?id=1&action=update\' OR \'1\'=\'1" User-Agent="Mozilla/5.0" host="localhost"',
        'payment-service-1       | timestamp="2025-10-15T15:01:29.129Z" Method="GET" URL="/history" User-Agent="Mozilla/5.0" host="localhost"',
    ]

@task
def preprocess_logs_for_llm(logs: List[str]) -> List[str]:
    """Processes a list of raw logs into the text format required by the LLM."""
    print("TASK: Preprocessing logs for the model...")
    processed_texts = [preprocess_log_for_model(log) for log in logs]
    
    print("\n--- Example of Processed Text (Attack Log) ---")
    print(processed_texts[0])
    print("----------------------------------------------\n")
    
    return processed_texts

@task
def analyze_with_llm(processed_texts: List[str]) -> List[dict]:
    """
    Loads the local LLM and adapter, then analyzes the preprocessed logs for threats.
    """
    print(f"TASK: Loading model and analyzing {len(processed_texts)} logs...")

    # --- 1. Define Model and Adapter Paths ---
    # The original model you fine-tuned
    base_model_name = "distilbert-base-uncased"
    # The path to your folder with the adapter files
    adapter_path = "/home/uday/Downloads/distilbert_lora_webattack_coral/best_model_with_lora_coral"

    # --- 2. Load the Model and Tokenizer ---
    # Load the tokenizer from your saved folder
    tokenizer = AutoTokenizer.from_pretrained(adapter_path)
    
    # Load the base model
    base_model = AutoModelForSequenceClassification.from_pretrained(
        base_model_name,
        num_labels=2,
        return_dict=True
    )
    
    # Apply your LoRA adapter to the base model
    model = PeftModel.from_pretrained(base_model, adapter_path)
    
    # --- 3. Set Device and Run Inference ---
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval() # Set the model to evaluation mode

    results = []
    print("--- Inference Results ---")
    
    for text in processed_texts:
        # Tokenize the input text
        inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True).to(device)
        
        # Get model prediction (no gradient calculation needed)
        with torch.no_grad():
            outputs = model(**inputs)
        
        # Get the predicted class (0 or 1)
        prediction = torch.argmax(outputs.logits, dim=1).item()
        label = "Attack" if prediction == 1 else "Normal"
        
        results.append({"log": text, "prediction": label})
        print(f"Prediction: {label} ==> Log: \"{text[:80]}...\"")
        
    print("-------------------------")
    return results
@flow(log_prints=True)
def log_analysis_flow():
    """The main flow that orchestrates the threat detection pipeline."""
    raw_logs = collect_logs()
    
    if raw_logs:
        processed_texts = preprocess_logs_for_llm(logs=raw_logs)
        predictions = analyze_with_llm(processed_texts=processed_texts)
        
        # Check for any detected attacks
        attacks_found = [p for p in predictions if p["prediction"] == "Attack"]
        
        if attacks_found:
            print(f"🚨 SECURITY ALERT! Detected {len(attacks_found)} potential attack(s).")
        else:
            print("✅ Flow finished. No threats detected.")
    else:
        print("Flow finished: No new logs to process.")

if __name__ == "__main__":
    log_analysis_flow()
