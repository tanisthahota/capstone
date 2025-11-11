#!/usr/bin/env python
#
# Install dependencies:
# pip install prefect kafka-python torch transformers peft scikit-learn

import re
import json
from typing import List, Optional, Dict
from prefect import flow, task, get_run_logger
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel
from kafka import KafkaConsumer

# --- 1. Helper Function (from your file) ---

def extract_content_from_log(log_line: str) -> Optional[str]:
    """
    Parses a single log line and extracts the 'content' field.
    Handles nested escaped quotes and JSON-formatted content.
    """
    # Find the content field using a more robust approach
    # Look for: content="..."
    content_start = log_line.find('content="')
    if content_start == -1:
        print(f"[DEBUG EXTRACT] No 'content=' field found in log")
        return None
    
    # Start after 'content="'
    content_start += len('content="')
    
    # Find the closing quote, accounting for escaped quotes
    i = content_start
    content_chars = []
    while i < len(log_line):
        char = log_line[i]
        
        if char == '\\' and i + 1 < len(log_line):
            # Escaped character - include both the backslash and the next char
            next_char = log_line[i + 1]
            if next_char == '"':
                # This is an escaped quote - add just the quote to content
                content_chars.append('"')
                i += 2  # Skip both the backslash and quote
            else:
                # Other escape sequence - keep as is
                content_chars.append(char)
                content_chars.append(next_char)
                i += 2
        elif char == '"':
            # Unescaped quote = end of content
            break
        else:
            content_chars.append(char)
            i += 1
    
    content = ''.join(content_chars)
    if content:
        print(f"[DEBUG EXTRACT] Extracted content: {repr(content[:100])}")
    else:
        print(f"[DEBUG EXTRACT] Content field was empty")
    return content if content else None

# --- 2. Prefect Tasks ---

@task
def load_application_slm() -> Dict:
    """
    Loads your fine-tuned Application SLM (LoRA) and tokenizer *once*.
    """
    print("TASK: Loading Application SLM...")
    
    # --- ⚠️ IMPORTANT: This path is from your new_flow.py ---
    adapter_path = "/home/uday/Downloads/sqli_benign_xss/content/model_output/final_lora_model" 
    base_model_name = "distilbert-base-uncased"
    label_map = {0: "Normal", 1: "SQLi", 2: "XSS"} # From your training

    try:
        tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        
        base_model = AutoModelForSequenceClassification.from_pretrained(
            base_model_name,
            num_labels=len(label_map) # Set to 3 labels
        )
        
        # Apply the trained LoRA adapter
        model = PeftModel.from_pretrained(base_model, adapter_path)
        
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        
        print(f"✅ Application SLM loaded successfully to {device}.")
        
        return {
            "model": model,
            "tokenizer": tokenizer,
            "label_map": label_map,
            "device": device
        }
    except Exception as e:
        print(f"🚨 FATAL: Could not load model from {adapter_path}.")
        print(f"Please check the path. Error: {e}")
        raise

@task
def analyze_log_content(log_content: str, model_pack: Dict) -> Optional[Dict]:
    """
    Analyzes a *single* preprocessed log content string with the loaded model.
    Includes debug logging to help diagnose issues.
    """
    if not log_content:
        return None
        
    # Unpack the loaded model components
    model = model_pack["model"]
    tokenizer = model_pack["tokenizer"]
    label_map = model_pack["label_map"]
    device = model_pack["device"]

    # --- Debug: Show what we're analyzing ---
    print(f"\n[DEBUG] Raw content extracted: {repr(log_content)}")
    print(f"[DEBUG] Content length: {len(log_content)} chars")
    print(f"[DEBUG] First 100 chars: {log_content[:100]}")

    # --- Run Inference ---
    inputs = tokenizer(log_content, return_tensors="pt", truncation=True, padding=True, max_length=512).to(device)
    with torch.no_grad():
        outputs = model(**inputs)
    
    # Apply softmax to get probabilities
    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    conf, pred_idx = torch.max(probs, dim=1)
    
    prediction_index = pred_idx.item()
    label = label_map.get(prediction_index, "Unknown")
    score = conf.item()
    
    # --- Debug: Show all probabilities ---
    all_probs = probs[0].cpu().numpy()
    print(f"[DEBUG] Probabilities: Normal={all_probs[0]:.4f}, SQLi={all_probs[1]:.4f}, XSS={all_probs[2]:.4f}")
    print(f"[DEBUG] Prediction: {label} (confidence: {score:.4f})\n")

    return {
        "content": log_content,
        "prediction": label,
        "score": score
    }

# --- 3. The Main Prefect Flow (Modified for Streaming) ---

@flow(log_prints=True)
def realtime_app_log_analysis_flow(confidence_threshold: float = 0.45):
    """
    Orchestrates the threat detection pipeline in real-time.
    
    Args:
        confidence_threshold: Minimum confidence (0-1) to trigger a security alert.
                            Default 0.45 (45%). Lower = more sensitive, more false positives.
    """
    logger = get_run_logger()
    print(f"\n🔍 Threat Detection Started!")
    print(f"📊 Confidence threshold: {confidence_threshold:.0%}")
    print(f"⏳ Listening to Kafka topic 'app-logs'...\n")
    
    # --- Step 1: Load the SLM (runs once) ---
    model_pack = load_application_slm()
    
    # --- Step 2: Connect to Kafka (runs forever) ---
    print("Connecting to Kafka topic 'app-logs'...")
    try:
        consumer = KafkaConsumer(
            'app-logs',
            bootstrap_servers='localhost:9092',
            auto_offset_reset='latest', # Start from the newest messages
            consumer_timeout_ms=1000  # Don't block forever if no messages
        )
        print("✅ Connected to Kafka successfully!\n")
    except Exception as e:
        print(f"🚨 FATAL: Could not connect to Kafka at localhost:9092. Is it running?")
        print(f"Error: {e}")
        return

    print("✅ Kafka connected. Listening for application logs...\n")

    # --- Step 3: Run the infinite detection loop ---
    message_count = 0
    for message in consumer:
        # 1. Get log from Kafka
        log_line = message.value.decode('utf-8')
        message_count += 1
        print(f"\n[MSG #{message_count}] Received log from Kafka")
        
        # 2. Preprocess the log
        # This is the same function from your original script 
        log_content = extract_content_from_log(log_line)
        
        if not log_content:
            print(f"[MSG #{message_count}] ⚠️  No content field found, skipping")
            continue # Skip logs that don't have a 'content' field

        # 3. Analyze the log content
        prediction = analyze_log_content(log_content, model_pack)

        # 4. Report the threat
        if prediction and prediction["prediction"] != "Normal":
            # Set a confidence threshold to reduce false positives
            if prediction["score"] > confidence_threshold:
                print(
                    f"\n{'='*60}")
                print(f"🚨 SECURITY ALERT! 🚨")
                print(f"{'='*60}")
                print(f"  Threat Type: {prediction['prediction']}")
                print(f"  Confidence: {prediction['score']:.4f} ({prediction['score']:.2%})")
                print(f"  Content: {prediction['content'][:200]}")
                print(f"{'='*60}\n")
            else:
                print(f"[LOW CONF] {prediction['prediction']} @ {prediction['score']:.2%} (threshold: {confidence_threshold:.2%})")
        else:
            if prediction:
                print(f"[BENIGN] Normal @ {prediction['score']:.2%}")
            
# --- 4. Script Entry Point ---

if __name__ == "__main__":
    realtime_app_log_analysis_flow()
