# test_model.py
import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel
from typing import List, Dict

# --- Step 1: Copy your exact preprocessing functions ---
# It's CRITICAL that these are identical to your main flow.

def parse_log_line(log_line: str) -> Dict[str, str]:
    pattern = re.compile(r'(\w+)="([^"]*)"')
    matches = pattern.findall(log_line)
    log_dict = {key: value for key, value in matches}
    log_dict.setdefault('Method', 'GET')
    log_dict.setdefault('URL', '')
    log_dict.setdefault('User-Agent', 'Mozilla/5.0')
    log_dict.setdefault('host', 'localhost')
    return log_dict

def extract_url_features(url: str) -> list:
    url_str = str(url).lower()
    features = []
    # No attack patterns should be in normal logs, but we keep this for consistency.
    if any(x in url_str for x in ['<script', 'select', '../', '`']):
        features.append('SuspiciousKeyword')
    return features

def create_text_input(row: dict) -> str:
    method = str(row.get('Method', 'GET')).upper()
    url = str(row.get('URL', ''))
    host = str(row.get('host', 'localhost'))
    ua = str(row.get('User-Agent', ''))
    path, query = url.split('?', 1) if '?' in url else (url, '')
    path = path[:300]; query = query[:300]; ua = ua[:200]
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
    parsed_data = parse_log_line(raw_log_line)
    return create_text_input(parsed_data)


# --- Step 2: Define your list of harmless logs ---
# Add more examples of what normal traffic looks like for your app.
NORMAL_LOGS_TO_TEST = [
    'payment-service-1 | Method="GET" URL="/history" User-Agent="Mozilla/5.0 (Windows NT 10.0)" host="localhost"',
    'payment-service-1 | Method="GET" URL="/" User-Agent="MyAwesomeApp/2.1.0" host="localhost"',
    'payment-service-1 | Method="POST" URL="/process" User-Agent="curl/8.9.1" host="localhost" content="{\'amount\':50.0}"',
    'payment-service-1 | Method="GET" URL="/profile/settings" User-Agent="Mozilla/5.0" host="localhost"',
    'payment-service-1 | Method="GET" URL="/assets/style.css" User-Agent="Mozilla/5.0" host="localhost"',
    'payment-service-1 | Method="POST" URL="/logout" User-Agent="Mozilla/5.0" host="localhost"',
    'payment-service-1 | Method="POST" URL="/process?id=1&action=update\' OR \'1\'=\'1" User-Agent="Mozilla/5.0" host="localhost"'
]

# --- Step 3: Main testing logic ---
def run_false_positive_test():
    print("🔬 Starting false positive test...")

    # Load model (same as in your Prefect task)
    base_model_name = "distilbert-base-uncased"
    adapter_path = "/home/uday/Downloads/89_model/89_model/"
    tokenizer = AutoTokenizer.from_pretrained(base_model_name)
    base_model = AutoModelForSequenceClassification.from_pretrained(base_model_name, num_labels=2)
    model = PeftModel.from_pretrained(base_model, adapter_path)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    false_positives = 0
    total_tests = len(NORMAL_LOGS_TO_TEST)

    for i, log in enumerate(NORMAL_LOGS_TO_TEST):
        # Preprocess the log
        processed_text = preprocess_log_for_model(log)

        # Get prediction
        inputs = tokenizer(processed_text, return_tensors="pt").to(device)
        with torch.no_grad():
            outputs = model(**inputs)
        prediction = torch.argmax(outputs.logits, dim=1).item()
        
        # Check for false positive
        if prediction == 1: # 1 means "Attack"
            false_positives += 1
            print(f"❌ Test {i+1}/{total_tests}: FALSE POSITIVE")
            print(f"   Log: \"{log}\"")
        else:
            print(f"✅ Test {i+1}/{total_tests}: Correctly identified as Normal.")

    # --- Final Report ---
    print("\n--- 📊 Test Report ---")
    fp_rate = (false_positives / total_tests) * 100
    print(f"Total Normal Logs Tested: {total_tests}")
    print(f"False Positives Detected: {false_positives}")
    print(f"False Positive Rate: {fp_rate:.2f}%")
    print("---------------------\n")
    
    if fp_rate > 10:
        print("💡 Recommendation: The model seems overly sensitive. Consider retraining with more diverse 'normal' log examples.")
    else:
        print("👍 The model's false positive rate is reasonable.")


if __name__ == "__main__":
    run_false_positive_test()
