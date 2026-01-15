#!/usr/bin/env python3
"""
Test script to diagnose model classification issues
Shows what the model predicts for SQLi vs XSS payloads
"""

import torch
import json
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel

# Load model
print("Loading model...")
adapter_path = "/workspace/slm/sqli_benign_xss/model_output/final_lora_model"
base_model_name = "distilbert-base-uncased"
label_map = {0: "Normal", 1: "SQLi", 2: "XSS"}

tokenizer = AutoTokenizer.from_pretrained(base_model_name)
base_model = AutoModelForSequenceClassification.from_pretrained(base_model_name, num_labels=3)
model = PeftModel.from_pretrained(base_model, adapter_path)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)
model.eval()
print(f"Model loaded on {device}\n")

# Test SQLi payloads
sqli_tests = [
    ("POST /auth/login", '{"email":"admin\' OR \'1\'=\'1","password":"test"}'),
    ("POST /auth/login", '{"email":"admin\'--","password":""}'),
    ("POST /auth/login", '{"email":"\' OR 1=1--","password":"test"}'),
    ("POST /auth/login", '{"email":"admin\' UNION SELECT NULL--","password":"test"}'),
]

# Test XSS payloads
xss_tests = [
    ("POST /auth/register", '{"email":"<script>alert(\'XSS\')</script>","password":"test"}'),
    ("POST /auth/register", '{"email":"test@test.com","password":"<img src=x onerror=alert(\'XSS\')>"}'),
    ("POST /auth/register", '{"email":"<svg onload=alert(\'XSS\')>","password":"test"}'),
    ("POST /auth/register", '{"email":"javascript:alert(\'XSS\')","password":"test"}'),
]

def parse_content(content_str):
    """Parse JSON content and extract payload"""
    try:
        content_dict = json.loads(content_str)
        email = content_dict.get('email', '')
        password = content_dict.get('password', '')
        return f"email:{email} password:{password}"
    except:
        return content_str

def test_payload(method_url, content, expected_type):
    """Test a single payload"""
    content_text = parse_content(content)
    text = f"{method_url} {content_text}"[:512]
    
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512).to(device)
    with torch.no_grad():
        outputs = model(**inputs)
    
    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    all_probs = probs[0].cpu().numpy()
    
    pred_idx = torch.argmax(probs, dim=1).item()
    predicted = label_map[pred_idx]
    confidence = all_probs[pred_idx]
    
    prob_normal = all_probs[0]
    prob_sqli = all_probs[1]
    prob_xss = all_probs[2]
    
    # Check if correct
    is_correct = "✓" if predicted == expected_type else "✗"
    
    print(f"{is_correct} Expected: {expected_type:6} | Predicted: {predicted:6} | Conf: {confidence:.2%}")
    print(f"   Probabilities - Normal: {prob_normal:.2%}, SQLi: {prob_sqli:.2%}, XSS: {prob_xss:.2%}")
    print(f"   Payload: {content_text[:80]}...")
    print()

print("="*70)
print("TESTING SQL INJECTION PAYLOADS")
print("="*70)
for method_url, content in sqli_tests:
    test_payload(method_url, content, "SQLi")

print("\n" + "="*70)
print("TESTING XSS PAYLOADS")
print("="*70)
for method_url, content in xss_tests:
    test_payload(method_url, content, "XSS")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print("If SQLi payloads are being classified as XSS, the issue is likely:")
print("1. Model training data bias")
print("2. Model needs retraining with better SQLi examples")
print("3. Preprocessing not capturing SQLi-specific patterns (OR, UNION, --, etc.)")

