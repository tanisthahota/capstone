# Direct Threat Detection Testing Guide

This guide shows you how to directly send attack payloads via curl and see real-time detections in NEWFLOW.py without needing intermediate scripts.

## 🚀 Quick Start (30 seconds)

### Terminal 1: Start NEWFLOW.py (Real-Time Monitoring)
```bash
cd /home/uday/Desktop/PayPal/prefect-project
python NEWFLOW.py
```
You should see: `Listening to Kafka topic 'app-logs'...`

### Terminal 2: Send Attacks

**Step 1: Get an authentication token**
```bash
# Register user (one-time setup)
curl -s -X POST "http://localhost:8080/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq .

# Login and extract token
TOKEN=$(curl -s -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq -r '.token')

echo "Token: $TOKEN"
```

**Step 2: Send attacks and watch NEWFLOW.py detect them in real-time**

---

## 📝 Direct Curl Commands

### ✅ BENIGN (Normal) Request
Watch for: **`✓`** dot in NEWFLOW.py output
```bash
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"Normal payment"}' | jq .
```
Expected NEWFLOW.py output: `✓` (printed as a dot)

---

### 🔴 XSS Attack (Classic Script Tag)
Watch for: **`🚨 SECURITY ALERT! XSS @ 99.94%`** in NEWFLOW.py output
```bash
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"<script>alert('"'"'XSS'"'"')</script>"}' | jq .
```
Expected NEWFLOW.py output: `🚨 SECURITY ALERT! XSS (Score: 99.94%)`

---

### 🔴 XSS Attack (IMG SRC)
Watch for: **`🚨 SECURITY ALERT! XSS`** in NEWFLOW.py output
```bash
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"<img src=x onerror=alert(1)>"}' | jq .
```

---

### 🟡 SQLi Attack (Classic OR 1=1)
Watch for: **`SQLi @ 58.58%`** in NEWFLOW.py output (below alert threshold)
```bash
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"admin'"'"' OR '"'"'1'"'"'='"'"'1","description":"test"}' | jq .
```

---

### 🟡 SQLi Attack (UNION SELECT)
Watch for: **`SQLi @`** in NEWFLOW.py output
```bash
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"admin UNION SELECT * FROM users--","description":"advanced"}' | jq .
```

---

## 🎯 Interactive Testing Script

For an interactive menu-driven interface:
```bash
./direct-threat-test.sh
```

Menu options:
- **1**: Run ALL tests (benign + all attacks)
- **2**: Test benign traffic only
- **3**: Test SQLi attack
- **4**: Test XSS attack
- **5**: Test command injection pattern
- **6**: Run sequential attacks
- **7**: Send custom JSON payload
- **8**: Exit

---

## 🔧 Custom Attack Payloads

You can modify the `description` field to send any custom payload:

```bash
# Custom payload template
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"test@test.com","description":"YOUR_CUSTOM_PAYLOAD"}' | jq .
```

Examples:
```bash
# Path traversal pattern
-d '{"amount":100,"recipient":"test@test.com","description":"../../../etc/passwd"}'

# XXE pattern
-d '{"amount":100,"recipient":"test@test.com","description":"<?xml version='"'"'1.0'"'"'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '"'"'file:///etc/passwd'"'"'>]><foo>&xxe;</foo>"}'

# LDAP injection pattern
-d '{"amount":100,"recipient":"test@test.com","description":"*)(|(uid=*"}'
```

---

## 📊 NEWFLOW.py Output Reference

### ✅ Normal Log (Benign Traffic)
```
.
```
(Single dot - barely visible as noise)

### 🚨 XSS Alert (High Confidence)
```
🚨 SECURITY ALERT! XSS (Score: 99.94%)
Full log: [log details...]
```

### 🟡 SQLi Detection (Low Confidence - No Alert)
```
SQLi (Score: 58.58%) - CONFIDENCE BELOW THRESHOLD (90%)
```

---

## 💡 How It Works

1. **Terminal 1 - NEWFLOW.py**: Listens to Kafka topic `app-logs` in real-time
2. **Terminal 2 - curl command**: Sends HTTP request to API
3. **Microservice**: Logs the request with request body to Kafka
4. **Kafka**: Message delivered to NEWFLOW.py
5. **NEWFLOW.py**: Extracts content, runs ML model, detects threats
6. **Output**: Alert printed to console immediately

**Latency**: ~100-500ms from curl to detection

---

## 🛠️ Troubleshooting

### NEWFLOW.py not detecting anything?
- Check Kafka is running: `docker ps | grep kafka`
- Check microservices are running: `docker ps | grep payment-service`
- Check NEWFLOW.py is subscribed to `app-logs` topic

### "Authorization required" error?
- Make sure `$TOKEN` variable is set
- Verify token was extracted correctly: `echo $TOKEN`
- Try getting a new token

### No real-time output?
- Increase Kafka consumer timeout: add `session_timeout_ms=10000` to KafkaConsumer
- Check network connectivity: `telnet localhost 9092`

---

## 📚 Testing Sequence

For comprehensive validation:

```bash
# Test 1: Benign traffic (should see dots)
for i in {1..5}; do
  curl -s -X POST "http://localhost:8080/api/payment/process" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"amount\":$((100 + i))}," | jq .
  sleep 1
done

# Test 2: XSS attack (should trigger alert)
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"<script>alert(1)</script>"}' | jq .

sleep 2

# Test 3: SQLi attack (should detect but not alert)
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"admin'"'"' OR '"'"'1'"'"'='"'"'1","description":"test"}' | jq .
```

---

## 🎓 Key Points

- **Direct curl**: No intermediate scripts needed
- **Real-time**: See detections as they happen
- **CSIC 2010 format**: Logs are structured in the dataset format
- **ML-powered**: Uses fine-tuned DistilBERT with LoRA adapter
- **Configurable threshold**: Default 90%, adjust in NEWFLOW.py

---

## 📱 One-Liner Setup

Copy-paste this entire block to automate everything:

```bash
# Set variables
API="http://localhost:8080/api"
TOKEN=$(curl -s -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass"}' | \
  curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"pass"}' | jq -r '.token')

# Send benign
curl -X POST "$API/payment/process" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" -d '{"amount":100,"recipient":"u@e.com","description":"test"}' | jq .

# Send XSS
curl -X POST "$API/payment/process" -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" -d '{"amount":100,"recipient":"u@e.com","description":"<script>1</script>"}' | jq .
```

---

**Happy Testing! 🔐**
