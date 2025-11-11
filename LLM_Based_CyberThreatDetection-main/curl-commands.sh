#!/bin/bash

# One-Liner Direct Threat Detection Commands
# Use these to quickly test specific attacks without interactive menus

API_BASE="http://localhost:8080/api"

# ============================================================================
# STEP 1: Register & Get Token (run once at the beginning)
# ============================================================================

echo "Registering user and getting token..."

# Register
curl -s -X POST "$API_BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Get token and save it
TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq -r '.token')

echo "Token: $TOKEN"
echo ""

# ============================================================================
# STEP 2: Send Attacks - One Command per Attack
# ============================================================================

echo "Now copy and paste any of these commands:"
echo ""

# BENIGN REQUEST
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "BENIGN (Normal) - Watch for '✓' dot in NEWFLOW.py:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat << 'EOF'
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"Regular payment"}' | jq .
EOF
echo ""

# SIMPLE SQLi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SQLi ATTACK - Watch for 'SQLi @' in NEWFLOW.py:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat << 'EOF'
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"admin'"'"' OR '"'"'1'"'"'='"'"'1","description":"test"}' | jq .
EOF
echo ""

# CLASSIC XSS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "XSS ATTACK - Watch for '🚨 SECURITY ALERT!' + '99.94%' in NEWFLOW.py:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat << 'EOF'
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"<script>alert('"'"'XSS'"'"')</script>"}' | jq .
EOF
echo ""

# IMG SRC XSS
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "XSS (IMG SRC) - Another XSS variant:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat << 'EOF'
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"<img src=x onerror=alert(1)>"}' | jq .
EOF
echo ""

# UNION SELECT SQLi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SQLi (UNION SELECT) - Advanced SQLi:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat << 'EOF'
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"admin UNION SELECT * FROM users--","description":"advanced"}' | jq .
EOF
echo ""

# ============================================================================
# STEP 3: Quick Setup (copy-paste everything below)
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "QUICK START - Copy & paste everything below in a terminal:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat << 'SETUP'

# Terminal 1: Start NEWFLOW.py (real-time monitoring)
python /home/uday/Desktop/PayPal/prefect-project/NEWFLOW.py

# Terminal 2: Register and get token
curl -s -X POST "http://localhost:8080/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

TOKEN=$(curl -s -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq -r '.token')

echo "Your token: $TOKEN"

# Then send attacks:
# Send benign:
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"Normal payment"}' | jq .

# Send XSS (should get detected with 99.94%):
curl -s -X POST "http://localhost:8080/api/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"user@example.com","description":"<script>alert(1)</script>"}' | jq .

SETUP

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
