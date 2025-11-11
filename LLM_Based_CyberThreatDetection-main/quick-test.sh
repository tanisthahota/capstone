#!/bin/bash

# Ultra Simple Direct Testing - Just Run This!
# This will setup everything and let you send attacks directly

set -e

API="http://localhost:8080/api"

echo "🔐 PayPal Clone - Direct Attack Testing"
echo "========================================"
echo ""

# Step 1: Register
echo "📝 Registering test user..."
curl -s -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' > /dev/null

# Step 2: Get token
echo "🔑 Getting authentication token..."
TOKEN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq -r '.token')

echo "✅ Token: $TOKEN"
echo ""

# Step 3: Show examples
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "READY TO SEND ATTACKS! Copy any command below and run it:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📊 BENIGN (Should show ✓ dot in NEWFLOW.py):"
echo "curl -s -X POST \"$API/payment/process\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer $TOKEN\" -d '{\"amount\":100,\"recipient\":\"user@example.com\",\"description\":\"normal payment\"}' | jq ."
echo ""

echo "🔴 XSS ATTACK (Should show 🚨 ALERT + 99.94% in NEWFLOW.py):"
echo "curl -s -X POST \"$API/payment/process\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer $TOKEN\" -d '{\"amount\":100,\"recipient\":\"user@example.com\",\"description\":\"<script>alert(1)</script>\"}' | jq ."
echo ""

echo "🟡 SQLi ATTACK (Should show SQLi detection in NEWFLOW.py):"
echo "curl -s -X POST \"$API/payment/process\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer $TOKEN\" -d '{\"amount\":100,\"recipient\":\"admin'"'"' OR '"'"'1'"'"'='"'"'1\",\"description\":\"attack\"}' | jq ."
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Save token to file for easy reuse
echo "💾 Token saved to: /tmp/paypal-token.txt"
echo "$TOKEN" > /tmp/paypal-token.txt

echo "To reuse token in future: export TOKEN=\$(cat /tmp/paypal-token.txt)"
