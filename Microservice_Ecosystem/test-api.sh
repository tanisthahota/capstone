#!/bin/bash

API_BASE="http://localhost:8080/api"

echo "🧪 Testing PayPal Clone API"

# Test health endpoints
echo "1. Testing health endpoints..."
curl -s "$API_BASE/auth/health" | jq .
curl -s "$API_BASE/payment/health" | jq .
curl -s "$API_BASE/notification/health" | jq .

# Register user
echo -e "\n2. Registering user..."
curl -s -X POST "$API_BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq .

# Login user
echo -e "\n3. Logging in user..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}')

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.token')
echo $LOGIN_RESPONSE | jq .

# Process payment
echo -e "\n4. Processing payment..."
curl -s -X POST "$API_BASE/payment/process" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":100,"recipient":"recipient@example.com","description":"Test payment"}' | jq .

# Get payment history
echo -e "\n5. Getting payment history..."
curl -s -X GET "$API_BASE/payment/history" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n✅ API tests completed!"
