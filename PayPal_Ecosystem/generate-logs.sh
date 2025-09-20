#!/bin/bash

API_BASE="http://localhost:8080/api"
LOG_FILE="logs/ecosystem-$(date +%Y%m%d-%H%M%S).log"

mkdir -p logs

log_with_timestamp() {
    # The >&2 redirects the echo output to standard error
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2 | tee -a "$LOG_FILE"
}

make_api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local header=$4
    
    local url="$API_BASE$endpoint"
    log_with_timestamp "🔄 API Call: $method $url"
    
    local curl_opts=(-s -X "$method")
    
    curl_opts+=(-H "Content-Type: application/json")
    
    if [ -n "$header" ]; then
        curl_opts+=(-H "$header")
    fi
    
    if [ -n "$data" ]; then
        curl_opts+=(-d "$data")
    fi
    
    response=$(curl "${curl_opts[@]}" "$url")
    log_with_timestamp "📥 Response: $response"
    echo "$response"
}

extract_json_value() {
    local json="$1"
    local key="$2"
    # The -r flag outputs the raw string without quotes
    echo "$json" | jq -r ".${key}"
}

log_with_timestamp "🚀 Starting PayPal Clone Ecosystem Test Suite"
log_with_timestamp "=============================================="

# STEP 1: Health Checks
log_with_timestamp ""
log_with_timestamp "🏥 STEP 1: Health Checks"
log_with_timestamp "========================"

make_api_call "GET" "/auth/health" "" ""
sleep 1
make_api_call "GET" "/payment/health" "" ""
sleep 1  
make_api_call "GET" "/notification/health" "" ""
sleep 2

# STEP 2: User Registration
log_with_timestamp ""
log_with_timestamp "👤 STEP 2: User Registration"
log_with_timestamp "============================"

users=("alice@paypal.com" "bob@paypal.com" "charlie@paypal.com")
tokens=()

for user in "${users[@]}"; do
    log_with_timestamp "📝 Registering user: $user"
    make_api_call "POST" "/auth/register" "{\"email\":\"$user\",\"password\":\"password123\"}" ""
    sleep 1
done

# STEP 3: User Login (Simplified)
log_with_timestamp ""
log_with_timestamp "🔐 STEP 3: User Login"
log_with_timestamp "====================="

for user in "${users[@]}"; do
    log_with_timestamp "🔑 Logging in user: $user"
    response=$(make_api_call "POST" "/auth/login" "{\"email\":\"$user\",\"password\":\"password123\"}" "")
    log_with_timestamp "🐞 Raw login response: $response"

    # The new function handles everything cleanly
    token=$(extract_json_value "$response" "token")
    log_with_timestamp "🐞 Extracted token: $token"
    
    if [ -n "$token" ] && [ "$token" != "null" ]; then
        tokens+=("$token")
        short_token="${token:0:20}..."
        log_with_timestamp "✅ Token extracted successfully for $user"
        log_with_timestamp "🔒 Token details: $short_token"
        
        # Verify immediately after login
        log_with_timestamp "🔑 Verifying token immediately after login"
        make_api_call "POST" "/auth/verify" "" "Authorization: Bearer $token"
    else
        tokens+=("")
        log_with_timestamp "❌ Failed to extract token for $user"
    fi
    sleep 1
done
    
# STEP 4: Token Verification
log_with_timestamp ""
log_with_timestamp "✅ STEP 4: Token Verification"  
log_with_timestamp "============================="

for i in "${!tokens[@]}"; do
    # Clean token (remove quotes, newlines, carriage returns, spaces)
    token=$(echo "${tokens[$i]}" | tr -d '\n\r" ')
    
    log_with_timestamp "DEBUG Raw token for ${users[$i]}: ->${token}<-"
3
    if [ -n "$token" ] && [ "$token" != "null" ]; then
        log_with_timestamp "🎫 Verifying token for ${users[$i]}"
        make_api_call "POST" "/auth/verify" "" "Authorization: Bearer $token"
        sleep 1
    else
        log_with_timestamp "⚠️ Skipping verification for ${users[$i]} - no valid token"
    fi
done


# STEP 5: Payment Processing
log_with_timestamp ""
log_with_timestamp "💳 STEP 5: Payment Processing"
log_with_timestamp "============================="

payment_scenarios=(
    "50.00|john@example.com|Coffee payment"
    "150.75|sarah@store.com|Online shopping"
    "25.50|mike@restaurant.com|Lunch bill" 
    "300.00|landlord@apartments.com|Monthly rent"
    "75.25|utilities@company.com|Electric bill"
)

for i in "${!tokens[@]}"; do
    token="${tokens[$i]}"
    if [ -n "$token" ] && [ "$token" != "null" ]; then
        for scenario in "${payment_scenarios[@]}"; do
            IFS='|' read -r amount recipient description <<< "$scenario"
            log_with_timestamp "💰 Processing payment: $amount to $recipient"
            json_payload=$(printf '{"amount":%s,"recipient":"%s","description":"%s"}' "$amount" "$recipient" "$description")
            make_api_call "POST" "/payment/process" "$json_payload" "Authorization: Bearer $token"
            sleep 2
        done
    fi
done

# STEP 6: Payment History
log_with_timestamp ""
log_with_timestamp "📊 STEP 6: Payment History"
log_with_timestamp "=========================="

if [ -n "${tokens[0]}" ] && [ "${tokens[0]}" != "null" ]; then
    log_with_timestamp "📈 Fetching payment history"
    make_api_call "GET" "/payment/history" "" "Authorization: Bearer ${tokens[0]}"
fi

# STEP 7: Error Scenarios
log_with_timestamp ""
log_with_timestamp "❌ STEP 7: Error Scenarios"
log_with_timestamp "=========================="

log_with_timestamp "🚫 Testing invalid login"
make_api_call "POST" "/auth/login" "{\"email\":\"invalid@test.com\",\"password\":\"wrong\"}" ""
sleep 1

log_with_timestamp "🚫 Testing payment without token"
make_api_call "POST" "/payment/process" "{\"amount\":100,\"recipient\":\"test@test.com\",\"description\":\"Should fail\"}" ""
sleep 1

log_with_timestamp "🚫 Testing invalid token"
make_api_call "POST" "/payment/process" "{\"amount\":100,\"recipient\":\"test@test.com\",\"description\":\"Should fail\"}" "Authorization: Bearer invalid-token"
sleep 1

# STEP 8: Full Flow Test
log_with_timestamp ""
log_with_timestamp "🔄 STEP 8: Inter-Service Communication"
log_with_timestamp "======================================"

if [ -n "${tokens[0]}" ] && [ "${tokens[0]}" != "null" ]; then
    log_with_timestamp "🎯 Testing complete flow: Auth → Payment → Notification"
    make_api_call "POST" "/payment/process" \
        "{\"amount\":999.99,\"recipient\":\"vip@customer.com\",\"description\":\"VIP Transaction - Full Flow Test\"}" \
        "Authorization: Bearer ${tokens[0]}"
fi

# Final summary
log_with_timestamp ""
log_with_timestamp "✅ ECOSYSTEM TEST COMPLETED"
log_with_timestamp "============================"
log_with_timestamp "📊 Total API calls made: $(grep -c '🔄 API Call:' "$LOG_FILE")"
log_with_timestamp "📝 Log file saved: $LOG_FILE"
