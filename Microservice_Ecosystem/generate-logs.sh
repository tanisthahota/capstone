#!/bin/bash

API_BASE="http://localhost:8080/api"
LOG_FILE="logs/ecosystem-$(date +%Y%m%d-%H%M%S).log"

echo "🧪 Generating Sample Logs for PayPal Clone"
echo "==========================================="
echo "📝 Logs will be saved to: $LOG_FILE"
echo ""

mkdir -p logs

log_with_timestamp() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

make_api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local headers=$4
    
    log_with_timestamp "🔄 API Call: $method $endpoint"
    
    if [ -n "$data" ]; then
        if [ -n "$headers" ]; then
            response=$(curl -s -X "$method" "$API_BASE$endpoint" -H "Content-Type: application/json" $headers -d "$data")
        else
            response=$(curl -s -X "$method" "$API_BASE$endpoint" -H "Content-Type: application/json" -d "$data")
        fi
    else
        if [ -n "$headers" ]; then
            response=$(curl -s -X "$method" "$API_BASE$endpoint" $headers)
        else
            response=$(curl -s -X "$method" "$API_BASE$endpoint")
        fi
    fi
    
    log_with_timestamp "📥 Response: $response"
    echo "$response"
}

log_with_timestamp "🚀 Starting PayPal Clone Ecosystem Test Suite"
log_with_timestamp "=============================================="

log_with_timestamp ""
log_with_timestamp "🏥 STEP 1: Health Checks"
log_with_timestamp "========================"

make_api_call "GET" "/auth/health" "" ""
sleep 1
make_api_call "GET" "/payment/health" "" ""
sleep 1  
make_api_call "GET" "/notification/health" "" ""
sleep 2

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

log_with_timestamp ""
log_with_timestamp "🔐 STEP 3: User Login"
log_with_timestamp "====================="

for user in "${users[@]}"; do
    log_with_timestamp "🔑 Logging in user: $user"
    response=$(make_api_call "POST" "/auth/login" "{\"email\":\"$user\",\"password\":\"password123\"}" "")
    token=$(echo "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    tokens+=("$token")
    sleep 1
done

log_with_timestamp ""
log_with_timestamp "✅ STEP 4: Token Verification"  
log_with_timestamp "============================="

for i in "${!tokens[@]}"; do
    if [ -n "${tokens[$i]}" ]; then
        log_with_timestamp "🎫 Verifying token for ${users[$i]}"
        make_api_call "POST" "/auth/verify" "{\"token\":\"${tokens[$i]}\"}" ""
        sleep 1
    fi
done

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
    if [ -n "${tokens[$i]}" ]; then
        for scenario in "${payment_scenarios[@]}"; do
            IFS='|' read -r amount recipient description <<< "$scenario"
            
            log_with_timestamp "💰 Processing payment: $amount to $recipient"
            make_api_call "POST" "/payment/process" \
                "{\"amount\":$amount,\"recipient\":\"$recipient\",\"description\":\"$description\"}" \
                "-H \"Authorization: Bearer ${tokens[$i]}\""
            sleep 2 # Allow time for notification service
        done
        break # Only use first user for payments to avoid too many logs
    fi
done

log_with_timestamp ""
log_with_timestamp "📊 STEP 6: Payment History"
log_with_timestamp "=========================="

if [ -n "${tokens[0]}" ]; then
    log_with_timestamp "📈 Fetching payment history"
    make_api_call "GET" "/payment/history" "" "-H \"Authorization: Bearer ${tokens[0]}\""
fi

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
make_api_call "POST" "/payment/process" "{\"amount\":100,\"recipient\":\"test@test.com\",\"description\":\"Should fail\"}" "-H \"Authorization: Bearer invalid-token\""
sleep 1

log_with_timestamp ""
log_with_timestamp "🔄 STEP 8: Inter-Service Communication"
log_with_timestamp "======================================"

if [ -n "${tokens[0]}" ]; then
    log_with_timestamp "🎯 Testing complete flow: Auth → Payment → Notification"
    make_api_call "POST" "/payment/process" \
        "{\"amount\":999.99,\"recipient\":\"vip@customer.com\",\"description\":\"VIP Transaction - Full Flow Test\"}" \
        "-H \"Authorization: Bearer ${tokens[0]}\""
fi

log_with_timestamp ""
log_with_timestamp "✅ ECOSYSTEM TEST COMPLETED"
log_with_timestamp "============================"
log_with_timestamp "📊 Total API calls made: $(grep -c '🔄 API Call:' "$LOG_FILE")"
log_with_timestamp "📝 Log file saved: $LOG_FILE"
log_with_timestamp ""
log_with_timestamp "🐳 Docker container logs:"
log_with_timestamp "  - docker-compose logs auth-service"
log_with_timestamp "  - docker-compose logs payment-service" 
log_with_timestamp "  - docker-compose logs notification-service"
log_with_timestamp "  - docker-compose logs api-gateway"

echo ""
echo "✅ Sample logs generated successfully!"
echo "📝 Check the log file: $LOG_FILE"
echo ""
echo "🔍 View live service logs:"
echo "  docker-compose logs -f --tail=50"
echo ""
echo "📊 View specific service logs:"
echo "  docker-compose logs -f auth-service"
echo "  docker-compose logs -f payment-service"
echo "  docker-compose logs -f notification-service"
