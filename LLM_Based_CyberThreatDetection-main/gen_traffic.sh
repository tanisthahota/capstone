#!/bin/bash
# generate_traffic.sh
# Generates varied, concurrent, and realistic benign traffic for the PayPal clone.

# --- Configuration ---
API_BASE="http://localhost:8080/api"
LOG_FILE="logs/benign-traffic-$(date +%Y%m%d-%H%M%S).log"
NUM_USERS=11 # <-- Increase this number to generate more traffic

mkdir -p logs

# --- Data Pools for Randomization ---
RECIPIENTS=("amazon.com" "starbucks" "local_diner" "bookstore.com" "gas_station" "online_course_provider")
DESCRIPTIONS=("Electronics purchase" "Morning coffee" "Dinner with friends" "New novel" "Fuel" "Web dev course")
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
    "MyAwesomeApp/2.1.0 (iPhone; iOS 16.1; Scale/3.00)"
    "curl/8.9.1"
)

# --- Helper Functions (Reused from your original script) ---
log_with_timestamp() {
    # The >&2 redirects the echo output to standard error to not pollute function returns
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2 | tee -a "$LOG_FILE"
}

make_api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local header=$4
    local user_agent=$5

    local url="$API_BASE$endpoint"
    local curl_opts=(-s -X "$method")
    curl_opts+=(-H "Content-Type: application/json")
    curl_opts+=(-A "$user_agent") # Use the provided user agent

    if [ -n "$header" ]; then
        curl_opts+=(-H "$header")
    fi
    if [ -n "$data" ]; then
        curl_opts+=(-d "$data")
    fi

    response=$(curl "${curl_opts[@]}" "$url")
    echo "$response"
}

extract_json_value() {
    echo "$1" | jq -r ".${2}"
}

# --- Core Simulation Logic ---
simulate_user_session() {
    local user_id=$1
    local email="user${user_id}-$(date +%s%N)@paypal.com" # Unique email every time
    local password="password123"

    log_with_timestamp "[User $user_id] 🚀 Starting session for $email"

    # 1. Register
    make_api_call "POST" "/auth/register" "{\"email\":\"$email\",\"password\":\"$password\"}" "" "RegistrationBot/1.0"
    sleep 1

    # 2. Login
    local login_response
    login_response=$(make_api_call "POST" "/auth/login" "{\"email\":\"$email\",\"password\":\"$password\"}" "" "LoginBot/1.0")
    local token
    token=$(extract_json_value "$login_response" "token")

    if [ -z "$token" ] || [ "$token" == "null" ]; then
        log_with_timestamp "[User $user_id] ❌ Login failed for $email. Ending session."
        return
    fi
    log_with_timestamp "[User $user_id] ✅ Login successful for $email."

    # 3. Perform a random number of actions
    local num_actions=$((RANDOM % 5 + 2)) # User will perform 2 to 6 actions
    log_with_timestamp "[User $user_id] 🎲 Will perform $num_actions actions."

    for ((i=1; i<=num_actions; i++)); do
        local action=$((RANDOM % 10)) # 80% chance of payment, 20% chance of checking history
        local random_agent=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}

        if [ $action -lt 8 ]; then
            # Make a payment
            local amount="$(shuf -i 5-500 -n 1).$(shuf -i 10-99 -n 1)"
            local recipient=${RECIPIENTS[$RANDOM % ${#RECIPIENTS[@]}]}
            local description=${DESCRIPTIONS[$RANDOM % ${#DESCRIPTIONS[@]}]}
            local json_payload
            json_payload=$(printf '{"amount":%s,"recipient":"%s","description":"%s"}' "$amount" "$recipient" "$description")
            log_with_timestamp "[User $user_id] 💳 Action $i: Making payment of $amount to $recipient."
            make_api_call "POST" "/payment/process" "$json_payload" "Authorization: Bearer $token" "$random_agent"
        else
            # Check history
            log_with_timestamp "[User $user_id] 📊 Action $i: Checking payment history."
            make_api_call "GET" "/payment/history" "" "Authorization: Bearer $token" "$random_agent"
        fi

        # Sleep for a random, short interval
        sleep 0.$((RANDOM % 800 + 100))
    done

    log_with_timestamp "[User $user_id] 👋 Session ended for $email."
}

# --- Main Execution ---
log_with_timestamp "🚀 Starting Benign Traffic Generation Suite"
log_with_timestamp "=============================================="
log_with_timestamp "👥 Simulating $NUM_USERS concurrent users..."

# Launch all user sessions in the background
for i in $(seq 1 $NUM_USERS); do
    simulate_user_session "$i" &
    sleep 0.2 # Stagger the start of each user slightly
done

log_with_timestamp "⏳ All user sessions launched. Waiting for them to complete..."
wait # This is crucial: waits for all background jobs to finish
log_with_timestamp "✅ All user sessions have completed."
log_with_timestamp "=============================================="
log_with_timestamp "📝 Benign traffic generation complete. Log file saved to: $LOG_FILE"