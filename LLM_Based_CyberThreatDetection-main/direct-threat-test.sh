#!/bin/bash

# Direct Threat Detection Testing Script
# This script sends attack payloads directly to the API and monitors NEWFLOW.py in real-time
# No need to run separate scripts or check logs manually

set -e

API_BASE="http://localhost:8080/api"
COLORS=true

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Helper function to print colored output
print_header() {
    if [ "$COLORS" = true ]; then
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}$1${NC}"
        echo -e "${BLUE}========================================${NC}"
    else
        echo "========================================"
        echo "$1"
        echo "========================================"
    fi
}

print_success() {
    if [ "$COLORS" = true ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo "[✓] $1"
    fi
}

print_attack() {
    if [ "$COLORS" = true ]; then
        echo -e "${RED}🔴 $1${NC}"
    else
        echo "[!] $1"
    fi
}

print_info() {
    if [ "$COLORS" = true ]; then
        echo -e "${CYAN}ℹ️  $1${NC}"
    else
        echo "[i] $1"
    fi
}

# Function to register user
register_user() {
    print_info "Registering test user..."
    curl -s -X POST "$API_BASE/auth/register" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"password123"}' > /dev/null 2>&1
    print_success "User registered"
}

# Function to get token
get_token() {
    print_info "Obtaining authentication token..."
    TOKEN=$(curl -s -X POST "$API_BASE/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"password123"}' | jq -r '.token')
    echo "$TOKEN"
}

# Test benign traffic
test_benign() {
    print_header "Testing BENIGN Traffic (Normal Classification Expected)"
    
    local token=$(get_token)
    
    print_info "Sending normal payment request..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"amount":100,"recipient":"user@example.com","description":"Regular payment"}' | jq . 2>/dev/null || true
    
    sleep 1
    print_success "Normal log sent - check NEWFLOW.py for Normal classification (✓ dot)"
}

# Test SQLi attack
test_sqli() {
    print_header "Testing SQLi Attack (High Priority)"
    
    local token=$(get_token)
    
    print_attack "Sending SQLi payload..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"amount":100,"recipient":"admin'\'' OR '\''1'\''='\''1","description":"Test"}' | jq . 2>/dev/null || true
    
    sleep 1
    print_attack "SQLi attack sent - check NEWFLOW.py for detection"
}

# Test XSS attack
test_xss() {
    print_header "Testing XSS Attack (High Priority)"
    
    local token=$(get_token)
    
    print_attack "Sending XSS payload..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"amount":100,"recipient":"user@example.com","description":"<script>alert(\"XSS\")</script>"}' | jq . 2>/dev/null || true
    
    sleep 1
    print_attack "XSS attack sent - check NEWFLOW.py for detection"
}

# Test command injection
test_cmd_injection() {
    print_header "Testing Command Injection Pattern"
    
    local token=$(get_token)
    
    print_attack "Sending command injection pattern..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"amount":100,"recipient":"user@example.com","description":"; rm -rf /; //"}' | jq . 2>/dev/null || true
    
    sleep 1
    print_attack "Command injection pattern sent"
}

# Test multiple payloads in sequence
test_sequence() {
    print_header "Running Sequential Attack Sequence"
    
    local token=$(get_token)
    
    for i in {1..3}; do
        print_info "Sending benign request #$i..."
        curl -s -X POST "$API_BASE/payment/process" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $token" \
            -d "{\"amount\":$((100 + i*10)),\"recipient\":\"user$i@example.com\",\"description\":\"Payment $i\"}" > /dev/null 2>&1
        sleep 0.5
    done
    
    print_info "Sending SQLi attack..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"amount":500,"recipient":"admin'\'' UNION SELECT * FROM users--","description":"Attack"}' > /dev/null 2>&1
    sleep 0.5
    
    print_info "Sending XSS attack..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d '{"amount":500,"recipient":"user@example.com","description":"<img src=x onerror=alert(1)>"}' > /dev/null 2>&1
    sleep 0.5
    
    print_success "Sequence completed - observe NEWFLOW.py output"
}

# Main menu
show_menu() {
    print_header "Direct Threat Detection Testing"
    echo ""
    echo "1) Run ALL tests (benign + all attacks)"
    echo "2) Test BENIGN traffic only"
    echo "3) Test SQLi attack"
    echo "4) Test XSS attack"
    echo "5) Test command injection"
    echo "6) Run sequential attacks"
    echo "7) Send custom JSON payload"
    echo "8) Exit"
    echo ""
    read -p "Choose option (1-8): " choice
}

# Custom payload sender
send_custom_payload() {
    print_header "Custom Payload Sender"
    
    local token=$(get_token)
    
    echo "Enter your JSON payload (e.g., {\"amount\":100,\"recipient\":\"test@test.com\",\"description\":\"payload\"})"
    read -p "Payload: " payload
    
    print_info "Sending custom payload..."
    curl -s -X POST "$API_BASE/payment/process" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $token" \
        -d "$payload" | jq . 2>/dev/null || true
    
    sleep 1
    print_info "Payload sent - check NEWFLOW.py"
}

# Main execution
main() {
    print_header "🔐 PayPal Clone - Direct Threat Detection"
    
    print_info "Initializing..."
    register_user
    echo ""
    
    while true; do
        show_menu
        case $choice in
            1)
                test_benign
                echo ""
                test_sqli
                echo ""
                test_xss
                echo ""
                ;;
            2)
                test_benign
                echo ""
                ;;
            3)
                test_sqli
                echo ""
                ;;
            4)
                test_xss
                echo ""
                ;;
            5)
                test_cmd_injection
                echo ""
                ;;
            6)
                test_sequence
                echo ""
                ;;
            7)
                send_custom_payload
                echo ""
                ;;
            8)
                print_success "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option"
                echo ""
                ;;
        esac
    done
}

# Run main function
main
