#!/bin/bash

echo "📊 PayPal Clone - Live Log Monitor"
echo "=================================="
echo "Press Ctrl+C to stop monitoring"
echo ""

# Function to colorize logs
colorize_logs() {
    while IFS= read -r line; do
        case "$line" in
            *"[AUTH-SERVICE]"*)
                echo -e "\033[36m$line\033[0m"  # Cyan
                ;;
            *"[PAYMENT-SERVICE]"*)
                echo -e "\033[32m$line\033[0m"  # Green
                ;;
            *"[NOTIFICATION-SERVICE]"*)
                echo -e "\033[35m$line\033[0m"  # Magenta
                ;;
            *"api-gateway"*)
                echo -e "\033[33m$line\033[0m"  # Yellow
                ;;
            *"ERROR"*|*"error"*|*"Error"*)
                echo -e "\033[31m$line\033[0m"  # Red
                ;;
            *)
                echo "$line"
                ;;
        esac
    done
}

docker-compose logs -f --tail=20 | colorize_logs
