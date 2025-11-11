#!/bin/bash

show_help() {
    echo "📊 PayPal Clone - Log Monitor"
    echo "============================="
    echo "Usage: ./monitor-logs.sh [option]"
    echo ""
    echo "Options:"
    echo "  -a, --app      Show application logs (default)"
    echo "  -s, --system   Show system-level container logs"
    echo "  -d, --docker   Show Docker events"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "Press Ctrl+C to stop monitoring"
    echo ""
}

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

# Parse command line arguments
option="${1:-app}"  # Default to app logs if no option provided

case "$option" in
    -a|--app)
        echo "📋 Showing application logs..."
        docker compose logs -f --tail=20 | colorize_logs
        ;;
    -s|--system)
        echo "🔧 Showing system-level container logs..."
        echo "Container Stats:"
        docker stats --no-stream
        echo -e "\nContainer Details:"
        docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo -e "\nDetailed Logs:"
        docker compose ps -a
        docker compose top
        ;;
    -d|--docker)
        echo "🐳 Showing Docker events..."
        docker events --filter 'type=container' --format 'Type={{.Type}} Status={{.Status}} ID={{.ID}} Image={{.From}}'
        ;;
    -h|--help)
        show_help
        exit 0
        ;;
    *)
        show_help
        exit 1
        ;;
esac
