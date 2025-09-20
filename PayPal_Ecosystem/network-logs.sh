#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_help() {
    echo -e "${BLUE}🌐 PayPal Clone - Network Traffic Monitor${NC}"
    echo "======================================"
    echo "Usage: ./network-logs.sh [option]"
    echo ""
    echo "Options:"
    echo "  -a, --api        Monitor API Gateway traffic"
    echo "  -s, --service    Monitor service-to-service communication"
    echo "  -t, --tcp        Show TCP connections between services"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./network-logs.sh --api"
    echo "  ./network-logs.sh --service auth-service"
    echo ""
}

# Check if tcpdump is installed
check_tcpdump() {
    if ! command -v tcpdump &> /dev/null; then
        echo -e "${RED}❌ tcpdump is not installed. Installing...${NC}"
        sudo apt-get update && sudo apt-get install -y tcpdump
    fi
}

# Monitor API Gateway traffic
monitor_api_gateway() {
    echo -e "${GREEN}📊 Monitoring API Gateway traffic (port 8080)...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    sudo tcpdump -i any "port 8080" -A -n
}

# Monitor service-to-service communication
monitor_service() {
    local service=$1
    local port
    case $service in
        "auth-service")
            port=3001
            ;;
        "payment-service")
            port=3002
            ;;
        "notification-service")
            port=3003
            ;;
        *)
            echo -e "${RED}Invalid service. Use: auth-service, payment-service, or notification-service${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}📊 Monitoring $service traffic (port $port)...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    sudo tcpdump -i any "port $port" -A -n
}

# Show TCP connections
show_tcp_connections() {
    echo -e "${GREEN}📊 Active TCP connections between services:${NC}"
    echo "-------------------------------------------"
    # Get container network stats
    echo -e "${YELLOW}Container Network Statistics:${NC}"
    docker stats --no-stream --format "table {{.Name}}\t{{.NetIO}}"
    
    echo -e "\n${YELLOW}TCP Connections:${NC}"
    sudo netstat -plant | grep -E '3001|3002|3003|8080'
    
    echo -e "\n${YELLOW}Container Network Details:${NC}"
    docker network inspect paypal-network
}

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run with sudo for network monitoring capabilities${NC}"
    exit 1
fi

# Parse command line arguments
case "${1:-}" in
    -a|--api)
        check_tcpdump
        monitor_api_gateway
        ;;
    -s|--service)
        if [ -z "$2" ]; then
            echo -e "${RED}Please specify a service to monitor${NC}"
            show_help
            exit 1
        fi
        check_tcpdump
        monitor_service "$2"
        ;;
    -t|--tcp)
        show_tcp_connections
        ;;
    -h|--help|*)
        show_help
        exit 0
        ;;
esac
