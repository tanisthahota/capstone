#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Auto-discover the network interface ---
PAYPAL_NETWORK_NAME=$(docker network ls --filter "name=paypal" --format "{{.Name}}")
NETWORK_ID=$(docker network inspect $PAYPAL_NETWORK_NAME -f "{{.Id}}")
BRIDGE_IF="br-${NETWORK_ID:0:12}"

if [ -z "$PAYPAL_NETWORK_NAME" ] || [ -z "$BRIDGE_IF" ]; then
    echo -e "${RED}Error: Could not find the 'paypal' docker network. Is it running?${NC}"
    exit 1
fi
echo -e "${BLUE}Found PayPal network '$PAYPAL_NETWORK_NAME' on interface '$BRIDGE_IF'${NC}"
echo "======================================"
# ------------------------------------------

show_help() {
    echo -e "${BLUE}🌐 PayPal Clone - Network Traffic Monitor${NC}"
    echo "======================================"
    echo "Usage: ./network-logs.sh [option]"
    echo ""
    echo "Options:"
    echo "  -a, --api        Monitor API Gateway traffic (port 8080)"
    echo "  -s, --service    Monitor a specific service"
    echo "  -t, --tcp        Show active TCP connections for the app"
    echo "  -c, --capture    Capture traffic to a .pcap file (e.g., traffic.pcap)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo ./network-logs.sh --api"
    echo "  sudo ./network-logs.sh --service auth-service"
    echo "  sudo ./network-logs.sh --capture my_capture.pcap"
    echo ""
}

# Check if tcpdump is installed
check_tcpdump() {
    if ! command -v tcpdump &> /dev/null; then
        echo -e "${RED}❌ tcpdump is not installed. Installing...${NC}"
        # --- FIX: Use dnf for Fedora ---
        sudo dnf install -y tcpdump
    fi
}

# Monitor API Gateway traffic
monitor_api_gateway() {
    echo -e "${GREEN}📊 Monitoring API Gateway traffic (port 8080) on $BRIDGE_IF...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    # --- FIX: Listen on the correct bridge ---
    sudo tcpdump -i $BRIDGE_IF "port 8080" -A -n
}

# Capture traffic to a pcap file
capture_to_pcap() {
    local filename=$1
    echo -e "${GREEN}📦 Capturing traffic on $BRIDGE_IF to $filename...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop capturing${NC}"
    # --- FIX: Removed the conflicting > .txt redirect ---
    sudo tcpdump -i $BRIDGE_IF -w "$filename"
    echo -e "${GREEN}✅ Capture saved to $filename${NC}"
    echo "To convert to a .txt file, run:"
    echo -e "${YELLOW}tcpdump -n -r $filename > ${filename%.*}.txt${NC}"
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
    echo -e "${GREEN}📊 Monitoring $service traffic (port $port) on $BRIDGE_IF...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    # --- FIX: Listen on the correct bridge ---
    sudo tcpdump -i $BRIDGE_IF "port $port" -A -n
}

# Show TCP connections
show_tcp_connections() {
    echo -e "${GREEN}📊 Active TCP connections for the app:${NC}"
    echo "-------------------------------------------"
    echo -e "${YELLOW}Container Network Statistics:${NC}"
    docker stats --no-stream --filter "name=paypal" --format "table {{.Name}}\t{{.NetIO}}"
    
    echo -e "\n${YELLOW}TCP Connections (using ss):${NC}"
    # --- FIX: Use ss (modern netstat) and filter for your app's ports ---
    sudo ss -plant | grep -E '3001|3002|3003|8080'
    
    echo -e "\n${YELLOW}Container Network Details:${NC}"
    # --- FIX: Use the auto-discovered network name ---
    docker network inspect $PAYPAL_NETWORK_NAME
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
    -c|--capture)
        if [ -z "$2" ]; then
            echo -e "${RED}Please specify a filename for the capture (e.g., traffic.pcap)${NC}"
            show_help
            exit 1
        fi
        check_tcpdump
        capture_to_pcap "$2"
        ;;
    -t|--tcp)
        show_tcp_connections
        ;;
    -h|--help|*)
        show_help
        exit 0
        ;;
esac