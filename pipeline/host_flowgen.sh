#!/usr/bin/env bash
set -euo pipefail

# host_flowgen.sh
# Usage:
#   ./host_flowgen.sh                 # uses defaults (container=python-scripts, latest pcap)
#   ./host_flowgen.sh --container my-cntr --trigger
#   ./host_flowgen.sh --jar /path/to/CICFlowMeter-3.0.jar
#   ./host_flowgen.sh --pcap seg_0_20251116_071256.pcap
#
# Notes:
# - Requires `docker` CLI and cicflowmeter CLI (python package) OR a Java CICFlowMeter jar.
# - Defaults assume your container stores pcaps in /app/pcaps and expects CSVs in /app/flow_csvs.
# - If using the Java jar, pass --jar /path/to/CICFlowMeter-3.0.jar
# - Use --trigger to restart network_stream.py in the container after copying CSVs.

CNTR="python-scripts"
PCAP_DIR_CONTAINER="/app/pcaps"
FLOW_DIR_CONTAINER="/app/flow_csvs"

PCAPS_HOST_DIR="./pcaps_host"
FLOWS_HOST_DIR="./flows_host"

# Default behaviour: use cicflowmeter (python package). If JAR is provided, use Java mode.
CICFLOW_JAR=""
TRIGGER_NETWORK_STREAM=false
SPECIFIC_PCAP=""

# parse args (simple)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) CNTR="$2"; shift 2;;
    --pcap) SPECIFIC_PCAP="$2"; shift 2;;
    --jar) CICFLOW_JAR="$2"; shift 2;;
    --trigger) TRIGGER_NETWORK_STREAM=true; shift;;
    --help|-h) echo "Usage: $0 [--container name] [--pcap filename] [--jar /path/to/jar] [--trigger]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 2;;
  esac
done

mkdir -p "$PCAPS_HOST_DIR" "$FLOWS_HOST_DIR"

echo "Container: $CNTR"
echo "Container PCAP dir: $PCAP_DIR_CONTAINER"
echo "Container FLOW dir: $FLOW_DIR_CONTAINER"
echo "Local PCAP dir: $PCAPS_HOST_DIR"
echo "Local FLOW dir: $FLOWS_HOST_DIR"
if [[ -n "$SPECIFIC_PCAP" ]]; then
  echo "Requested specific pcap: $SPECIFIC_PCAP"
fi
if [[ -n "$CICFLOW_JAR" ]]; then
  echo "Using Java CICFlowMeter JAR: $CICFLOW_JAR"
else
  echo "Using host cicflowmeter (python CLI)."
fi
echo

# 1) find PCAP to copy (either SPECIFIC_PCAP or latest in container)
if [[ -n "$SPECIFIC_PCAP" ]]; then
  PCAP_BASENAME="$SPECIFIC_PCAP"
else
  echo "Finding latest pcap inside container..."
  LATEST=$(docker exec "$CNTR" sh -c "ls -1t $PCAP_DIR_CONTAINER/*.pcap 2>/dev/null | head -n1 || true")
  if [[ -z "$LATEST" ]]; then
    echo "No pcap files found in container at $PCAP_DIR_CONTAINER"
    exit 3
  fi
  PCAP_BASENAME=$(basename "$LATEST")
fi

echo "Selected pcap: $PCAP_BASENAME"

# 2) copy that pcap to host
echo "Copying $PCAP_BASENAME from container to host..."
docker cp "${CNTR}:${PCAP_DIR_CONTAINER}/${PCAP_BASENAME}" "${PCAPS_HOST_DIR}/${PCAP_BASENAME}"
echo "Copied to ${PCAPS_HOST_DIR}/${PCAP_BASENAME}"
ls -lh "${PCAPS_HOST_DIR}/${PCAP_BASENAME}"
echo

# 3) run cicflowmeter on host (either python CLI or Java jar)
if [[ -n "$CICFLOW_JAR" ]]; then
  echo "Running Java CICFlowMeter (jar) on host..."
  if ! command -v java >/dev/null 2>&1; then
    echo "ERROR: java not found on host. Install a JRE/JDK or use python cicflowmeter."
    exit 4
  fi
  # run jar on the single pcap file into FLOWS_HOST_DIR
  java -jar "$CICFLOW_JAR" -f "${PCAPS_HOST_DIR}/${PCAP_BASENAME}" -w "$FLOWS_HOST_DIR" || {
    echo "Java CICFlowMeter failed (exit $?)"
    exit 5
  }
else
  echo "Running python cicflowmeter on host..."
  if ! command -v cicflowmeter >/dev/null 2>&1; then
    echo "ERROR: cicflowmeter CLI (python package) not found. Install via 'pip install cicflowmeter' or use --jar option."
    exit 4
  fi
  # run in place for the single file
  OUT_CSV="${FLOWS_HOST_DIR}/${PCAP_BASENAME%.pcap}_flows.csv"

  echo "Using command:"
  echo "cicflowmeter -f ${PCAPS_HOST_DIR}/${PCAP_BASENAME} -c ${OUT_CSV}"

  # Run cicflowmeter (new CLI)
  if cicflowmeter -f "${PCAPS_HOST_DIR}/${PCAP_BASENAME}" -c "${OUT_CSV}"; then
    echo "cicflowmeter succeeded → produced ${OUT_CSV}"
  else
    echo "❌ cicflowmeter failed (exit $?)"
    exit 5
  fi
fi

echo "Listing generated CSVs in $FLOWS_HOST_DIR"
ls -la "$FLOWS_HOST_DIR" | sed -n '1,50p'
echo

# 4) copy CSV(s) back into container
echo "Copying CSV(s) back into container $CNTR:$FLOW_DIR_CONTAINER ..."
docker cp "${FLOWS_HOST_DIR}/." "${CNTR}:${FLOW_DIR_CONTAINER}/"
echo "Copied. Contents in container:"
docker exec "$CNTR" sh -c "ls -la ${FLOW_DIR_CONTAINER} | sed -n '1,50p'"

# 5) (optional) trigger network_stream.py restart inside the container
if $TRIGGER_NETWORK_STREAM; then
  echo "Triggering network_stream.py restart inside container (will try to pkill and restart in background)..."
  # try to kill existing, then start detached
  docker exec "$CNTR" sh -c "pkill -f network_stream.py || true"
  # start in background (no -it)
  docker exec -d "$CNTR" sh -c "python /workspace/pipeline/network_stream.py >/tmp/network_stream.log 2>&1 || true"
  echo "network_stream.py restarted (detached). Inspect logs with: docker exec -it $CNTR tail -n 200 /tmp/network_stream.log"
fi

echo
echo "DONE. CSVs are available in $FLOW_DIR_HOST and copied to container $CNTR:$FLOW_DIR_CONTAINER."
