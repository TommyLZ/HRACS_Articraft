#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-101.52.241.92}"
PORT="${2:-19203}"
TRIALS="${3:-10}"
INTERFACE="${4:-ens33}"

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
RESULT="$ROOT/Result"
STAMP="$(date +%Y%m%d_%H%M%S)"
DATE="$(date +%Y%m%d)"
PCAP="$RESULT/${STAMP}_APAKE_Communication.pcap"
RAW="$RESULT/${DATE}_APAKE_Communication_raw.csv"
WIRE_RAW="$RESULT/${STAMP}_APAKE_Communication_wire_raw.csv"
SUMMARY="$RESULT/${STAMP}_APAKE_Communication_wire_summary.csv"

mkdir -p "$RESULT"
if [[ ! -x "$BUILD/apake_comm_client" || ! -x "$BUILD/apake_pcap_analyzer" ]]; then
    echo "Build first: cmake -S '$ROOT' -B '$BUILD' && cmake --build '$BUILD' -j2" >&2
    exit 1
fi

echo "Packet capture requires sudo once."
sudo -v
TCPDUMP_PID=""
cleanup() {
    if [[ -n "$TCPDUMP_PID" ]] && sudo kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        sudo kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

sudo tcpdump -i "$INTERFACE" -s 0 -U -n \
    -w "$PCAP" "host $HOST and tcp port $PORT" &
TCPDUMP_PID=$!
sleep 2

(cd "$BUILD" && ./apake_comm_client "$HOST" "$PORT" "$TRIALS")
sleep 2
cleanup
TCPDUMP_PID=""
sudo chmod 0644 "$PCAP"

"$BUILD/apake_pcap_analyzer" "$PCAP" "$RAW" "$WIRE_RAW" "$SUMMARY" "$PORT"
echo "PCAP: $PCAP"
echo "Per-trial CSV: $WIRE_RAW"
echo "Mean/stddev CSV: $SUMMARY"
