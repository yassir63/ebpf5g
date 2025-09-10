#!/bin/bash
set -e

# Load from environment with default fallback
IFACE="${IFACE:-n2}"
HANDLE="${HANDLE:-1}"
PRIO="${PRIO:-1}"
EXPORTER_PORT="${EXPORTER_PORT:-8000}"
EXPORTER_PATH="${EXPORTER_PATH:-/metrics}"
TEIDS="${TEIDS:-}"

if [[ -z "$TEIDS" ]]; then
    echo "Error: TEIDS not provided. Set the TEIDS env variable (e.g., '0x100@1 0x200')."
    exit 1
fi

echo "Launching eBPF Latency Probe:"
echo "  Interface      = $IFACE"
echo "  Handle         = $HANDLE"
echo "  Priority       = $PRIO"
echo "  TEIDs          = $TEIDS"
echo "  Exporter Port  = $EXPORTER_PORT"
echo "  Metrics Path   = $EXPORTER_PATH"


BPF_PID=""
EXPORTER_PID=""

cleanup() {
  echo "🧼 Cleaning up probe filter on $IFACE (prio=$PRIO)"
  tc filter del dev "$IFACE" ingress prio "$PRIO" 2>/dev/null || true
  tc filter del dev "$IFACE" egress prio "$PRIO" 2>/dev/null || true


  # Kill the eBPF program if it's running
    if [ ! -z "$BPF_PID" ]; then
        echo "Stopping eBPF program..."
        kill $BPF_PID 2>/dev/null || true
    fi
    
    # Kill the exporter if it's running
    if [ ! -z "$EXPORTER_PID" ]; then
        echo "Stopping exporter..."
        kill $EXPORTER_PID 2>/dev/null || true
    fi
  
  echo "🧽 Removing pinned eBPF maps..."
  rm -rf /sys/fs/bpf/tc/globals/gtp_latency* 2>/dev/null || true

     # Clean up Unix socket
    echo "Cleaning up Unix socket..."
    rm -f /tmp/gtp_latency.sock 2>/dev/null || true

  make clean

  echo "✅ Cleanup complete."
}

trap cleanup EXIT
trap cleanup SIGINT
trap cleanup SIGTERM


# Export to Makefile
export IFACE HANDLE PRIO TEIDS

make clean && make
make run

./gtp_latency_user "$IFACE" \
  --handle "$HANDLE" \
  --prio "$PRIO" \
  $TEIDS &
BPF_PID=$!

# Start exporter (assumes Python-based Prometheus exporter)
python3 exporter.py --port "$EXPORTER_PORT" --metrics-path "$EXPORTER_PATH" &
EXPORTER_PID=$!

wait


# set -e

# # Default values
# IFACE="n2"
# HANDLE="1"
# PRIO="1"
# EXPORTER_PORT="9100"
# EXPORTER_PATH="/metrics"
# TEIDS=()

# # Print usage
# print_usage() {
#     echo "Usage: $0 [options] [TEID1[@slice] [TEID2[@slice] ...]]"
#     echo "Options:"
#     echo "  -i, --iface INTERFACE    Network interface (default: n2)"
#     echo "  -h, --handle HANDLE      TC handle (default: 1)"
#     echo "  -p, --prio PRIORITY      TC priority (default: 1)"
#     echo "  -P, --port PORT          Exporter port (default: 8000)"
#     echo "  -m, --metrics-path PATH  Exporter metrics path (default: /metrics)"
#     echo "  --help                   Show this help message"
#     exit 1
# }

# # Parse command line arguments
# while [[ $# -gt 0 ]]; do
#     case $1 in
#         -i|--iface)
#             IFACE="$2"
#             shift 2
#             ;;
#         -h|--handle)
#             HANDLE="$2"
#             shift 2
#             ;;
#         -p|--prio)
#             PRIO="$2"
#             shift 2
#             ;;
#         -P|--port)
#             EXPORTER_PORT="$2"
#             shift 2
#             ;;
#         -m|--metrics-path)
#             EXPORTER_PATH="$2"
#             shift 2
#             ;;
#         --help)
#             print_usage
#             ;;
#         -*)
#             echo "Unknown option: $1"
#             print_usage
#             ;;
#         *)
#             TEIDS+=("$1")
#             shift
#             ;;
#     esac
# done

# # Check if TEIDs are provided
# if [ ${#TEIDS[@]} -eq 0 ]; then
#     echo "Error: No TEIDs provided"
#     print_usage
# fi

# echo "Running eBPF Latency Probe with:"
# echo "  Interface: $IFACE"
# echo "  Handle: $HANDLE"
# echo "  Priority: $PRIO"
# echo "  Exporter Port: $EXPORTER_PORT"
# echo "  Exporter Path: $EXPORTER_PATH"
# echo "  TEIDs: ${TEIDS[@]}"

# # Build and run the eBPF program
# make clean && make
# exec $(which make) run IFACE="$IFACE" --handle "$HANDLE" --prio "$PRIO" TEIDS="${TEIDS[@]}" &

# # Start the exporter
# python3 exporter.py --port "$EXPORTER_PORT" --metrics-path "$EXPORTER_PATH" 


