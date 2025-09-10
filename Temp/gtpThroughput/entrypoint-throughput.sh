#!/bin/bash
set -e

# Default values
: "${IFACE:=n2}"
: "${INGRESS_HANDLE:=1}"
: "${EGRESS_HANDLE:=2}"
: "${PRIO:=1}"
: "${PORT:=9200}"
: "${METRICS_PATH:=/metrics}"

# Extract TEIDs from env or arguments
if [ -z "$TEIDS" ] && [[ $# -gt 0 ]]; then
    TEIDS="$*"
fi

# Validate interface
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "❌ Error: Interface '$IFACE' does not exist"
    exit 1
fi

# Validate TEIDs
if [ -z "$TEIDS" ]; then
    echo "❌ Error: No TEIDs provided (via env or arguments)"
    exit 1
fi

# Show configuration
echo "🚀 Starting eBPF Throughput Probe with:"
echo "  Interface      : $IFACE"
echo "  Ingress Handle : $INGRESS_HANDLE"
echo "  Egress Handle  : $EGRESS_HANDLE"
echo "  Priority       : $PRIO"
echo "  Port           : $PORT"
echo "  Metrics Path   : $METRICS_PATH"
echo "  TEIDs          : $TEIDS"

# Cleanup logic
cleanup() {
  echo "🧼 Cleaning up tc filters for $IFACE (prio=$PRIO)"
  tc filter del dev "$IFACE" ingress prio "$PRIO" 2>/dev/null || true
  tc filter del dev "$IFACE" egress prio "$PRIO" 2>/dev/null || true

  echo "🧽 Removing pinned eBPF maps..."
  rm -rf /sys/fs/bpf/tc/globals/gtp_throughput* 2>/dev/null || true

  make clean
  echo "🗑️ Removing socket file..."

  rm -f /tmp/gtp_throughput.sock 2>/dev/null || true

  echo "✅ Cleanup complete."
}

trap cleanup EXIT
trap cleanup SIGINT
trap cleanup SIGTERM

# Build the BPF program
make clean && make

# Run user-space binary via Makefile with env parameters
# make run \
#   IFACE="$IFACE" \
#   INGRESS_HANDLE="$INGRESS_HANDLE" \
#   EGRESS_HANDLE="$EGRESS_HANDLE" \
#   PRIO="$PRIO" \
#   TEIDS="$TEIDS" &

make run

./gtp_throughput_user "$IFACE" \
  --ingress-handle "$INGRESS_HANDLE" \
  --egress-handle "$EGRESS_HANDLE" \
  --priority "$PRIO" \
  $TEIDS &
BPF_PID=$!

# Start Prometheus exporter
python3 exporter.py --port "$PORT" --metrics-path "$METRICS_PATH" &
EXPORTER_PID=$!

wait






# #!/bin/bash
# set -e

# # Default values
# IFACE="n2"
# HANDLE=1
# PRIO=1
# PORT=9200
# METRICS_PATH="/metrics"

# # Print usage
# print_usage() {
#     echo "Usage: $0 [options] [TEID1[:TEID2[@slice]]] [TEID3[:TEID4[@slice]]] ..."
#     echo "Options:"
#     echo "  -i, --interface <iface>    Network interface to monitor (default: n2)"
#     echo "  -h, --handle <handle>      TC handle for BPF program (default: 1)"
#     echo "  -p, --priority <priority>  TC priority (default: 1)"
#     echo "  --port <port>              Port for Prometheus exporter (default: 9200)"
#     echo "  --metrics-path <path>      Path for Prometheus metrics (default: /metrics)"
#     echo "  --help                     Show this help message"
#     echo ""
#     echo "TEID format:"
#     echo "  Single TEID: 0x12345678"
#     echo "  TEID pair: 0x12345678:0x87654321"
#     echo "  With slice: 0x12345678@1 or 0x12345678:0x87654321@1"
#     echo ""
#     echo "Example:"
#     echo "  $0 -i n3 -h 2 -p 2 --port 8080 --metrics-path /custom-metrics 0x12345678:0x87654321@1 0x11111111:0x22222222@2"
# }

# # Parse arguments
# while [[ $# -gt 0 ]]; do
#     case $1 in
#         -i|--interface)
#             IFACE="$2"
#             shift 2
#             ;;
#         -h|--handle)
#             HANDLE="$2"
#             shift 2
#             ;;
#         -p|--priority)
#             PRIO="$2"
#             shift 2
#             ;;
#         --port)
#             PORT="$2"
#             shift 2
#             ;;
#         --metrics-path)
#             METRICS_PATH="$2"
#             shift 2
#             ;;
#         --help)
#             print_usage
#             exit 0
#             ;;
#         -*)
#             echo "Unknown option: $1"
#             print_usage
#             exit 1
#             ;;
#         *)
#             # Remaining arguments are TEIDs
#             break
#             ;;
#     esac
# done

# # Check if interface exists
# if ! ip link show "$IFACE" >/dev/null 2>&1; then
#     echo "Error: Interface '$IFACE' does not exist"
#     exit 1
# fi

# echo "Running eBPF Latency Probe with:"
# echo "  Interface: $IFACE"
# echo "  Handle: $HANDLE"
# echo "  Priority: $PRIO"
# echo "  Port: $PORT"
# echo "  Metrics Path: $METRICS_PATH"
# echo "  TEIDs: $@"


# cleanup() {
#   echo "🧼 Cleaning up probe filter on $IFACE (prio=$PRIO)"
#   tc filter del dev "$IFACE" ingress prio "$PRIO" 2>/dev/null || true
  
#   echo "🧽 Removing pinned eBPF maps..."
#   rm -rf /sys/fs/bpf/tc/globals/gtp_throughput* 2>/dev/null || true

#   echo "✅ Cleanup complete."
# }

# trap cleanup EXIT
# trap cleanup SIGINT
# trap cleanup SIGTERM


# # Build and run the BPF program
# make clean && make
# exec $(which make) run IFACE="$IFACE" --handle "$HANDLE" --prio "$PRIO" TEIDS="$@" &

# # Start the Prometheus exporter
# python3 exporter.py --port "$PORT" --metrics-path "$METRICS_PATH"