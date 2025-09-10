from flask import Flask, Response
from prometheus_client import Gauge, generate_latest
import threading
import json
import socket
import os
import argparse

SOCKET_PATH = "/tmp/gtp_latency.sock"
latency_cache = {}

# Parse command line arguments
parser = argparse.ArgumentParser(description='GTP Latency Exporter')
parser.add_argument('--port', type=int, default=8000, help='Port to expose metrics on')
parser.add_argument('--metrics-path', type=str, default='/metrics', help='Path to expose metrics on')
args = parser.parse_args()

app = Flask(__name__)
latency_ns = Gauge("gtp_teid_latency_ns", "Last-seen GTP latency (ns)", ["teid", "slice"])

def listen_on_socket():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.bind(SOCKET_PATH)
    except OSError:
        os.remove(SOCKET_PATH)
        sock.bind(SOCKET_PATH)
    print(f"[exporter] Listening on {SOCKET_PATH}")
    while True:
        data, _ = sock.recvfrom(1024)
        try:
            evt = json.loads(data.decode("utf-8"))
            teid = evt["teid"]
            latency_cache[teid] = {
                "latency_ns": evt["latency_ns"],
                "slice": str(evt.get("slice", "0"))
            }
        except Exception as e:
            print("bad payload:", e)

@app.route("/" + args.metrics_path.lstrip("/"))
def metrics():
    for teid, entry in latency_cache.items():
        latency_ns.labels(teid=teid, slice=entry["slice"]).set(entry["latency_ns"])
    return Response(generate_latest(), mimetype="text/plain")

if __name__ == "__main__":
    threading.Thread(target=listen_on_socket, daemon=True).start()
    print(f"Deploying Latency Exporter on port {args.port} serving at {args.metrics_path}")

    app.run(host="0.0.0.0", port=args.port)