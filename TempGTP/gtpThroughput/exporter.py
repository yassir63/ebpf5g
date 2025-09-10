import socket
import os
import threading
import time
import json
import argparse
from prometheus_client import start_http_server, Gauge
import re

# Argument parsing
parser = argparse.ArgumentParser(description='GTP Throughput Prometheus Exporter')
parser.add_argument('--port', type=int, default=9200, help='Port to expose metrics on')
parser.add_argument('--metrics-path', type=str, default='/metrics', help='Path to expose metrics on')
args = parser.parse_args()

SOCKET_PATH = "/tmp/gtp_throughput.sock"
teid_data = {}

# Prometheus metrics
packets_gauge = Gauge("gtp_throughput_packets_total", "Total packets per TEID", ["teid", "slice"])
bytes_gauge = Gauge("gtp_throughput_bytes_total", "Total bytes per TEID", ["teid", "slice"])
bitrate_gauge = Gauge("gtp_throughput_bitrate_bps", "Bitrate in bits per second per TEID", ["teid", "slice"])

def handle_client(conn):
    with conn:
        buffer = ""
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                buffer += data.decode("utf-8")
            except UnicodeDecodeError as e:
                print(f"[!] Decode error: {e}")
                continue

            # Split on boundaries between adjacent JSON objects
            json_objects = re.findall(r'\{.*?\}', buffer)
            for obj in json_objects:
                parse_message(obj)
            
            # Leave buffer as is if partial object at the end
            last_closing = buffer.rfind('}')
            if last_closing != -1:
                buffer = buffer[last_closing+1:]


def parse_message(msg):
    try:
        parsed = json.loads(msg)
        teid = f"0x{parsed['teid']:08x}"
        slice_id = str(parsed.get("slice", 0))

        teid_data[(teid, slice_id)] = {
            "packets": parsed["packets"],
            "bytes": parsed["bytes"],
            "bitrate": parsed["bitrate"]
        }
    except Exception as e:
        print(f"[!] Failed to parse JSON: {msg} | Error: {e}")

def socket_server():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)
    print(f"[+] Socket server listening at {SOCKET_PATH}")

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

def update_metrics():
    while True:
        for (teid, slice_id), stats in teid_data.items():
            packets_gauge.labels(teid=teid, slice=slice_id).set(stats["packets"])
            bytes_gauge.labels(teid=teid, slice=slice_id).set(stats["bytes"])
            bitrate_gauge.labels(teid=teid, slice=slice_id).set(stats["bitrate"])
        time.sleep(1)

if __name__ == "__main__":
    start_http_server(args.port, addr='0.0.0.0')
    print(f"[+] Prometheus exporter running at http://localhost:{args.port}{args.metrics_path}")

    threading.Thread(target=socket_server, daemon=True).start()
    update_metrics()