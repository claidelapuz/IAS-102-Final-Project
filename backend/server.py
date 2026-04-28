from flask import Flask, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading, time, psutil, os
from scanner import scan_host, save_report

app = Flask(__name__, static_folder="../frontend")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

scan_state    = {"running": False}
traffic_state = {"running": False}

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

# --- Traffic loop: reads real network speed every second ---
def traffic_loop():
    prev = psutil.net_io_counters()
    while traffic_state["running"]:
        time.sleep(1)
        curr = psutil.net_io_counters()
        dl = round((curr.bytes_recv - prev.bytes_recv) * 8 / 1024, 2)
        ul = round((curr.bytes_sent - prev.bytes_sent) * 8 / 1024, 2)
        socketio.emit("traffic_update", {"dl": dl, "ul": ul})
        prev = curr

@socketio.on("connect")
def on_connect():
    if not traffic_state["running"]:
        traffic_state["running"] = True
        threading.Thread(target=traffic_loop, daemon=True).start()

@socketio.on("start_scan")
def handle_start_scan(data):
    if scan_state["running"]:
        return
    host  = data.get("host", "127.0.0.1")
    ps    = int(data.get("port_start", 1))
    pe    = int(data.get("port_end", 1024))
    scan_state["running"] = True
    emit("scan_started", {"host": host})

    def run():
        def cb(r):
            if scan_state["running"]:
                socketio.emit("port_found", r)
        ports = scan_host(host, (ps, pe), callback=cb)
        save_report(host, ports)
        scan_state["running"] = False
        socketio.emit("scan_complete", {
            "total": len(ports), "ports": ports
        })

    threading.Thread(target=run, daemon=True).start()

@socketio.on("stop_scan")
def handle_stop_scan():
    scan_state["running"] = False
    emit("scan_stopped", {})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)