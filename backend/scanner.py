import socket
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Alt"
}

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return {
                "port": port,
                "state": "open",
                "service": SERVICE_MAP.get(port, "Unknown")
            }
    except:
        pass
    return None

def scan_host(host, port_range=(1, 1024), callback=None):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, p): p
                   for p in range(port_range[0], port_range[1] + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                if callback:
                    callback(result)
    return sorted(open_ports, key=lambda x: x["port"])

def save_report(host, open_ports):
    os.makedirs("../reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"../reports/scan_{host}_{ts}.json"
    with open(fname, "w") as f:
        json.dump({
            "host": host,
            "scanned_at": datetime.now().isoformat(),
            "total_open_ports": len(open_ports),
            "open_ports": open_ports
        }, f, indent=2)
    return fname