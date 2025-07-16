# system_info.py

import platform
import psutil
import time
import os
from scapy.all import get_if_list, get_if_hwaddr, get_if_addr

def get_best_interface():
    for iface in get_if_list():
        if "Loopback" not in iface and not iface.lower().startswith("lo"):
            return iface
    return "Unknown"

def get_system_info():
    iface = get_best_interface()
    try:
        mac = get_if_hwaddr(iface)
        ip = get_if_addr(iface)
    except Exception:
        mac, ip = "Unknown", "Unknown"

    try:
        uptime_seconds = int(time.time() - psutil.boot_time())
    except Exception:
        uptime_seconds = 0

    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory_percent = psutil.virtual_memory().percent
    except Exception:
        cpu_percent = memory_percent = 0.0

    return {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.architecture()[0],
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(memory_percent, 1),
        "uptime_seconds": uptime_seconds,
        "interface": iface,
        "mac_address": mac,
        "ip_address": ip
    }

def log_system_info(info):
    try:
        os.makedirs("logs", exist_ok=True)
        log_path = os.path.join("logs", "system_info.log")
        with open(log_path, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {info}\n")
    except Exception as e:
        print(f"[❌ LOG ERROR] Failed to write system info log: {e}")
