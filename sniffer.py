# sniffer.py

import os
import json
import joblib
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime
from collections import deque
from scapy.all import sniff, get_if_list, conf, IP
from socketio_instance import socketio  # Initialized in app.py

# --- Setup ---
os.makedirs('database', exist_ok=True)
DB_PATH = os.path.join('database', 'threats.db')

# --- Load model, scaler & features ---
try:
    model = joblib.load('threat_detection_model.joblib')
    scaler = joblib.load('threat_detection_scaler.joblib')
    with open('selected_features.json', 'r') as f:
        selected_features = json.load(f)
    print("[INIT] Model, scaler & features loaded.")
except Exception as e:
    print(f"[LOAD ERROR] {e}")
    model = scaler = None
    selected_features = []

# --- Label map ---
label_map = {
    "0": "Benign",
    "1": "DoS",
    "2": "PortScan",
    "3": "BruteForce",
    "4": "Phishing"
}

# --- Dedup cache ---
recent_signatures = deque(maxlen=200)

# --- Feature extractor ---
def extract_features(pkt):
    return {
        'packet_length': len(pkt),
        'src_port': getattr(pkt, 'sport', 0),
        'dst_port': getattr(pkt, 'dport', 0),
        'protocol': getattr(pkt, 'proto', 0),
        'flags': getattr(pkt, 'flags', 0)
    }

# --- Pick best non-loopback interface ---
def get_best_interface():
    for iface in get_if_list():
        if "Loopback" not in iface and not iface.lower().startswith("lo"):
            return iface
    return conf.iface

# --- Build a simple signature for deduplication ---
def packet_signature(src, dst, label, iface):
    return f"{src}|{dst}|{label}|{iface}"

# --- Main packet handler ---  
def handle_packet(pkt, socketio, iface):
    if model is None or scaler is None or not selected_features or IP not in pkt:
        return

    try:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto  = pkt[IP].proto
    except Exception:
        return

    # Skip pure loopback
    if src_ip.startswith("127.") and dst_ip.startswith("127."):
        return

    # Build DataFrame
    raw = extract_features(pkt)
    df  = pd.DataFrame([raw])
    for col in selected_features:
        if col not in df.columns:
            df[col] = 0
    df = df[selected_features]

    try:
        scaled    = scaler.transform(df)
        scaled_df = pd.DataFrame(scaled, columns=selected_features)
        pred      = model.predict(scaled_df)[0]
        conf_pct  = round(100 * np.max(model.predict_proba(scaled_df)), 2)
    except Exception as e:
        print(f"[PREDICT ERROR] {e}")
        return

    label = label_map.get(str(pred), "Unknown")
    sig   = packet_signature(src_ip, dst_ip, label, iface)
    if sig in recent_signatures:
        return         # duplicate within cache window
    recent_signatures.append(sig)

    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # --- Emit via Socket.IO ---
    try:
        socketio.emit('new_threat', {
            'timestamp': ts,
            'src_ip':    src_ip,
            'dst_ip':    dst_ip,
            'protocol':  proto,
            'label':     label,
            'confidence': f"{conf_pct:.2f}%",
            'interface': iface
        })
        print(f"[SOCKET] {label} ({conf_pct:.2f}%) {src_ip}→{dst_ip} on {iface}")
    except Exception as e:
        print(f"[SOCKET ERROR] {e}")

    # --- Log to SQLite ---
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    label TEXT,
                    confidence REAL
                )
            ''')
            cur.execute('INSERT INTO threats VALUES (?, ?, ?, ?, ?, ?)', (
                ts, src_ip, dst_ip, str(proto), label, conf_pct
            ))
            conn.commit()
    except Exception as e:
        print(f"[DB ERROR] {e}")

# --- Start sniffing on a single, auto-selected interface ---
def start_sniffing():
    iface = get_best_interface()
    print(f"[SNIFFER] Listening on interface: {iface}")
    sniff(
        iface=iface,
        prn=lambda pkt: handle_packet(pkt, socketio, iface),
        store=False
    )

if __name__ == "__main__":
    start_sniffing()
