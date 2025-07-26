# sniffer.py

import os
import time
import joblib
import pandas as pd
import threading
import numpy as np
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, conf
from datetime import datetime

# --- CONFIGURATION ---
try:
    model = joblib.load('threat_detection_model.joblib')
    scaler = joblib.load('threat_detection_scaler.joblib')
    print("[INFO] Model and scaler loaded successfully.")
except FileNotFoundError:
    print("[FATAL ERROR] Model or scaler file not found.")
    exit()
EXPECTED_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 
    'Idle Std', 'Idle Max', 'Idle Min'
]

FLOW_TIMEOUT_SECONDS = 120
CLEANUP_INTERVAL_SECONDS = 15

flow_cache = {}
packet_count_total = 0
packet_count_interval = 0
sniffing_active = threading.Event()
sniffing_active.set()

class Flow:
    # Unchanged: your Flow class logic is solid.
    ...

def handle_packet(packet, socketio=None, iface=None):
    global packet_count_total, packet_count_interval
    if not sniffing_active.is_set() or IP not in packet:
        return

    packet_count_total += 1
    packet_count_interval += 1

    s_ip, d_ip = packet[IP].src, packet[IP].dst
    proto = packet[IP].proto
    s_port, d_port = (
        (packet[TCP].sport, packet[TCP].dport) if TCP in packet
        else (packet[UDP].sport, packet[UDP].dport) if UDP in packet
        else (0, 0)
    )

    flow_key = tuple(sorted(((s_ip, s_port), (d_ip, d_port)))) + (proto,)
    if flow_key in flow_cache:
        flow_cache[flow_key].add_packet(packet)
    else:
        flow_cache[flow_key] = Flow(packet)

def process_finished_flows(socketio=None):
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        now = time.time()
        finished_flow_keys = [key for key, flow in flow_cache.items() if (now - flow.last_time) > FLOW_TIMEOUT_SECONDS]

        for key in finished_flow_keys:
            flow = flow_cache.pop(key, None)
            if not flow:
                continue

            try:
                features_df = flow.get_features()
                if features_df is None:
                    continue

                scaled_features = scaler.transform(features_df)
                prediction_idx = model.predict(scaled_features)[0]
                prediction_label = str(model.classes_[prediction_idx])
                probability = model.predict_proba(scaled_features)[0][prediction_idx]

                if prediction_label.lower() != 'benign':
                    threat_data = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': flow.flow_id[0], 'dst_ip': flow.flow_id[2],
                        'label': prediction_label, 'confidence': f"{probability:.2f}",
                        'packet_info': {
                            'summary': flow.packets[0].summary(),
                            'layers': flow.packets[0].show(dump=True),
                            'hex_dump': str(bytes(flow.packets[0]))
                        }
                    }
                    print(f"[+] {prediction_label} ({probability:.2f}) detected: {flow.flow_id}")
                    if socketio:
                        socketio.emit('new_threat', threat_data)

            except Exception as e:
                print(f"[ERROR] Failed to process flow {flow.flow_id}: {e}")

def get_stats():
    global packet_count_interval
    pps = packet_count_interval / CLEANUP_INTERVAL_SECONDS
    packet_count_interval = 0
    return {"total_packets": packet_count_total, "pps": int(pps)}

def start_sniffing(socketio=None, iface=None):
    sniffing_active.set()

    # Automatically select default interface if not provided
    if iface is None:
        iface = conf.iface
        print(f"[INFO] No interface specified. Auto-selected interface: {iface}")

    print("[INFO] Starting flow processing thread...")
    threading.Thread(target=process_finished_flows, args=(socketio,), daemon=True).start()

    print(f"[INFO] Sniffing on interface: {iface}")
    try:
        sniff(iface=iface, prn=lambda p: handle_packet(p, socketio, iface),
              stop_filter=lambda p: not sniffing_active.is_set(), store=0)
    except Exception as e:
        print(f"[FATAL SNIFFER ERROR] Could not start sniffing. Interface: '{iface}'. Error: {e}")

def stop_sniffing():
    print("[INFO] Stopping sniffer...")
    sniffing_active.clear()

if __name__ == '__main__':
    print("Running sniffer in standalone test mode. Press Ctrl+C to stop.")
    start_sniffing()