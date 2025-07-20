import os
import time
import joblib
import pandas as pd
import threading
import numpy as np
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
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
FLOW_TIMEOUT_SECONDS = 60
CLEANUP_INTERVAL_SECONDS = 10

# --- GLOBAL STATE (for this module) ---
flow_cache = {}
packet_count_total = 0
packet_count_interval = 0
sniffing_active = threading.Event()

class Flow:
    # ... (No changes to the Flow class, it's correct)
    def __init__(self, packet):
        self.packets = []
        self.flow_id = self._get_flow_id(packet)
        self.start_time = packet.time
        self.last_time = packet.time
        self.add_packet(packet)
    def _get_flow_id(self, packet):
        if IP not in packet: return None
        s_ip, d_ip = packet[IP].src, packet[IP].dst
        proto = packet[IP].proto
        s_port, d_port = (packet[TCP].sport, packet[TCP].dport) if TCP in packet else ((packet[UDP].sport, packet[UDP].dport) if UDP in packet else (0, 0))
        if (s_ip, s_port) < (d_ip, d_port): return (s_ip, s_port, d_ip, d_port, proto)
        else: return (d_ip, d_port, s_ip, s_port, proto)
    def add_packet(self, packet):
        self.packets.append(packet)
        self.last_time = packet.time
    def get_features(self):
        if not self.packets: return None
        fwd_packets = [p for p in self.packets if p[IP].src == self.flow_id[0] and p[IP].dst == self.flow_id[2]]
        bwd_packets = [p for p in self.packets if p[IP].src == self.flow_id[2] and p[IP].dst == self.flow_id[0]]
        total_fwd_packets = len(fwd_packets); total_bwd_packets = len(bwd_packets)
        total_len_fwd = sum(len(p) for p in fwd_packets); total_len_bwd = sum(len(p) for p in bwd_packets)
        flow_duration = (self.last_time - self.start_time) * 1e6
        all_ts = sorted([p.time for p in self.packets]); flow_iat = np.diff(all_ts) if len(all_ts) > 1 else np.array([0])
        fwd_iat = np.diff(sorted([p.time for p in fwd_packets])) if len(fwd_packets) > 1 else np.array([0])
        bwd_iat = np.diff(sorted([p.time for p in bwd_packets])) if len(bwd_packets) > 1 else np.array([0])
        all_pkt_lens = [len(p) for p in self.packets]; fwd_pkt_lens = [len(p) for p in fwd_packets] if fwd_packets else [0]
        bwd_pkt_lens = [len(p) for p in bwd_packets] if bwd_packets else [0]
        flag_counts = defaultdict(int)
        for p in self.packets:
            if TCP in p:
                flags = p[TCP].flags
                if flags & 0x01: flag_counts['FIN'] += 1; 
                if flags & 0x02: flag_counts['SYN'] += 1
                if flags & 0x04: flag_counts['RST'] += 1; 
                if flags & 0x08: flag_counts['PSH'] += 1
                if flags & 0x10: flag_counts['ACK'] += 1; 
                if flags & 0x20: flag_counts['URG'] += 1
                if flags & 0x40: flag_counts['ECE'] += 1; 
                if flags & 0x80: flag_counts['CWR'] += 1
        features = {key: 0.0 for key in EXPECTED_FEATURES}; duration_sec = flow_duration / 1e6
        features.update({
            'Destination Port': self.flow_id[3], 'Flow Duration': flow_duration, 'Total Fwd Packets': total_fwd_packets,
            'Total Backward Packets': total_bwd_packets, 'Total Length of Fwd Packets': total_len_fwd, 'Total Length of Bwd Packets': total_len_bwd,
            'Fwd Packet Length Max': np.max(fwd_pkt_lens), 'Fwd Packet Length Min': np.min(fwd_pkt_lens), 'Fwd Packet Length Mean': np.mean(fwd_pkt_lens), 'Fwd Packet Length Std': np.std(fwd_pkt_lens),
            'Bwd Packet Length Max': np.max(bwd_pkt_lens), 'Bwd Packet Length Min': np.min(bwd_pkt_lens), 'Bwd Packet Length Mean': np.mean(bwd_pkt_lens), 'Bwd Packet Length Std': np.std(bwd_pkt_lens),
            'Flow Bytes/s': (total_len_fwd + total_len_bwd) / duration_sec if duration_sec > 0 else 0,
            'Flow Packets/s': (total_fwd_packets + total_bwd_packets) / duration_sec if duration_sec > 0 else 0,
            'Flow IAT Mean': np.mean(flow_iat) * 1e6, 'Flow IAT Std': np.std(flow_iat) * 1e6, 'Flow IAT Max': np.max(flow_iat) * 1e6 if flow_iat.size > 0 else 0, 'Flow IAT Min': np.min(flow_iat) * 1e6 if flow_iat.size > 0 else 0,
            'Fwd IAT Total': np.sum(fwd_iat) * 1e6, 'Fwd IAT Mean': np.mean(fwd_iat) * 1e6, 'Fwd IAT Std': np.std(fwd_iat) * 1e6, 'Fwd IAT Max': np.max(fwd_iat) * 1e6 if fwd_iat.size > 0 else 0, 'Fwd IAT Min': np.min(fwd_iat) * 1e6 if fwd_iat.size > 0 else 0,
            'Bwd IAT Total': np.sum(bwd_iat) * 1e6, 'Bwd IAT Mean': np.mean(bwd_iat) * 1e6, 'Bwd IAT Std': np.std(bwd_iat) * 1e6, 'Bwd IAT Max': np.max(bwd_iat) * 1e6 if bwd_iat.size > 0 else 0, 'Bwd IAT Min': np.min(bwd_iat) * 1e6 if bwd_iat.size > 0 else 0,
            'Fwd PSH Flags': sum(1 for p in fwd_packets if TCP in p and p[TCP].flags & 0x08), 'Bwd PSH Flags': sum(1 for p in bwd_packets if TCP in p and p[TCP].flags & 0x08),
            'Fwd URG Flags': sum(1 for p in fwd_packets if TCP in p and p[TCP].flags & 0x20), 'Bwd URG Flags': sum(1 for p in bwd_packets if TCP in p and p[TCP].flags & 0x20),
            'Fwd Header Length': sum(p[IP].ihl * 4 for p in fwd_packets), 'Bwd Header Length': sum(p[IP].ihl * 4 for p in bwd_packets),
            'Fwd Packets/s': total_fwd_packets / duration_sec if duration_sec > 0 else 0, 'Bwd Packets/s': total_bwd_packets / duration_sec if duration_sec > 0 else 0,
            'Min Packet Length': np.min(all_pkt_lens) if all_pkt_lens else 0, 'Max Packet Length': np.max(all_pkt_lens) if all_pkt_lens else 0,
            'Packet Length Mean': np.mean(all_pkt_lens), 'Packet Length Std': np.std(all_pkt_lens), 'Packet Length Variance': np.var(all_pkt_lens),
            'FIN Flag Count': flag_counts['FIN'], 'SYN Flag Count': flag_counts['SYN'], 'RST Flag Count': flag_counts['RST'],
            'PSH Flag Count': flag_counts['PSH'], 'ACK Flag Count': flag_counts['ACK'], 'URG Flag Count': flag_counts['URG'],
            'CWE Flag Count': flag_counts['CWR'], 'ECE Flag Count': flag_counts['ECE'],
            'Down/Up Ratio': total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0, 'Average Packet Size': np.mean(all_pkt_lens),
            'Avg Fwd Segment Size': np.mean(fwd_pkt_lens), 'Avg Bwd Segment Size': np.mean(bwd_pkt_lens),
            'Fwd Header Length.1': sum(p[IP].ihl * 4 for p in fwd_packets),
            'Init_Win_bytes_forward': fwd_packets[0][TCP].window if total_fwd_packets > 0 and TCP in fwd_packets[0] else -1,
            'Init_Win_bytes_backward': bwd_packets[0][TCP].window if total_bwd_packets > 0 and TCP in bwd_packets[0] else -1,
            'Subflow Fwd Packets': total_fwd_packets, 'Subflow Fwd Bytes': total_len_fwd, 'Subflow Bwd Packets': total_bwd_packets, 'Subflow Bwd Bytes': total_len_bwd
        })
        return pd.DataFrame([features])[EXPECTED_FEATURES]

def handle_packet(packet):
    global packet_count_total, packet_count_interval
    if not sniffing_active.is_set() or IP not in packet: return
    packet_count_total += 1; packet_count_interval += 1
    s_ip, d_ip, proto = packet[IP].src, packet[IP].dst, packet[IP].proto
    s_port, d_port = (packet[TCP].sport, packet[TCP].dport) if TCP in packet else ((packet[UDP].sport, packet[UDP].dport) if UDP in packet else (0, 0))
    flow_key = tuple(sorted(((s_ip, s_port), (d_ip, d_port)))) + (proto,)
    if flow_key in flow_cache: flow_cache[flow_key].add_packet(packet)
    else: flow_cache[flow_key] = Flow(packet)

def process_finished_flows(socketio=None):
    while sniffing_active.is_set():
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        now = time.time()
        finished_flow_keys = [key for key, flow in list(flow_cache.items()) if (now - flow.last_time) > FLOW_TIMEOUT_SECONDS]
        for key in finished_flow_keys:
            flow = flow_cache.pop(key, None)
            if not flow: continue
            try:
                features_df = flow.get_features()
                if features_df is None: continue
                scaled_features = scaler.transform(features_df)
                prediction_idx = model.predict(scaled_features)[0]
                prediction_label = str(model.classes_[prediction_idx])
                probability = model.predict_proba(scaled_features)[0][prediction_idx]
                if prediction_label.lower() != 'benign':
                    threat_data = {
                        'timestamp': datetime.now().isoformat(), 'src_ip': flow.flow_id[0], 'dst_ip': flow.flow_id[2],
                        'label': prediction_label, 'confidence': f"{probability:.2f}",
                        'packet_info': { 'summary': flow.packets[0].summary(), 'layers': flow.packets[0].show(dump=True), 'hex_dump': str(bytes(flow.packets[0])) }
                    }
                    print(f"[PREDICTION] Flow {flow.flow_id[0]}:{flow.flow_id[1]} -> {flow.flow_id[2]}:{flow.flow_id[3]} is {prediction_label} (Confidence: {probability:.2f})")
                    if socketio: socketio.emit('new_threat', threat_data)
            except Exception as e: print(f"[ERROR] Failed to process flow {flow.flow_id}: {e}")

def get_stats():
    global packet_count_interval
    pps = packet_count_interval / CLEANUP_INTERVAL_SECONDS; packet_count_interval = 0
    return {"total_packets": packet_count_total, "pps": int(pps)}

def start_sniffing(socketio=None, iface=None):
    sniffing_active.set()
    processing_thread = threading.Thread(target=process_finished_flows, args=(socketio,), daemon=True)
    processing_thread.start()
    print(f"[INFO] Sniffing on interface: {iface or 'default'}")
    try:
        sniff(iface=iface, prn=handle_packet, stop_filter=lambda p: not sniffing_active.is_set(), store=0)
    except Exception as e: print(f"[FATAL SNIFFER ERROR] on '{iface}': {e}")
    print(f"[INFO] Sniffing stopped on interface: {iface}")

def stop_sniffing():
    sniffing_active.clear()