import os
import time
from flask import Flask, render_template
from flask_socketio import SocketIO
from sniffer_manager import SnifferManager
from system_info import get_system_info
import sniffer

# --- Flask App Setup ---
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-strong-default-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Initialize Sniffer Manager ---
sniffer_manager = SnifferManager(socketio=socketio)

# --- Periodic System Info Emitter ---
def update_stats_periodically():
    while True:
        try:
            stats = sniffer.get_stats()
            sysinfo = get_system_info()
            combined = {**sysinfo, **stats}
            socketio.emit('system_info', combined)
        except Exception as e:
            print(f"[ERROR] update_stats_periodically: {e}")
        time.sleep(3)

# --- Routes ---
@app.route('/')
def index():
    return render_template('live_dashboard.html')

# --- Socket.IO Events ---
@socketio.on('connect')
def handle_connect():
    print("[SOCKET] Client connected.")

@socketio.on('disconnect')
def handle_disconnect():
    print("[SOCKET] Client disconnected.")

@socketio.on('request_initial_data')
def handle_initial_data_request():
    print("[SOCKET] Client requested initial data.")
    interfaces = sniffer_manager.get_available_interfaces()
    current_iface = sniffer_manager.get_active_interface()

    socketio.emit('initial_data', {
        'interfaces': interfaces,
        'current_interface': current_iface
    })
    socketio.emit('sniffer_status', sniffer_manager.get_status())
    socketio.emit('system_info', {**get_system_info(), **sniffer.get_stats()})

@socketio.on('set_interface')
def handle_set_interface(data):
    iface = data.get('interface')
    if iface:
        print(f"[MANAGER] Switching sniffer to: {iface}")
        sniffer_manager.set_active_sniffer(iface)
        socketio.emit('sniffer_status', sniffer_manager.get_status())
    else:
        socketio.emit('sniffer_status', {"error": "No interface provided"})

# --- App Entry ---
if __name__ == '__main__':
    print("[INIT] Launching AI Threat Intelligence Dashboard...")

    # Start background sniffing and stats reporting
    socketio.start_background_task(sniffer_manager.start_default_sniffer)
    socketio.start_background_task(update_stats_periodically)

    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)



