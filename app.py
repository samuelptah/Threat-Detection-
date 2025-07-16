from flask import Flask, render_template
from flask_socketio import SocketIO
from sniffer_manager import SnifferManager
from system_info import get_system_info, log_system_info
from sniffer import recent_threats
 

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Initialize Sniffer Manager ---
sniffer_manager = SnifferManager(socketio=socketio)

# --- Routes ---
@app.route('/')
def index():
    return render_template('live_dashboard.html')

# --- Socket.IO Events ---
@socketio.on('connect')
def on_connect():
    print("[SOCKET] Client connected.")

    # Emit past buffered threats (last 20 for brevity)
    for threat in list(recent_threats)[-20:]:
        socketio.emit('new_threat', threat)

    # Start sniffers in background
    socketio.start_background_task(target=sniffer_manager.start_all_sniffers)

    # Emit system info
    info = get_system_info()
    socketio.emit('system_info', info)
    log_system_info(info)

@socketio.on('disconnect')
def on_disconnect():
    print("[SOCKET] Client disconnected.")

@socketio.on('get_sniffer_status')
def send_status():
    status = sniffer_manager.get_status()
    socketio.emit('sniffer_status', status)

@socketio.on('select_interface')
def switch_interface(data):
    iface = data.get('iface')
    if iface:
        result = sniffer_manager.restart_sniffer_on_interface(iface)
        socketio.emit('sniffer_status', result)
    else:
        socketio.emit('sniffer_status', {"error": "No interface specified"})

@socketio.on('start_sniffers')
def start_all():
    sniffer_manager.start_all_sniffers()
    socketio.emit('sniffer_status', {'status': 'started'})

@socketio.on('stop_sniffers')
def stop_all():
    sniffer_manager.stop_all_sniffers()
    socketio.emit('sniffer_status', {'status': 'stopped'})

# --- Main ---
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)



