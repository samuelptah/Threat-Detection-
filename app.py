from flask import Flask, render_template
from flask_socketio import SocketIO
from sniffer_manager import SnifferManager

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# --- SocketIO Setup ---
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Sniffer Manager (for multi-interface sniffing) ---
sniffer_manager = SnifferManager(socketio=socketio)

# --- Routes ---
@app.route('/')
def index():
    return render_template('live_dashboard.html')  # replace with your actual template

# --- SocketIO Events ---
@socketio.on('connect')
def on_connect():
    print("[SOCKET] Client connected.")
    socketio.start_background_task(target=sniffer_manager.start_all_sniffers)

@socketio.on('disconnect')
def on_disconnect():
    print("[SOCKET] Client disconnected.")

@socketio.on('get_sniffer_status')
def send_status():
    status = sniffer_manager.get_status()
    socketio.emit('sniffer_status', status)

@socketio.on('stop_sniffers')
def stop_all():
    sniffer_manager.stop_all_sniffers()
    socketio.emit('sniffer_status', {'status': 'stopped'})

# --- App Entry ---
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
# This is the main entry point for the Flask application.