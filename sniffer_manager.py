import threading
from scapy.all import get_if_list, conf
import sniffer 

class SnifferManager:
    """Manages a single, active sniffer thread."""

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.sniffer_thread = None
        self.active_interface = None
        self.available_interfaces = self._get_interfaces()
        print(f"[INIT] SnifferManager initialized. Found interfaces: {self.available_interfaces}")

    def _get_interfaces(self):
        """Gets a list of human-readable network interface names."""
        try:
            # Use Scapy's conf object for more reliable interface info
            return [iface.name for iface in conf.ifaces.values() if iface.ip and iface.mac]
        except Exception as e:
            print(f"[ERROR] Could not get interface list: {e}")
            return ["default"]

    def start_default_sniffer(self):
        """Starts a sniffer on the first available valid interface."""
        if self.available_interfaces:
            default_iface = self.available_interfaces[0]
            self.set_active_sniffer(default_iface)
        else:
            print("[ERROR] No suitable network interfaces found to start sniffing.")

    def set_active_sniffer(self, iface):
        """Stops any current sniffer and starts a new one on the specified interface."""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            if self.active_interface == iface:
                print(f"[WARN] Sniffer for interface {iface} is already running.")
                return
            
            print(f"[MANAGER] Stopping sniffer on {self.active_interface} to switch.")
            sniffer.stop_sniffing()
            self.sniffer_thread.join(timeout=2) # Wait for the thread to finish

        self.active_interface = iface
        print(f"[MANAGER] Starting new sniffer on interface: {self.active_interface}")
        
        self.sniffer_thread = threading.Thread(
            target=sniffer.start_sniffing,
            args=(self.socketio, self.active_interface),
            daemon=True
        )
        self.sniffer_thread.start()
        print(f"[START] Sniffer started successfully on {self.active_interface}.")

    def get_status(self):
        """Returns the status of the active sniffer."""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return {
                "running": True, 
                "interface": self.active_interface
            }
        return {
            "running": False,
            "interface": None
        }

    def get_active_interface(self):
        return self.active_interface

    def get_available_interfaces(self):
        return self.available_interfaces