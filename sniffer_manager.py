import threading
import socket
from scapy.all import conf, get_if_list, get_if_addr
import sniffer

class SnifferManager:
    """Manages a single, active sniffer thread for the application."""

    def __init__(self, socketio=None):
        self.socketio = socketio
        self.sniffer_thread = None
        self.active_interface = None
        self.available_interfaces = self._get_interfaces()
        print(f"[INIT] SnifferManager initialized. Found interfaces: {self.available_interfaces}")

    def _get_interfaces(self):
        """Returns a list of interfaces with valid IPv4 addresses."""
        interfaces = []
        try:
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    if ip and not ip.startswith("127."):  # Skip loopback
                        interfaces.append(iface)
                except Exception:
                    continue
        except Exception as e:
            print(f"[ERROR] Failed to retrieve interfaces: {e}")
        return interfaces

    def start_default_sniffer(self):
        """Automatically selects the best interface and starts the sniffer."""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            print("[INFO] Sniffer is already running.")
            return

        # Try to auto-detect interface with external IP
        default_iface = None
        if self.available_interfaces:
            default_iface = self._get_interface_with_ip()

        # Fallback to common names if auto-detect fails
        if not default_iface:
            priority = ['Wi-Fi', 'Ethernet', 'eth0', 'wlan0', 'en0']
            default_iface = next((iface for iface in priority if iface in self.available_interfaces), None)

        # Fallback to first available interface
        if not default_iface and self.available_interfaces:
            default_iface = self.available_interfaces[0]

        if default_iface:
            print(f"[AUTO] Auto-selected interface: {default_iface}")
            self.set_active_sniffer(default_iface)
        else:
            print("[ERROR] No valid network interface found for sniffing.")

    def _get_interface_with_ip(self):
        """Returns the first interface with a valid non-loopback IP."""
        for iface in self.available_interfaces:
            try:
                ip = get_if_addr(iface)
                if ip and not ip.startswith("127."):
                    return iface
            except:
                continue
        return None

    def set_active_sniffer(self, iface):
        """Starts sniffing on the specified interface."""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            if self.active_interface == iface:
                print(f"[WARN] Sniffer already running on {iface}.")
                return
            print(f"[MANAGER] Switching sniffer from {self.active_interface} to {iface}.")
            sniffer.stop_sniffing()
            self.sniffer_thread.join(timeout=2)

        self.active_interface = iface
        print(f"[MANAGER] Starting sniffer on: {iface}")
        self.sniffer_thread = threading.Thread(
            target=sniffer.start_sniffing,
            args=(self.socketio, iface),
            daemon=True
        )
        self.sniffer_thread.start()
        print(f"[START] Sniffer started on {iface}.")

    def get_status(self):
        """Returns current sniffer status."""
        return {
            "running": self.sniffer_thread and self.sniffer_thread.is_alive(),
            "interface": self.active_interface
        }

    def get_active_interface(self):
        return self.active_interface

    def get_available_interfaces(self):
        return self.available_interfaces
