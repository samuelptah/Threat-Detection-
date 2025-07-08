# sniffer_manager.py

import platform
from scapy.all import get_if_list
from sniffer_thread import SnifferThread


class SnifferManager:
    def __init__(self, socketio=None):
        self.sniffers = {}  # {iface_name: SnifferThread}
        self.socketio = socketio

    def start_all_sniffers(self):
        """Start sniffing on all available interfaces."""
        interfaces = get_if_list()

        for iface in interfaces:
            if iface not in self.sniffers:
                try:
                    print(f"[INFO] Starting sniffer on interface: {iface}")
                    sniffer = SnifferThread(iface=iface, socketio=self.socketio)
                    sniffer.start()
                    self.sniffers[iface] = sniffer
                except Exception as e:
                    print(f"[ERROR] Failed to start sniffer on {iface}: {e}")

    def stop_all_sniffers(self):
        """Stop all active sniffers."""
        for iface, sniffer in self.sniffers.items():
            try:
                print(f"[INFO] Stopping sniffer on interface: {iface}")
                sniffer.stop()
            except Exception as e:
                print(f"[ERROR] Failed to stop sniffer on {iface}: {e}")
        self.sniffers.clear()

    def get_status(self):
        """Get status of all interfaces being sniffed."""
        status = {}
        for iface, sniffer in self.sniffers.items():
            try:
                status[iface] = {
                    "is_sniffing": sniffer.is_sniffing(),
                    "is_paused": sniffer.is_paused(),
                    "is_stopped": sniffer.is_stopped(),
                }
            except Exception as e:
                status[iface] = {"error": str(e)}
        return status
    def get_interfaces(self):
        """Get a list of available network interfaces."""
        try:
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            print(f"[ERROR] Failed to retrieve interfaces: {e}")
            return []
    def get_os_info(self):
        """Get OS information."""
        try:
            os_info = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.architecture(),
            }
            return os_info
        except Exception as e:
            print(f"[ERROR] Failed to retrieve OS info: {e}")
            return {}
    def get_sniffer_info(self, iface):
        """Get information about a specific sniffer."""
        if iface in self.sniffers:
            sniffer = self.sniffers[iface]
            return {
                "iface": iface,
                "is_sniffing": sniffer.is_sniffing(),
                "is_paused": sniffer.is_paused(),
                "is_stopped": sniffer.is_stopped(),
            }
        else:
            return {"error": f"No sniffer found for interface {iface}"}