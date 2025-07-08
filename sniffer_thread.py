# sniffer_thread.py

import threading
from scapy.all import sniff
from sniffer import handle_packet  # Must accept (packet, socketio, iface)

class SnifferThread(threading.Thread):
    def __init__(self, iface, socketio=None):
        super().__init__(daemon=True)
        self.iface = iface
        self.socketio = socketio
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        print(f"[INIT] SnifferThread created for interface: {self.iface}")

    def run(self):
        print(f"[START] Sniffer started on interface: {self.iface}")
        try:
            sniff(
                iface=self.iface,
                prn=self._packet_handler,
                store=False,
                stop_filter=self._should_stop
            )
        except Exception as e:
            print(f"[ERROR] Exception during sniffing on {self.iface}: {e}")
        finally:
            print(f"[EXIT] Sniffer thread exiting for interface: {self.iface}")

    def _packet_handler(self, packet):
        if not self.pause_event.is_set():
            try:
                handle_packet(packet, self.socketio, self.iface)
            except Exception as e:
                print(f"[ERROR] handle_packet() failed on {self.iface}: {e}")

    def _should_stop(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        print(f"[STOP] Requesting stop on interface: {self.iface}")
        self.stop_event.set()
        self.resume()  # In case it's paused, resume so thread can exit

    def pause(self):
        print(f"[PAUSE] Sniffer paused on interface: {self.iface}")
        self.pause_event.set()

    def resume(self):
        if self.pause_event.is_set():
            print(f"[RESUME] Sniffer resumed on interface: {self.iface}")
            self.pause_event.clear()

    def is_sniffing(self):
        return not self.stop_event.is_set() and not self.pause_event.is_set()

    def is_paused(self):
        return self.pause_event.is_set()

    def is_stopped(self):
        return self.stop_event.is_set()
