from scapy.all import sniff

class CaptureManager:
    def __init__(self, interfaces=None, callback=None):
        self.interfaces = interfaces
        self.callback = callback

    def start(self):
        sniff(iface=self.interfaces, prn=self.callback, store=False)
