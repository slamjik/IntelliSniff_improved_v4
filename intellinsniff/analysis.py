from scapy.layers.inet import IP, TCP, UDP

class Analyzer:
    def analyze(self, packet):
        if IP in packet:
            proto = packet[IP].proto
            if proto == 6: return "TCP"
            elif proto == 17: return "UDP"
            else: return f"IP proto {proto}"
        return "Unknown"
