from scapy.all import rdpcap
from traffic_analyzer.streaming import handle_packet
def import_and_process(path):
    pkts = rdpcap(path)
    for p in pkts:
        try:
            handle_packet(p)
        except Exception:
            pass
