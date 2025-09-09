import threading, logging
from queue import Queue, Full
from typing import Optional, Iterable
from time import time
from scapy.all import sniff, get_if_list, PcapWriter
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from ..models import PacketView
from .pyshark_backend import HAS_PYSHARK, PySharkCapture

log = logging.getLogger(__name__)

class CaptureManager:
    def __init__(self, classifier, queue_max=30000, prefer_pyshark=True):
        self.classifier = classifier
        self._threads = []
        self._stop = threading.Event()
        self._queue: Queue = Queue(maxsize=queue_max)
        self._pcap_writer = None
        self._running = False
        self.prefer_pyshark = prefer_pyshark and HAS_PYSHARK
        self._pyshark_instances = []

    @staticmethod
    def list_ifaces():
        try:
            return list(get_if_list())
        except Exception:
            return []

    def start(self, ifaces: Optional[Iterable[str]]=None, write_pcap: Optional[str]=None, bpf: Optional[str]=None, use_pyshark=False):
        if self._running:
            return
        self._stop.clear()
        self._running = True
        if write_pcap:
            try:
                self._pcap_writer = PcapWriter(write_pcap, append=True, sync=True)
            except Exception:
                self._pcap_writer = None
        if ifaces is None:
            ifaces = [None]
        # prefer pyshark only if available and requested
        use_pyshark = use_pyshark and HAS_PYSHARK
        for iface in ifaces:
            if use_pyshark:
                # start a pyshark capture in a thread
                cap = PySharkCapture(iface=iface or None, bpf=bpf, callback=self._on_pyshark_pkt)
                t = threading.Thread(target=cap.start, daemon=True)
                t.start()
                self._threads.append((t, cap))
            else:
                t = threading.Thread(target=self._sniff_iface, args=(iface or '', bpf), daemon=True)
                t.start()
                self._threads.append((t, None))

    def _sniff_iface(self, iface, bpf):
        def _prn(pkt):
            try:
                if not hasattr(pkt, 'sniffed_on'):
                    pkt.sniffed_on = iface
                if self._pcap_writer:
                    try:
                        self._pcap_writer.write(pkt)
                    except Exception:
                        pass
                self._on_pkt(pkt)
            except Exception:
                log.exception('Error processing pkt')
            return None
        sniff(iface=iface, store=False, prn=_prn, filter=bpf, stop_filter=lambda p: self._stop.is_set())

    def _on_pyshark_pkt(self, parsed):
        # parsed is dict from pyshark_backend: convert to PacketView-like and push to queue
        try:
            ts = time()
            # best-effort extraction
            iface = parsed.get('layers', {}).get('frame', {}).get('frame_interface_id', '') or ''
            src = parsed.get('layers', {}).get('ip', {}).get('ip_src', '?')
            dst = parsed.get('layers', {}).get('ip', {}).get('ip_dst', '?')
            l4 = parsed.get('layers', {}).get('tcp', None) and 'TCP' or (parsed.get('layers', {}).get('udp', None) and 'UDP' or 'OTHER')
            sport = parsed.get('layers', {}).get('tcp', {}).get('tcp_src') or parsed.get('layers', {}).get('udp', {}).get('udp_src')
            dport = parsed.get('layers', {}).get('tcp', {}).get('tcp_dst') or parsed.get('layers', {}).get('udp', {}).get('udp_dst')
            info = ''
            # prefer HTTP host, then TLS SNI, then DNS qname
            if 'http' in parsed.get('layers', {}):
                info = parsed['layers']['http'].get('http_host') or parsed['layers']['http'].get('host') or ''
            if not info and 'tls' in parsed.get('layers', {}):
                info = parsed['layers']['tls'].get('handshake_extensions_server_name') or parsed['layers']['tls'].get('tls.handshake.extensions_server_name') or ''
            if not info and 'dns' in parsed.get('layers', {}):
                info = parsed['layers']['dns'].get('qry_name') or ''
            try:
                sport = int(sport) if sport else None
                dport = int(dport) if dport else None
            except Exception:
                sport = None; dport = None
            pv = PacketView(ts=ts, iface=iface, src=src, dst=dst, proto=l4, sport=sport, dport=dport, length=len(parsed.get('raw') or b''), classification='pyshark', summary=info, raw=parsed.get('raw') or b'', scapy_pkt=None)
            try:
                self._queue.put_nowait(pv)
            except Full:
                pass
        except Exception:
            pass

    def _on_pkt(self, pkt):
        try:
            ts = time()
            src = getattr(pkt.getlayer(IP) or pkt.getlayer(IPv6), 'src', '?')
            dst = getattr(pkt.getlayer(IP) or pkt.getlayer(IPv6), 'dst', '?')
            label, l4, sport, dport, info = self.classifier.classify(pkt)
            pv = PacketView(ts=ts, iface=getattr(pkt, 'sniffed_on', ''), src=src, dst=dst, proto=l4, sport=sport, dport=dport, length=len(pkt), classification=label, summary=info, raw=bytes(pkt), scapy_pkt=pkt)
            try:
                self._queue.put_nowait(pv)
            except Full:
                pass
        except Exception:
            log.exception('Failed to on_pkt')

    def pull_packet(self):
        try:
            return self._queue.get_nowait()
        except Exception:
            return None

    def stop(self):
        if not self._running:
            return
        self._stop.set()
        # try to stop pyshark instances
        for t, cap in self._threads:
            try:
                if cap and hasattr(cap, 'stop'):
                    cap.stop()
            except Exception:
                pass
            try:
                if t.is_alive():
                    t.join(timeout=0.5)
            except Exception:
                pass
        self._threads.clear()
        if self._pcap_writer:
            try:
                self._pcap_writer.close()
            except Exception:
                pass
        self._running = False
