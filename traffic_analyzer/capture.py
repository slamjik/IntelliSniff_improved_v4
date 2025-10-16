
import logging, threading, time
from typing import Optional

from .streaming import handle_packet, init_streaming, stop_streaming
from .nfstream_helper import NFSTREAM_AVAILABLE, make_streamer, iterate_flows_from_streamer

log = logging.getLogger('ta.capture')

try:
    from scapy.all import AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

_sniffer = None
_sniffer_lock = threading.Lock()
_nf_thread = None
_nf_stop = False
_status = {
    'running': False,
    'started_at': None,
    'iface': None,
    'bpf': None,
    'use_nfstream': False,
    'flow_timeout': 30.0,
}

def list_ifaces():
    """Return available interfaces (fallback to empty list when scapy missing)."""
    if not SCAPY_AVAILABLE:
        return []
    try:
        return get_if_list()
    except Exception:
        return []

def _pkt_to_dict(pkt):
    """Normalize scapy packet or dict-like flow into expected dict for handle_packet."""
    if pkt is None:
        return None
    # if already dict (e.g., from NFStream helper), trust keys
    if isinstance(pkt, dict):
        return pkt
    # scapy Packet: try to extract basic info
    try:
        src = getattr(pkt, 'src', None) or getattr(pkt, 'src_ip', None)
        dst = getattr(pkt, 'dst', None) or getattr(pkt, 'dst_ip', None)
        sport = getattr(pkt, 'sport', None) or getattr(pkt, 'src_port', None)
        dport = getattr(pkt, 'dport', None) or getattr(pkt, 'dst_port', None)
        proto = getattr(pkt, 'proto', None) or getattr(pkt, 'proto', None)
        ts = getattr(pkt, 'time', None)
        length = getattr(pkt, 'len', None) or getattr(pkt, 'length', None) or getattr(pkt, '__len__', None)
        iface = getattr(pkt, 'sniffed_on', None) or getattr(pkt, 'iface', None)
        return {
            'ts': ts,
            'src': src,
            'dst': dst,
            'sport': sport,
            'dport': dport,
            'proto': proto,
            'bytes': length,
            'iface': iface,
            'raw': None
        }
    except Exception:
        return None

def _on_packet(pkt):
    pd = _pkt_to_dict(pkt)
    if pd is None:
        return
    try:
        handle_packet(pd)
    except Exception:
        log.exception("handle_packet failed")

def _run_nfstream(interface=None, pcap=None, flow_timeout: float = 30.0):
    """Run NFStreamer loop and forward flows to handle_packet."""
    global _nf_stop
    _nf_stop = False
    streamer = make_streamer(interface=interface, pcap=pcap)
    if not streamer:
        log.warning("NFStream requested but not available or failed to start.")
        return
    for flow in iterate_flows_from_streamer(streamer):
        if _nf_stop:
            break
        try:
            # normalize flow to dict
            pkt = {
                'ts': getattr(flow, 'timestamp', None),
                'src': getattr(flow, 'src_ip', None),
                'dst': getattr(flow, 'dst_ip', None),
                'sport': getattr(flow, 'src_port', None),
                'dport': getattr(flow, 'dst_port', None),
                'proto': getattr(flow, 'protocol', None),
                'bytes': getattr(flow, 'bytes', None),
                'packets': getattr(flow, 'packets', None),
                'iface': interface,
                'tls_sni': getattr(flow, 'tls_sni', None),
                'http_host': getattr(flow, 'http_host', None),
                'dns_query': getattr(flow, 'dns_qry_name', None),
                'application_name': getattr(flow, 'application_name', None),
            }
            handle_packet(pkt)
        except Exception:
            log.exception("Failed handling nfstream flow")
    try:
        streamer.stop()
    except Exception:
        pass

def start_capture(iface: Optional[str] = None, bpf: Optional[str] = None,
                  flow_timeout: float = 30.0, use_nfstream: bool = False):
    """Start packet capture. If use_nfstream True and NFStream is available, use NFStream; otherwise use scapy AsyncSniffer."""
    global _sniffer, _nf_thread, _nf_stop
    with _sniffer_lock:
        if _sniffer is not None or (_nf_thread is not None and _nf_thread.is_alive()):
            log.warning("Capture already running")
            return
        init_streaming(flow_timeout=flow_timeout)
        _status.update({
            'running': True,
            'started_at': time.time(),
            'iface': iface,
            'bpf': bpf,
            'use_nfstream': bool(use_nfstream and NFSTREAM_AVAILABLE),
            'flow_timeout': flow_timeout,
        })
        if use_nfstream and NFSTREAM_AVAILABLE:
            log.info("Starting NFStream-based capture")
            _nf_thread = threading.Thread(
                target=_run_nfstream,
                kwargs={'interface': iface, 'flow_timeout': flow_timeout},
                daemon=True
            )
            _nf_thread.start()
            return
        # fallback to scapy
        if not SCAPY_AVAILABLE:
            log.error("Scapy is not available; cannot start AsyncSniffer")
            _status['running'] = False
            return
        try:
            _sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_on_packet, store=False)
            _sniffer.start()
            log.info("AsyncSniffer started on iface=%s with bpf=%s", iface, bpf)
        except Exception:
            log.exception("Failed to start AsyncSniffer")
            _sniffer = None
            _status['running'] = False

def stop_capture():
    """Stop any running capture (scapy or nfstream)"""
    global _sniffer, _nf_thread, _nf_stop
    with _sniffer_lock:
        if _sniffer:
            try:
                _sniffer.stop()
            except Exception:
                pass
            _sniffer = None
        # stop NFStream
        _nf_stop = True
        if _nf_thread is not None:
            try:
                _nf_thread.join(timeout=2)
            except Exception:
                pass
            _nf_thread = None
        stop_streaming()
        _status.update({
            'running': False,
            'stopped_at': time.time(),
        })
        log.info("Capture stopped")

def is_running() -> bool:
    with _sniffer_lock:
        if _sniffer and getattr(_sniffer, 'running', False):
            return True
        if _nf_thread and _nf_thread.is_alive():
            return True
    return False

def get_status():
    """Return current capture status snapshot."""
    status = _status.copy()
    status['running'] = is_running()
    status['nfstream_available'] = NFSTREAM_AVAILABLE
    status['interfaces'] = list_ifaces()
    return status
