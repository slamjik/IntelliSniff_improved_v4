import logging, threading, time
import socket
from typing import Iterable, Optional
import psutil

from .streaming import handle_packet, init_streaming, stop_streaming
from .nfstream_helper import NFSTREAM_AVAILABLE, make_streamer, iterate_flows_from_streamer

log = logging.getLogger('ta.capture')

try:
    from scapy.all import AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

_sniffer = None
_sniffers = []  # список для мульти-захвата
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

_VIRTUAL_KEYWORDS = (
    "loopback", "virtual", "vmware", "hyper-v", "docker", "br-", "veth",
    "tap", "tun", "pseudo", "awdl", "nflog", "nfqueue", "ppp"
)


def _filter_interfaces(candidates: Iterable[str]) -> list[str]:
    seen = set()
    filtered = []
    for name in candidates:
        if not name:
            continue
        lowered = name.lower()
        if lowered in {"lo", "lo0"}:
            continue
        if any(keyword in lowered for keyword in _VIRTUAL_KEYWORDS):
            continue
        if name not in seen:
            filtered.append(name)
            seen.add(name)
    return filtered


def list_ifaces():
    """Return available interfaces with IPs and add 'All interfaces' option."""
    candidates = []
    if SCAPY_AVAILABLE:
        try:
            candidates.extend(get_if_list())
        except Exception:
            pass
    if not candidates:
        try:
            candidates.extend(name for _, name in socket.if_nameindex())
        except Exception:
            pass

    filtered = _filter_interfaces(candidates)

    # добавим IP для каждого интерфейса, если можем
    try:
        addrs = psutil.net_if_addrs()
        named = []
        for iface in filtered:
            ips = [
                snic.address
                for snic in addrs.get(iface, [])
                if snic.family == socket.AF_INET
            ]
            if not ips:
                continue  # пропускаем интерфейсы без IP
            label = f"{iface} ({ips[0]})"
            named.append(label)
        named.insert(0, "All interfaces")
        return named
    except Exception:
        filtered.insert(0, "All interfaces")
        return filtered


def _normalize_iface_for_capture(label: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (display_label, capture_name) for provided interface label."""
    if label is None:
        return None, None
    label = label.strip()
    if not label:
        return "", None
    if label == "All interfaces":
        return label, label
    base = label.split(' ')[0]
    return label, base


def _call_if_callable(value):
    if callable(value):
        try:
            return value()
        except Exception:
            return None
    return value


def _pkt_to_dict(pkt):
    """Normalize scapy packet or dict-like flow into expected dict for handle_packet."""
    if pkt is None:
        return None
    if isinstance(pkt, dict):
        return pkt
    try:
        def g(attr_name, fallback=None):
            value = getattr(pkt, attr_name, fallback)
            return _call_if_callable(value)

        src = g('src') or g('src_ip')
        dst = g('dst') or g('dst_ip')
        sport = g('sport') or g('src_port')
        dport = g('dport') or g('dst_port')
        proto = g('proto') or g('proto')
        ts = g('time')
        length = g('len') or g('length') or g('__len__')
        iface = g('sniffed_on') or g('iface')

        def to_int(val):
            if val is None:
                return None
            if callable(val):
                return to_int(_call_if_callable(val))
            if isinstance(val, bool):
                return int(val)
            if isinstance(val, (int, float)):
                return int(val)
            try:
                return int(str(val).strip())
            except Exception:
                return None

        def to_str(val):
            if val is None:
                return None
            if isinstance(val, (bytes, bytearray)):
                try:
                    return val.decode('utf-8', errors='ignore')
                except Exception:
                    return str(val)
            return str(val)

        return {
            'ts': float(ts) if ts is not None else None,
            'src': to_str(src) if src is not None else None,
            'dst': to_str(dst) if dst is not None else None,
            'sport': to_int(sport),
            'dport': to_int(dport),
            'proto': to_str(proto) if proto is not None else None,
            'bytes': to_int(length),
            'iface': to_str(iface) if iface else None,
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
    """Start packet capture. Supports 'All interfaces' or auto-detection."""
    global _sniffer, _sniffers, _nf_thread, _nf_stop
    with _sniffer_lock:
        if _sniffer or _sniffers or (_nf_thread and _nf_thread.is_alive()):
            log.warning("Capture already running")
            return

        # Если iface не задан — выбираем первый активный
        if not iface or iface.strip() == "" or iface.lower() == "auto":
            all_ifaces = list_ifaces()
            if not all_ifaces:
                log.error("No interfaces found for auto mode.")
                return
            # пропускаем пункт All interfaces
            iface = next((i for i in all_ifaces if i != "All interfaces"), all_ifaces[0])
            log.info(f"Auto-selected interface: {iface}")

        display_iface, capture_iface = _normalize_iface_for_capture(iface)

        init_streaming(flow_timeout=flow_timeout)
        _status.update({
            'running': True,
            'started_at': time.time(),
            'iface': display_iface,
            'bpf': bpf,
            'use_nfstream': bool(use_nfstream and NFSTREAM_AVAILABLE),
            'flow_timeout': flow_timeout,
        })

        if not capture_iface and display_iface != "All interfaces":
            log.error("No valid interface resolved for capture")
            _status['running'] = False
            return

        # "All interfaces" → множественный захват
        if display_iface == "All interfaces":
            _sniffers = []
            for ifname in list_ifaces():
                if ifname == "All interfaces":
                    continue
                try:
                    base_name = ifname.split(' ')[0]
                    sniffer = AsyncSniffer(iface=base_name, filter=bpf, prn=_on_packet, store=False)
                    sniffer.start()
                    _sniffers.append(sniffer)
                    log.info(f"Started sniffer on {ifname}")
                except Exception:
                    log.exception(f"Failed to start sniffer on {ifname}")
            return

        # NFStream вариант
        if use_nfstream and NFSTREAM_AVAILABLE:
            log.info("Starting NFStream-based capture")
            _nf_thread = threading.Thread(
                target=_run_nfstream,
                kwargs={'interface': capture_iface, 'flow_timeout': flow_timeout},
                daemon=True
            )
            _nf_thread.start()
            return

        # Scapy fallback
        if not SCAPY_AVAILABLE:
            log.error("Scapy is not available; cannot start AsyncSniffer")
            _status['running'] = False
            return
        try:
            base_name = capture_iface.split(' ')[0] if capture_iface else None
            _sniffer = AsyncSniffer(iface=base_name, filter=bpf, prn=_on_packet, store=False)
            _sniffer.start()
            log.info(f"AsyncSniffer started on iface={base_name}")
        except Exception:
            log.exception("Failed to start AsyncSniffer")
            _sniffer = None
            _status['running'] = False



def stop_capture():
    """Stop all running captures (scapy or nfstream)."""
    global _sniffer, _sniffers, _nf_thread, _nf_stop
    with _sniffer_lock:
        if _sniffer:
            try:
                _sniffer.stop()
            except Exception:
                pass
            _sniffer = None

        if _sniffers:
            for s in _sniffers:
                try:
                    s.stop()
                except Exception:
                    pass
            _sniffers.clear()

        _nf_stop = True
        if _nf_thread:
            try:
                _nf_thread.join(timeout=2)
            except Exception:
                pass
            _nf_thread = None

        stop_streaming()
        _status.update({'running': False, 'stopped_at': time.time()})
        log.info("All captures stopped")


def is_running() -> bool:
    with _sniffer_lock:
        if _sniffer and getattr(_sniffer, 'running', False):
            return True
        if any(getattr(s, 'running', False) for s in _sniffers):
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
