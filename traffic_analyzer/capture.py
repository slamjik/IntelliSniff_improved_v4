from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Iterable, Optional

import psutil

from .streaming import (
    Flow,
    FlowKey,
    _emit_flow,
    _flows,
    _normalise_flow_key,
    handle_packet,
    init_streaming,
    stop_streaming,
)

from .nfstream_helper import (
    NFSTREAM_AVAILABLE,
    make_streamer,
    iterate_flows_from_streamer,
)


log = logging.getLogger('ta.capture')

try:
    from scapy.all import AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


_sniffer = None
_sniffers = []
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

# =============================================================================
# HELPERS
# =============================================================================

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
    """Return available interfaces and add Auto + All interfaces."""
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

    named = []
    try:
        addrs = psutil.net_if_addrs()
        for iface in filtered:
            ips = [
                snic.address
                for snic in addrs.get(iface, [])
                if snic.family == socket.AF_INET
            ]
            label = f"{iface} ({ips[0]})" if ips else f"{iface} (no IP)"
            named.append(label)
    except Exception:
        named = filtered

    named.insert(0, "All interfaces")
    named.insert(0, "Auto")
    return named


def _normalize_iface_for_capture(label: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return (display label, capture name)."""
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
    """Convert scapy packet to unified dict for handle_packet."""
    if pkt is None:
        return None
    if isinstance(pkt, dict):
        return pkt
    try:
        def g(attr, fb=None):
            v = getattr(pkt, attr, fb)
            return _call_if_callable(v)

        src = g('src') or g('src_ip')
        dst = g('dst') or g('dst_ip')
        sport = g('sport') or g('src_port')
        dport = g('dport') or g('dst_port')
        proto = g('proto')
        ts = g('time')
        length = g('len') or g('length') or g('__len__')
        iface = g('sniffed_on') or g('iface')

        def to_int(x):
            if x is None:
                return None
            if callable(x):
                return to_int(_call_if_callable(x))
            if isinstance(x, (int, float)):
                return int(x)
            try:
                return int(str(x).strip())
            except Exception:
                return None

        def to_str(x):
            if x is None:
                return None
            if isinstance(x, (bytes, bytearray)):
                try:
                    return x.decode('utf-8', errors='ignore')
                except Exception:
                    return str(x)
            return str(x)

        return {
            'ts': float(ts) if ts is not None else None,
            'src': to_str(src),
            'dst': to_str(dst),
            'sport': to_int(sport),
            'dport': to_int(dport),
            'proto': to_str(proto),
            'bytes': to_int(length),
            'iface': to_str(iface),
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


# =============================================================================
# NFSTREAM — ПРАВИЛЬНАЯ ИНТЕГРАЦИЯ
# =============================================================================

def _process_nfstream_flow(nf_flow, iface_name):
    """
    Корректно переносит NFStream flow в наш Flow так,
    чтобы duration/packets/bytes/IAT и т.п. были настоящими.
    """
    key, _ = _normalise_flow_key(
        nf_flow.src_ip,
        nf_flow.dst_ip,
        nf_flow.src_port,
        nf_flow.dst_port,
        str(getattr(nf_flow, "protocol", "")).upper(),
    )

    ts_first = nf_flow.bidirectional_first_seen_ms / 1000.0
    ts_last = nf_flow.bidirectional_last_seen_ms / 1000.0

    f = _flows.get(key)
    if not f:
        f = Flow(ts_first, key, iface=iface_name)
        _flows[key] = f

    f.first_ts = ts_first
    f.last_ts = ts_last

    f.packets = nf_flow.packets
    f.bytes = nf_flow.bytes

    f.fwd_packets = nf_flow.fwd_packets
    f.bwd_packets = nf_flow.bwd_packets
    f.fwd_bytes = nf_flow.fwd_bytes
    f.bwd_bytes = nf_flow.bwd_bytes

    duration = max(0.001, ts_last - ts_first)

    avg_pkt_size = nf_flow.bytes / max(1, nf_flow.packets)
    flow_iat = duration / max(1, nf_flow.packets - 1)

    def _seed_stats(stats_obj, count, mean_value):
        count = int(max(0, count))
        if count <= 0:
            stats_obj.count = 0
            stats_obj._sum = 0.0
            stats_obj._sum_sq = 0.0
            stats_obj._min = None
            stats_obj._max = None
            return
        stats_obj.count = count
        stats_obj._sum = float(mean_value) * count
        stats_obj._sum_sq = float(mean_value) * float(mean_value) * count
        stats_obj._min = float(mean_value)
        stats_obj._max = float(mean_value)

    _seed_stats(f.packet_stats, nf_flow.packets, avg_pkt_size)
    _seed_stats(f.flow_iat_stats, max(0, nf_flow.packets - 1), flow_iat)

    fwd_avg = nf_flow.fwd_bytes / max(1, nf_flow.fwd_packets)
    bwd_avg = nf_flow.bwd_bytes / max(1, nf_flow.bwd_packets)
    _seed_stats(f.fwd_packet_stats, nf_flow.fwd_packets, fwd_avg)
    _seed_stats(f.bwd_packet_stats, nf_flow.bwd_packets, bwd_avg)

    fwd_iat = duration / max(1, nf_flow.fwd_packets - 1)
    bwd_iat = duration / max(1, nf_flow.bwd_packets - 1)
    _seed_stats(f.fwd_iat_stats, max(0, nf_flow.fwd_packets - 1), fwd_iat)
    _seed_stats(f.bwd_iat_stats, max(0, nf_flow.bwd_packets - 1), bwd_iat)

    # Сохраняем метаданные (TLS, HTTP, DNS)
    f.extra.update({
        "tls_sni": getattr(nf_flow, "tls_sni", None),
        "http_host": getattr(nf_flow, "http_host", None),
        "dns_query": getattr(nf_flow, "dns_qry_name", None),
        "application_name": getattr(nf_flow, "application_name", None),
    })

    # Флоу полностью собран → отправляем в ML
    _emit_flow(key)


def _run_nfstream(interface, pcap=None, flow_timeout=30.0):
    global _nf_stop
    _nf_stop = False

    streamer = make_streamer(interface=interface, pcap=pcap)
    if not streamer:
        log.error("NFStream is requested but not available.")
        return

    for flow in iterate_flows_from_streamer(streamer):
        if _nf_stop:
            break
        try:
            _process_nfstream_flow(flow, iface_name=interface)
        except Exception:
            log.exception("Failed to process NFStream flow")

    try:
        streamer.stop()
    except Exception:
        pass


# =============================================================================
# START / STOP
# =============================================================================

def start_capture(iface=None, bpf=None, flow_timeout=30.0, use_nfstream=False):
    global _sniffer, _sniffers, _nf_thread, _nf_stop
    with _sniffer_lock:
        if _sniffer or _sniffers or (_nf_thread and _nf_thread.is_alive()):
            log.warning("Capture already running")
            return

        # Auto detect
        if not iface or iface.strip() == "" or iface.lower() == "auto":
            all_ifaces = list_ifaces()
            if not all_ifaces:
                log.error("No interfaces found for auto mode.")
                return
            iface = next((i for i in all_ifaces if i != "All interfaces"), all_ifaces[0])
            log.info(f"Auto-selected: {iface}")

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

        if display_iface == "All interfaces":
            _sniffers = []
            for name in list_ifaces():
                if name == "All interfaces":
                    continue
                try:
                    base = name.split(" ")[0]
                    sniffer = AsyncSniffer(iface=base, filter=bpf, prn=_on_packet, store=False)
                    sniffer.start()
                    _sniffers.append(sniffer)
                except Exception:
                    log.exception(f"Failed to start sniffer on {name}")
            return

        # NFSTREAM mode
        if use_nfstream and NFSTREAM_AVAILABLE:
            log.info(f"Starting NFStream capture on {capture_iface}")
            _nf_thread = threading.Thread(
                target=_run_nfstream,
                kwargs={'interface': capture_iface, 'flow_timeout': flow_timeout},
                daemon=True,
            )
            _nf_thread.start()
            return

        # SCAPY fallback
        if not SCAPY_AVAILABLE:
            log.error("Scapy is not available.")
            _status['running'] = False
            return
        try:
            sniffer = AsyncSniffer(iface=capture_iface, filter=bpf, prn=_on_packet, store=False)
            sniffer.start()
            _sniffer = sniffer
            log.info(f"AsyncSniffer started on {capture_iface}")
        except Exception:
            log.exception("Failed to start AsyncSniffer")
            _sniffer = None
            _status['running'] = False


def stop_capture():
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


def is_running():
    with _sniffer_lock:
        if _sniffer and getattr(_sniffer, 'running', False):
            return True
        if any(getattr(s, 'running', False) for s in _sniffers):
            return True
        if _nf_thread and _nf_thread.is_alive():
            return True
    return False


def get_status():
    st = _status.copy()
    st['running'] = is_running()
    st['nfstream_available'] = NFSTREAM_AVAILABLE
    st['interfaces'] = list_ifaces()
    return st
