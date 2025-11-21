from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Iterable, Optional

import psutil

from .nfstream_helper import NFSTREAM_AVAILABLE, iterate_flows_from_streamer, make_streamer
from .session_bridge import finish_capture_session, log_capture_event, start_capture_session
from .streaming import Flow, FlowKey, _emit_flow, _flows, _normalise_flow_key, handle_packet, init_streaming, stop_streaming

log = logging.getLogger("ta.capture")

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
    "running": False,
    "started_at": None,
    "iface": None,
    "bpf": None,
    "use_nfstream": False,
    "flow_timeout": 30.0,
}

_VIRTUAL_KEYWORDS = (
    "loopback",
    "virtual",
    "vmware",
    "hyper-v",
    "docker",
    "br-",
    "veth",
    "tap",
    "tun",
    "pseudo",
    "awdl",
    "nflog",
    "nfqueue",
    "ppp",
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
            ips = [snic.address for snic in addrs.get(iface, []) if snic.family == socket.AF_INET]
            label = f"{iface} ({ips[0]})" if ips else f"{iface} (no IP)"
            named.append(label)
    except Exception:
        named = filtered

    named.insert(0, "All interfaces")
    named.insert(0, "Auto")
    return named


def _normalize_iface_for_capture(label: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if label is None:
        return None, None
    label = label.strip()
    if not label:
        return "", None
    if label == "All interfaces":
        return label, label
    base = label.split(" ")[0]
    return label, base


def _call_if_callable(value):
    if callable(value):
        try:
            return value()
        except Exception:
            return None
    return value


def _pkt_to_dict(pkt):
    if pkt is None:
        return None
    if isinstance(pkt, dict):
        return pkt
    try:
        def g(attr, fb=None):
            v = getattr(pkt, attr, fb)
            return _call_if_callable(v)

        src = g("src") or g("src_ip")
        dst = g("dst") or g("dst_ip")
        sport = g("sport") or g("src_port")
        dport = g("dport") or g("dst_port")
        proto = g("proto")
        ts = g("time")
        length = g("len") or g("length") or g("__len__")
        iface = g("sniffed_on") or g("iface")

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
                    return x.decode("utf-8", errors="ignore")
                except Exception:
                    return str(x)
            return str(x)

        return {
            "ts": float(ts) if ts is not None else None,
            "src": to_str(src),
            "dst": to_str(dst),
            "sport": to_int(sport),
            "dport": to_int(dport),
            "proto": to_str(proto),
            "bytes": to_int(length),
            "iface": to_str(iface),
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
# NFSTREAM — PREDICTOR-COMPATIBLE INTEGRATION
# =============================================================================

def _get_attr(obj, names, default=0.0):
    for name in names:
        if hasattr(obj, name):
            try:
                return getattr(obj, name)
            except Exception:
                continue
    return default


def _seed_stats(stats_obj, count: float, mean: float, std: float = 0.0, min_v: Optional[float] = None, max_v: Optional[float] = None):
    count = max(0, int(count))
    mean = float(mean or 0.0)
    std = float(std or 0.0)
    stats_obj.count = count
    stats_obj._sum = mean * count
    stats_obj._sum_sq = (std ** 2 + mean ** 2) * count
    stats_obj._min = mean if min_v is None else float(min_v)
    stats_obj._max = mean if max_v is None else float(max_v)


def _extract_iat_tuple(nf_flow, prefix: str, fallback_mean: float, fallback_count: float) -> tuple[float, float, float, float]:
    mean = _get_attr(
        nf_flow,
        [f"{prefix}_iat_mean", f"{prefix}_mean_interarrival_time", f"{prefix}_interarrival_mean"],
        default=fallback_mean,
    )
    std = _get_attr(
        nf_flow,
        [f"{prefix}_iat_std", f"{prefix}_std_interarrival_time", f"{prefix}_interarrival_std"],
        default=0.0,
    )
    min_v = _get_attr(nf_flow, [f"{prefix}_iat_min", f"{prefix}_min_interarrival_time"], default=mean)
    max_v = _get_attr(nf_flow, [f"{prefix}_iat_max", f"{prefix}_max_interarrival_time"], default=mean)

    if fallback_count <= 1:
        return (0.0, 0.0, 0.0, 0.0)

    return (float(mean or fallback_mean), float(std or 0.0), float(min_v or mean), float(max_v or mean))


def _process_nfstream_flow(nf_flow, iface_name):
    key, _ = _normalise_flow_key(
        getattr(nf_flow, "src_ip", None),
        getattr(nf_flow, "dst_ip", None),
        getattr(nf_flow, "src_port", None),
        getattr(nf_flow, "dst_port", None),
        str(getattr(nf_flow, "protocol", "")).upper(),
    )

    ts_first = _get_attr(nf_flow, ["bidirectional_first_seen_ms", "first_seen_ms"], default=time.time() * 1000) / 1000.0
    ts_last = _get_attr(nf_flow, ["bidirectional_last_seen_ms", "last_seen_ms"], default=ts_first * 1000) / 1000.0
    duration = max(0.0, ts_last - ts_first)

    total_packets = float(_get_attr(nf_flow, ["bidirectional_packets", "packets", "n_packets"], default=0.0))
    total_bytes = float(_get_attr(nf_flow, ["bidirectional_bytes", "bytes", "n_bytes"], default=0.0))

    fwd_packets = float(_get_attr(nf_flow, ["src2dst_packets", "fwd_packets"], default=0.0))
    bwd_packets = float(_get_attr(nf_flow, ["dst2src_packets", "bwd_packets"], default=0.0))
    if total_packets and fwd_packets == 0 and bwd_packets == 0:
        fwd_packets = total_packets / 2.0
        bwd_packets = total_packets - fwd_packets

    fwd_bytes = float(_get_attr(nf_flow, ["src2dst_bytes", "fwd_bytes"], default=0.0))
    bwd_bytes = float(_get_attr(nf_flow, ["dst2src_bytes", "bwd_bytes"], default=0.0))
    if total_bytes and fwd_bytes == 0 and bwd_bytes == 0:
        fwd_bytes = total_bytes / 2.0
        bwd_bytes = total_bytes - fwd_bytes

    f = _flows.get(key)
    if not f:
        f = Flow(ts_first, key, iface=iface_name)
        _flows[key] = f

    f.first_ts = ts_first
    f.last_ts = ts_last
    f.packets = int(total_packets)
    f.bytes = int(total_bytes)
    f.fwd_packets = int(fwd_packets)
    f.bwd_packets = int(bwd_packets)
    f.fwd_bytes = int(fwd_bytes)
    f.bwd_bytes = int(bwd_bytes)

    # Packet length stats
    def _length_stats(prefix, total_b, pkt_count):
        mean_v = _get_attr(nf_flow, [f"{prefix}_pkt_len_mean", f"{prefix}_packet_length_mean"], default=0.0)
        max_v = _get_attr(nf_flow, [f"{prefix}_pkt_len_max", f"{prefix}_packet_length_max"], default=0.0)
        min_v = _get_attr(nf_flow, [f"{prefix}_pkt_len_min", f"{prefix}_packet_length_min"], default=0.0)
        std_v = _get_attr(nf_flow, [f"{prefix}_pkt_len_std", f"{prefix}_packet_length_std"], default=0.0)
        if pkt_count > 0 and mean_v == 0:
            mean_v = total_b / pkt_count
        if max_v == 0:
            max_v = mean_v
        if min_v == 0:
            min_v = mean_v
        return mean_v, std_v, min_v, max_v

    avg_len = total_bytes / total_packets if total_packets > 0 else 0.0
    mean_all = _get_attr(nf_flow, ["bidirectional_pkt_len_mean", "pkt_len_mean"], default=avg_len)
    std_all = _get_attr(nf_flow, ["bidirectional_pkt_len_std", "pkt_len_std"], default=0.0)
    min_all = _get_attr(nf_flow, ["bidirectional_pkt_len_min", "pkt_len_min"], default=mean_all)
    max_all = _get_attr(nf_flow, ["bidirectional_pkt_len_max", "pkt_len_max"], default=mean_all)

    fwd_mean, fwd_std, fwd_min, fwd_max = _length_stats("src2dst", fwd_bytes, fwd_packets)
    bwd_mean, bwd_std, bwd_min, bwd_max = _length_stats("dst2src", bwd_bytes, bwd_packets)

    _seed_stats(f.packet_stats, total_packets, mean_all or avg_len, std_all, min_all, max_all)
    _seed_stats(f.fwd_packet_stats, fwd_packets, fwd_mean, fwd_std, fwd_min, fwd_max)
    _seed_stats(f.bwd_packet_stats, bwd_packets, bwd_mean, bwd_std, bwd_min, bwd_max)

    # IAT stats approximated from duration
    def _fallback_iat(pkt_count):
        if pkt_count <= 1 or duration <= 0:
            return (0.0, 0.0, 0.0, 0.0)
        mean_iat = duration / (pkt_count - 1)
        return mean_iat, 0.0, mean_iat, mean_iat

    flow_mean, flow_std, flow_min, flow_max = _extract_iat_tuple(
        nf_flow,
        "bidirectional",
        fallback_mean=_fallback_iat(total_packets)[0],
        fallback_count=total_packets,
    )
    if flow_mean == flow_std == flow_min == flow_max == 0.0:
        flow_mean, flow_std, flow_min, flow_max = _fallback_iat(total_packets)

    fwd_mean_iat, fwd_std_iat, fwd_min_iat, fwd_max_iat = _extract_iat_tuple(
        nf_flow,
        "src2dst",
        fallback_mean=_fallback_iat(fwd_packets)[0],
        fallback_count=fwd_packets,
    )
    if fwd_mean_iat == fwd_std_iat == fwd_min_iat == fwd_max_iat == 0.0:
        fwd_mean_iat, fwd_std_iat, fwd_min_iat, fwd_max_iat = _fallback_iat(fwd_packets)

    bwd_mean_iat, bwd_std_iat, bwd_min_iat, bwd_max_iat = _extract_iat_tuple(
        nf_flow,
        "dst2src",
        fallback_mean=_fallback_iat(bwd_packets)[0],
        fallback_count=bwd_packets,
    )
    if bwd_mean_iat == bwd_std_iat == bwd_min_iat == bwd_max_iat == 0.0:
        bwd_mean_iat, bwd_std_iat, bwd_min_iat, bwd_max_iat = _fallback_iat(bwd_packets)

    _seed_stats(f.flow_iat_stats, max(total_packets - 1, 0), flow_mean, flow_std, flow_min, flow_max)
    _seed_stats(f.fwd_iat_stats, max(fwd_packets - 1, 0), fwd_mean_iat, fwd_std_iat, fwd_min_iat, fwd_max_iat)
    _seed_stats(f.bwd_iat_stats, max(bwd_packets - 1, 0), bwd_mean_iat, bwd_std_iat, bwd_min_iat, bwd_max_iat)

    # Save DPI-like metadata
    f.extra.update(
        {
            "tls_sni": getattr(nf_flow, "tls_sni", None),
            "http_host": getattr(nf_flow, "http_host", None),
            "dns_query": getattr(nf_flow, "dns_qry_name", None),
            "application_name": getattr(nf_flow, "application_name", None),
        }
    )

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
        already_running = bool(_sniffer or _sniffers or (_nf_thread and _nf_thread.is_alive()))
    if already_running:
        log.warning("Capture already running, forcing previous session stop")
        stop_capture(result="forced_stop")

    if not iface or iface.strip() == "" or iface.lower() == "auto":
        all_ifaces = list_ifaces()
        if not all_ifaces:
            log.error("No interfaces found for auto mode.")
            return
        iface = next((i for i in all_ifaces if i != "All interfaces"), all_ifaces[0])
        log.info(f"Auto-selected: {iface}")

    display_iface, capture_iface = _normalize_iface_for_capture(iface)

    init_streaming(flow_timeout=flow_timeout)
    start_capture_session(
        details={
            "mode": "capture",
            "iface": display_iface,
            "bpf": bpf,
            "use_nfstream": bool(use_nfstream and NFSTREAM_AVAILABLE),
        }
    )

    _status.update(
        {
            "running": True,
            "started_at": time.time(),
            "iface": display_iface,
            "bpf": bpf,
            "use_nfstream": bool(use_nfstream and NFSTREAM_AVAILABLE),
            "flow_timeout": flow_timeout,
        }
    )

    if display_iface == "All interfaces":
        _sniffers.clear()
        for name in list_ifaces():
            if name == "All interfaces":
                continue
            try:
                base = name.split(" ")[0]
                sniffer = AsyncSniffer(iface=base, filter=bpf, prn=_on_packet, store=False)
                sniffer.start()
                _sniffers.append(sniffer)
                log_capture_event("sniffer_started", {"iface": base})
            except Exception:
                log.exception(f"Failed to start sniffer on {name}")
        return

    if use_nfstream and NFSTREAM_AVAILABLE:
        log.info(f"Starting NFStream capture on {capture_iface}")
        log_capture_event("nfstream_started", {"iface": capture_iface, "bpf": bpf})
        _nf_thread = threading.Thread(target=_run_nfstream, kwargs={"interface": capture_iface, "flow_timeout": flow_timeout}, daemon=True)
        _nf_thread.start()
        return

    if not SCAPY_AVAILABLE:
        log.error("Scapy is not available.")
        _status["running"] = False
        return
    try:
        sniffer = AsyncSniffer(iface=capture_iface, filter=bpf, prn=_on_packet, store=False)
        sniffer.start()
        _sniffer = sniffer
        log_capture_event("scapy_started", {"iface": capture_iface, "bpf": bpf})
        log.info(f"AsyncSniffer started on {capture_iface}")
    except Exception:
        log.exception("Failed to start AsyncSniffer")
        _sniffer = None
        _status["running"] = False


def stop_capture(result: str = "success"):
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
        _status.update({"running": False, "stopped_at": time.time()})

    try:
        finish_capture_session(result=result)
    except Exception:
        log.warning("Failed to finish capture session", exc_info=True)
    log.info("All captures stopped")


def is_running():
    with _sniffer_lock:
        if _sniffer and getattr(_sniffer, "running", False):
            return True
        if any(getattr(s, "running", False) for s in _sniffers):
            return True
        if _nf_thread and _nf_thread.is_alive():
            return True
    return False


def get_status():
    st = _status.copy()
    st["running"] = is_running()
    st["nfstream_available"] = NFSTREAM_AVAILABLE
    st["interfaces"] = list_ifaces()
    return st
