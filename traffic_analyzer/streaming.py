import logging
import math
import time
import threading
from collections import namedtuple
from typing import Dict, Optional

from .features import extract_features_from_flow
from traffic_analyzer.flow_logger import save_flow
from .ml_runtime import get_predictor, get_model_manager
from .event_bus import publish

log = logging.getLogger('ta.streaming')
FlowKey = namedtuple('FlowKey', ['src', 'dst', 'sport', 'dport', 'proto'])


class _RunningStats:
    """Simple helper to accumulate statistics without storing raw values."""

    __slots__ = ("count", "_sum", "_sum_sq", "_min", "_max")

    def __init__(self):
        self.count = 0
        self._sum = 0.0
        self._sum_sq = 0.0
        self._min = None
        self._max = None

    def update(self, value: float) -> None:
        value = float(value or 0.0)
        self.count += 1
        self._sum += value
        self._sum_sq += value * value
        if self._min is None or value < self._min:
            self._min = value
        if self._max is None or value > self._max:
            self._max = value

    @property
    def total(self) -> float:
        return self._sum

    @property
    def mean(self) -> float:
        if self.count == 0:
            return 0.0
        return self._sum / float(self.count)

    @property
    def variance(self) -> float:
        if self.count <= 1:
            return 0.0
        mean = self.mean
        return max(0.0, (self._sum_sq / float(self.count)) - mean * mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def min(self) -> float:
        return 0.0 if self._min is None else float(self._min)

    @property
    def max(self) -> float:
        return 0.0 if self._max is None else float(self._max)


# === Класс потока ============================================================
class Flow:
    def __init__(self, ts: float, key: FlowKey, iface: Optional[str] = None):
        ts = float(ts or time.time())
        self.first_ts = ts
        self.last_ts = ts
        self.packets = 0
        self.bytes = 0
        self.iface = iface or '-'
        self.extra: Dict[str, Optional[str]] = {}
        self.key = key

        # direction counters
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        # statistics
        self.packet_stats = _RunningStats()
        self.fwd_packet_stats = _RunningStats()
        self.bwd_packet_stats = _RunningStats()

        self.flow_iat_stats = _RunningStats()
        self.fwd_iat_stats = _RunningStats()
        self.bwd_iat_stats = _RunningStats()

        # timestamps for IAT
        self._prev_ts = None
        self._prev_fwd_ts = None
        self._prev_bwd_ts = None

    @property
    def src(self):
        return self.key.src

    @property
    def dst(self):
        return self.key.dst

    @property
    def sport(self):
        return self.key.sport

    @property
    def dport(self):
        return self.key.dport

    @property
    def proto(self):
        return self.key.proto

    # ----------------- UPDATE PACKET -------------------------
    def update(self, ts: float, pkt_len: int, pkt_dict: Dict, is_forward: bool):
        self.last_ts = max(self.last_ts, ts)
        pkt_len = max(0, int(pkt_len or 0))

        self.packets += 1
        self.bytes += pkt_len

        if pkt_len > 0:
            self.packet_stats.update(pkt_len)
            if is_forward:
                self.fwd_packet_stats.update(pkt_len)
            else:
                self.bwd_packet_stats.update(pkt_len)

        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
            if self._prev_fwd_ts is not None:
                self.fwd_iat_stats.update(ts - self._prev_fwd_ts)
            self._prev_fwd_ts = ts
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len
            if self._prev_bwd_ts is not None:
                self.bwd_iat_stats.update(ts - self._prev_bwd_ts)
            self._prev_bwd_ts = ts

        if self._prev_ts is not None:
            self.flow_iat_stats.update(ts - self._prev_ts)
        self._prev_ts = ts

        # DPI / metadata
        for field in ('tls_sni', 'http_host', 'dns_query'):
            value = pkt_dict.get(field)
            if value:
                self.extra[field] = value

        if pkt_dict.get('application_name'):
            self.extra['app'] = pkt_dict.get('application_name')

        if pkt_dict.get('iface') and self.iface == '-':
            self.iface = pkt_dict.get('iface')

    # ----------------- COMPUTE BASE FEATURES ------------------
    def _to_feature_input(self) -> Dict[str, float]:
        duration = max(0.0, self.last_ts - self.first_ts)
        packets = float(self.packets)
        bytes_total = float(self.bytes)

        def _safe(num, den): return num / den if den else 0.0

        pkts_per_s = _safe(packets, duration) if duration else packets
        bytes_per_s = _safe(bytes_total, duration) if duration else bytes_total
        avg_pkt_size = _safe(bytes_total, packets)

        down_up_ratio = _safe(self.bwd_bytes, self.fwd_bytes)

        feature_input = {
            'protocol': self._proto_to_number(self.proto),
            'proto': self.proto,
            'flow_duration': duration,

            'total_fwd_packets': float(self.fwd_packets),
            'total_bwd_packets': float(self.bwd_packets),
            'fwd_packets_length_total': float(self.fwd_bytes),
            'bwd_packets_length_total': float(self.bwd_bytes),

            'fwd_packet_length_max': self.fwd_packet_stats.max,
            'fwd_packet_length_min': self.fwd_packet_stats.min,
            'fwd_packet_length_mean': self.fwd_packet_stats.mean,
            'fwd_packet_length_std': self.fwd_packet_stats.std,

            'bwd_packet_length_max': self.bwd_packet_stats.max,
            'bwd_packet_length_min': self.bwd_packet_stats.min,
            'bwd_packet_length_mean': self.bwd_packet_stats.mean,
            'bwd_packet_length_std': self.bwd_packet_stats.std,

            'flow_bytes_per_s': bytes_per_s,
            'flow_packets_per_s': pkts_per_s,

            'flow_iat_mean': self.flow_iat_stats.mean,
            'flow_iat_std': self.flow_iat_stats.std,
            'flow_iat_max': self.flow_iat_stats.max,
            'flow_iat_min': self.flow_iat_stats.min,

            'fwd_iat_total': self.fwd_iat_stats.total,
            'fwd_iat_mean': self.fwd_iat_stats.mean,
            'fwd_iat_std': self.fwd_iat_stats.std,
            'fwd_iat_max': self.fwd_iat_stats.max,
            'fwd_iat_min': self.fwd_iat_stats.min,

            'bwd_iat_total': self.bwd_iat_stats.total,
            'bwd_iat_mean': self.bwd_iat_stats.mean,
            'bwd_iat_std': self.bwd_iat_stats.std,
            'bwd_iat_max': self.bwd_iat_stats.max,
            'bwd_iat_min': self.bwd_iat_stats.min,

            'down_up_ratio': down_up_ratio,

            'packet_length_min': self.packet_stats.min,
            'packet_length_max': self.packet_stats.max,
            'packet_length_mean': self.packet_stats.mean,
            'packet_length_std': self.packet_stats.std,
            'packet_length_variance': self.packet_stats.variance,

            'avg_packet_size': avg_pkt_size,

            'destination_port': float(self.dport or 0),
            'source_port': float(self.sport or 0),

            'packets': packets,
            'bytes': bytes_total,
            'pkts_per_s': pkts_per_s,
            'bytes_per_s': bytes_per_s,
            'avg_pkt_size': avg_pkt_size,
        }

        return feature_input

    # ----------------- FINAL FEATURE VECTOR -------------------
    def metrics(self) -> Dict[str, float]:
        feature_input = self._to_feature_input()
        features = extract_features_from_flow(feature_input)

        for k, v in self.extra.items():
            if v:
                features[k] = v

        return features

    # ----------------- PROTOCOL MAP ---------------------------
    @staticmethod
    def _proto_to_number(proto: Optional[str]) -> float:
        if proto is None:
            return 0.0
        try:
            return float(int(proto))
        except Exception:
            mapping = {
                'TCP': 6,
                'UDP': 17,
                'ICMP': 1,
                'ICMPV6': 58,
                'ARP': 2054,
            }
            return float(mapping.get(str(proto).upper(), 0))


# === Global State ============================================================
_flows = {}
_lock = threading.Lock()
_flow_timeout = 30.0
_stop_event = threading.Event()
_flush_thread = None


def _normalise_flow_key(src, dst, sport, dport, proto):
    """Return canonical flow key and direction flag for the packet."""

    def _key_tuple(a, ap, b, bp):
        return (
            str(a or ''),
            int(ap or -1),
            str(b or ''),
            int(bp or -1),
        )

    forward_tuple = _key_tuple(src, sport, dst, dport)
    backward_tuple = _key_tuple(dst, dport, src, sport)

    if forward_tuple <= backward_tuple:
        key = FlowKey(src, dst, sport, dport, proto)
        return key, True

    return FlowKey(dst, src, dport, sport, proto), False


# ========================================================================
# STREAMING CONTROL
# ========================================================================
def init_streaming(model_path: Optional[str] = None, flow_timeout: float = 30.0):
    global _flow_timeout, _flush_thread

    _flow_timeout = float(flow_timeout)
    _stop_event.clear()
    get_model_manager()

    if _flush_thread is None or not _flush_thread.is_alive():
        _flush_thread = threading.Thread(target=_flow_flush_loop, daemon=True)
        _flush_thread.start()

    active = get_model_manager().get_active_model_info('attack')
    log.info(
        "Streaming initialized. flow_timeout=%s | model=%s",
        _flow_timeout,
        active.version if active else 'unknown',
    )


def stop_streaming():
    global _flush_thread
    _stop_event.set()
    if _flush_thread and _flush_thread.is_alive():
        _flush_thread.join(timeout=2)
    _flush_thread = None
    _flush_all()


def _flow_flush_loop():
    while not _stop_event.is_set():
        now = time.time()
        to_emit = []
        with _lock:
            for k, f in list(_flows.items()):
                if now - f.last_ts > _flow_timeout:
                    to_emit.append(k)
        for key in to_emit:
            _emit_flow(key)
        time.sleep(1.0)


def _flush_all():
    with _lock:
        keys = list(_flows.keys())
    for key in keys:
        _emit_flow(key)


# ========================================================================
# PACKET HANDLER
# ========================================================================
def handle_packet(pkt_dict):
    """Обработка пакета, поступающего из capture."""
    try:
        ts = _to_float(pkt_dict.get('ts'), default=time.time())
        src = _to_str(pkt_dict.get('src'))
        dst = _to_str(pkt_dict.get('dst'))
        sport = _to_int(pkt_dict.get('sport'))
        dport = _to_int(pkt_dict.get('dport'))
        proto = (_to_str(pkt_dict.get('proto')) or '').upper()

        key, is_forward = _normalise_flow_key(src, dst, sport, dport, proto)

        pkt_len = _to_int(pkt_dict.get('length') or pkt_dict.get('bytes'))

        with _lock:
            f = _flows.get(key)
            if not f:
                f = Flow(ts, key, iface=_to_str(pkt_dict.get('iface')))
                _flows[key] = f
            f.update(ts, pkt_len, pkt_dict, is_forward=is_forward)

    except Exception:
        log.exception("Error in handle_packet")


def _to_int(value, default=0):
    try:
        if callable(value):
            return _to_int(value(), default)
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            if math.isnan(value):
                return default
            return int(value)
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode('utf-8', errors='ignore')
            except Exception:
                return default
        return int(str(value).strip())
    except Exception:
        try:
            return int(float(str(value).strip()))
        except Exception:
            return default


def _to_float(value, default=0.0):
    try:
        if callable(value):
            return _to_float(value(), default)
        if value is None:
            return default
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode('utf-8', errors='ignore')
            except Exception:
                return default
        return float(str(value).strip())
    except Exception:
        return default


def _to_str(value):
    if value is None:
        return None
    if callable(value):
        try:
            return _to_str(value())
        except Exception:
            return None
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode('utf-8', errors='ignore')
        except Exception:
            return str(value)
    return str(value)


# ========================================================================
# FLOW EMISSION / MODEL / STORAGE
# ========================================================================
def _emit_flow(key):
    with _lock:
        flow = _flows.pop(key, None)

    if not flow:
        return

    feats = flow.metrics()

    log.warning("FEATURES: %s", list(feats.keys()))

    hints = {k: v for k, v in flow.extra.items() if v}

    predictor = get_predictor()

    try:
        features_payload = {**feats, **hints, 'duration': feats.get('duration'), 'iface': flow.iface}
        res = predictor.predict(features_payload, task='attack')
    except Exception:
        log.exception("Model prediction error")
        res = {'label': 'error', 'label_name': 'Prediction error', 'confidence': 0.0, 'explanation': []}

    duration_ms = int(max(0.0, (flow.last_ts - flow.first_ts)) * 1000)
    packets_per_sec = float(feats.get('pkts_per_s') or 0.0)
    bytes_per_sec = float(feats.get('bytes_per_s') or 0.0)
    avg_pkt_size = float(feats.get('avg_pkt_size') or 0.0)

    summary_dict = {
        'длительность_мс': duration_ms,
        'пакетов': flow.packets,
        'байт': flow.bytes,
        'пакетов_в_сек': round(packets_per_sec, 2),
        'байт_в_сек': round(bytes_per_sec, 2),
        'средний_размер_пакета': round(avg_pkt_size, 2),
        'модель': res.get('version'),
        'уверенность': round(res.get('confidence', 0.0), 3),
        **hints,
    }

    if res.get('explanation'):
        summary_dict['важные_признаки'] = res['explanation']

    if res.get('drift'):
        summary_dict['drift'] = res['drift']

    flow_dict = {
        'ts': int(flow.last_ts * 1000),
        'iface': flow.iface or '-',
        'src': key.src,
        'dst': key.dst,
        'sport': key.sport,
        'dport': key.dport,
        'proto': key.proto,
        'packets': flow.packets,
        'bytes': flow.bytes,
        'label': res.get('label'),
        'label_name': res.get('label_name', res.get('label', 'Unknown')),
        'score': float(res.get('confidence') or res.get('score') or 0.0),
        'summary': summary_dict,
        'duration_ms': duration_ms,
        'packets_per_sec': packets_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'avg_pkt_size': avg_pkt_size,
        'model_version': res.get('version'),
        'model_task': res.get('task'),
    }

    try:
        save_flow(flow_dict)
    except Exception:
        log.exception("FlowLogger insert error")

    try:
        publish('flow', flow_dict)
        publish('ml_prediction', res)
    except Exception:
        log.exception("Event publish error")

    log.info("[FLOW_EMIT] %s -> %s (label=%s | name=%s | score=%.3f)",
             key, res, res.get('label'), res.get('label_name'), res.get('score'))
