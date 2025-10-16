# traffic_analyzer/streaming.py
import logging, time, threading
from collections import namedtuple
from typing import Dict, Optional

from .features import extract_features_from_flow
from .classification import load_model, predict_from_features
from .storage import storage
from .event_bus import publish

log = logging.getLogger('ta.streaming')
FlowKey = namedtuple('FlowKey', ['src','dst','sport','dport','proto'])

class Flow:
    def __init__(self, ts: float, iface: Optional[str] = None):
        ts = float(ts or time.time())
        self.first_ts = ts
        self.last_ts = ts
        self.packets = 0
        self.bytes = 0
        self.iface = iface or '-'
        self.extra: Dict[str, Optional[str]] = {}

    def update(self, ts: float, pkt_len: int, pkt_dict: Dict):
        self.last_ts = max(self.last_ts, ts)
        self.packets += 1
        self.bytes += max(0, pkt_len)
        # сохраним полезные метаданные (SNI/HTTP/DNS и т.д.) для отображения в UI
        for field in ('tls_sni', 'http_host', 'dns_query'):
            value = pkt_dict.get(field)
            if value:
                self.extra[field] = value
        if pkt_dict.get('application_name'):
            self.extra['app'] = pkt_dict.get('application_name')
        if pkt_dict.get('iface') and self.iface == '-':
            self.iface = pkt_dict.get('iface')

    def metrics(self) -> Dict[str, float]:
        duration = max(0.0, self.last_ts - self.first_ts)
        base = {
            'duration': duration,
            'packets': self.packets,
            'bytes': self.bytes,
        }
        derived = extract_features_from_flow(base)
        return {**derived, **self.extra}

# Global state
_flows = {}  # FlowKey -> Flow
_lock = threading.Lock()
_flow_timeout = 30.0
_stop_event = threading.Event()
_model = None
_model_features = []
_flush_thread = None

def init_streaming(model_path=None, flow_timeout=30.0):
    global _model, _model_features, _flow_timeout, _flush_thread
    model, features = load_model(model_path) if model_path else load_model()
    _model = model
    _model_features = features or []
    _flow_timeout = float(flow_timeout)
    _stop_event.clear()
    if _flush_thread is None or not _flush_thread.is_alive():
        _flush_thread = threading.Thread(target=_flow_flush_loop, daemon=True)
        _flush_thread.start()
    log.info(
        "Streaming initialized. flow_timeout=%s model=%s features=%s",
        _flow_timeout,
        "loaded" if _model else "none",
        len(_model_features) if _model_features else 0,
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

def handle_packet(pkt_dict):
    """
    pkt_dict expected to have: ts (float seconds), src, dst, sport, dport, proto, length, iface
    This is the function called by capture layer for each incoming packet.
    """
    try:
        ts = float(pkt_dict.get('ts', time.time()))
        key = FlowKey(pkt_dict.get('src'), pkt_dict.get('dst'),
                      int(pkt_dict.get('sport') or 0),
                      int(pkt_dict.get('dport') or 0),
                      str(pkt_dict.get('proto') or '').upper())
        pkt_len = int(pkt_dict.get('length') or pkt_dict.get('bytes') or 0)

        with _lock:
            f = _flows.get(key)
            if not f:
                f = Flow(ts, iface=pkt_dict.get('iface'))
                _flows[key] = f
            f.update(ts, pkt_len, pkt_dict)
    except Exception:
        log.exception("Error in handle_packet")

def _emit_flow(key):
    with _lock:
        flow = _flows.pop(key, None)
    if not flow:
        return
    feats = flow.metrics()
    feats_logged = {k: v for k, v in feats.items() if isinstance(v, (int, float))}
    # Predict
    res = {'label':'unknown','score':0.0}
    try:
        res = predict_from_features(feats, _model, _model_features) if _model else {'label': 'unknown', 'score': 0.0}
    except Exception:
        log.exception("Model prediction error")
    # Prepare output for storage / UI
    duration_ms = int(max(0.0, (flow.last_ts - flow.first_ts)) * 1000)
    packets_per_sec = float(feats.get('pkts_per_s') or 0.0)
    bytes_per_sec = float(feats.get('bytes_per_s') or 0.0)
    avg_pkt_size = float(feats.get('avg_pkt_size') or 0.0)
    hints = {k: v for k, v in flow.extra.items() if v}
    summary_dict = {
        'длительность_мс': duration_ms,
        'пакетов': flow.packets,
        'байт': flow.bytes,
        'пакетов_в_сек': round(packets_per_sec, 2),
        'байт_в_сек': round(bytes_per_sec, 2),
        'средний_размер_пакета': round(avg_pkt_size, 2),
        **hints,
    }
    flow_dict = {
        'ts': int(flow.last_ts*1000),
        'iface': flow.iface or '-', 'src': key.src, 'dst': key.dst,
        'sport': key.sport, 'dport': key.dport, 'proto': key.proto,
        'packets': flow.packets, 'bytes': flow.bytes,
        'label': res.get('label'), 'score': float(res.get('score') or 0.0),
        'summary': summary_dict,
        'duration_ms': duration_ms,
        'packets_per_sec': packets_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'avg_pkt_size': avg_pkt_size,
    }
    # save and publish
    try:
        storage.insert_flow(flow_dict)
    except Exception:
        log.exception("Storage insert error")
    try:
        publish('flow', flow_dict)
    except Exception:
        log.exception("Event publish error")
    log.info("[FLOW_EMIT] %s -> %s feats=%s", key, res, feats_logged)
