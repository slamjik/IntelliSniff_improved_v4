import logging, math, time, threading, os
from collections import namedtuple
from typing import Dict, Optional

from .features import extract_features_from_flow
from .classification import load_model, predict_from_features
from .storage import storage
from .event_bus import publish

log = logging.getLogger('ta.streaming')
FlowKey = namedtuple('FlowKey', ['src', 'dst', 'sport', 'dport', 'proto'])

# 📌 Абсолютный путь к твоей обученной модели
MODEL_PATH = r"C:\Users\Olega\PycharmProjects\IntelliSniff_improved_v4\traffic_analyzer\data\model.joblib"


# === Класс потока ============================================================
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
        base = {'duration': duration, 'packets': self.packets, 'bytes': self.bytes}
        derived = extract_features_from_flow(base)
        return {**derived, **self.extra}


# === Global State ============================================================
_flows = {}
_lock = threading.Lock()
_flow_timeout = 30.0
_stop_event = threading.Event()
_model = None
_model_features = []
_flush_thread = None


# === Инициализация потокового анализа =======================================
def init_streaming(model_path: Optional[str] = None, flow_timeout: float = 30.0):
    """Загружает модель и запускает потоковый анализ."""
    global _model, _model_features, _flow_timeout, _flush_thread

    model_path = model_path or MODEL_PATH
    if not os.path.exists(model_path):
        log.warning("⚠️ Custom model not found at %s — falling back to demo.", model_path)
        model, features = load_model()
    else:
        log.info("📦 Loading trained model from: %s", model_path)
        model, features = load_model(model_path)

    _model = model
    _model_features = features or []
    _flow_timeout = float(flow_timeout)
    _stop_event.clear()

    if _flush_thread is None or not _flush_thread.is_alive():
        _flush_thread = threading.Thread(target=_flow_flush_loop, daemon=True)
        _flush_thread.start()

    log.info(
        "Streaming initialized. flow_timeout=%s | model=%s | features=%s",
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


# === Flush Loop ==============================================================
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


# === Type helpers ============================================================
def _to_int(value, default=0):
    if callable(value):
        try:
            return _to_int(value(), default)
        except Exception:
            return default
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int,)):
        return int(value)
    if isinstance(value, float):
        if math.isnan(value):
            return default
        return int(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode('utf-8', errors='ignore')
        except Exception:
            return default
    try:
        return int(str(value).strip())
    except Exception:
        try:
            return int(float(str(value).strip()))
        except Exception:
            return default


def _to_float(value, default=0.0):
    if callable(value):
        try:
            return _to_float(value(), default)
        except Exception:
            return default
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
    try:
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


# === Основная логика =========================================================
def handle_packet(pkt_dict):
    """Обработка пакета, поступающего из capture."""
    try:
        ts = _to_float(pkt_dict.get('ts'), default=time.time())
        key = FlowKey(
            _to_str(pkt_dict.get('src')),
            _to_str(pkt_dict.get('dst')),
            _to_int(pkt_dict.get('sport')),
            _to_int(pkt_dict.get('dport')),
            (_to_str(pkt_dict.get('proto')) or '').upper(),
        )
        pkt_len = _to_int(pkt_dict.get('length') or pkt_dict.get('bytes'))

        with _lock:
            f = _flows.get(key)
            if not f:
                f = Flow(ts, iface=_to_str(pkt_dict.get('iface')))
                _flows[key] = f
            f.update(ts, pkt_len, pkt_dict)
    except Exception:
        log.exception("Error in handle_packet")


# === Эмиссия потока ==========================================================
def _emit_flow(key):
    with _lock:
        flow = _flows.pop(key, None)
    if not flow:
        return

    feats = flow.metrics()
    feats_logged = {k: v for k, v in feats.items() if isinstance(v, (int, float))}

    res = {'label': 'unknown', 'label_name': 'Unknown', 'score': 0.0}
    try:
        if _model:
            res = predict_from_features(feats, _model, _model_features)
    except Exception:
        log.exception("Model prediction error")

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
        'score': float(res.get('score') or 0.0),
        'summary': summary_dict,
        'duration_ms': duration_ms,
        'packets_per_sec': packets_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'avg_pkt_size': avg_pkt_size,
    }

    # Сохраняем и публикуем
    try:
        storage.insert_flow(flow_dict)
    except Exception:
        log.exception("Storage insert error")

    try:
        publish('flow', flow_dict)
    except Exception:
        log.exception("Event publish error")

    log.info("[FLOW_EMIT] %s -> %s (label=%s | name=%s | score=%.3f)",
             key, res, res.get('label'), res.get('label_name'), res.get('score'))
