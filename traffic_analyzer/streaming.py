# traffic_analyzer/streaming.py
import logging, time, threading
from collections import namedtuple
from .features import extract_features_from_flow
from .classification import load_model, predict_from_features
from .storage import storage
from .event_bus import publish

log = logging.getLogger('ta.streaming')
FlowKey = namedtuple('FlowKey', ['src','dst','sport','dport','proto'])

class Flow:
    def __init__(self, ts):
        self.first_ts = ts
        self.last_ts = ts
        self.packets = 0
        self.bytes = 0
        self.extra = {}

    def update(self, ts, pkt_len):
        self.last_ts = max(self.last_ts, ts)
        self.packets += 1
        self.bytes += pkt_len

    def features(self):
        duration = max(0.0, self.last_ts - self.first_ts)
        return {
            'duration': duration,
            'packets': self.packets,
            'bytes': self.bytes,
            **self.extra
        }

# Global state
_flows = {}  # FlowKey -> Flow
_lock = threading.Lock()
_flow_timeout = 30.0
_stop_event = threading.Event()
_model = None

def init_streaming(model_path=None, flow_timeout=30.0):
    global _model, _flow_timeout
    _model = load_model(model_path) if model_path else load_model()
    _flow_timeout = float(flow_timeout)
    _stop_event.clear()
    t = threading.Thread(target=_flow_flush_loop, daemon=True)
    t.start()
    log.info("Streaming initialized. flow_timeout=%s model=%s", _flow_timeout, "loaded" if _model else "none")

def stop_streaming():
    _stop_event.set()

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
                      (pkt_dict.get('proto') or '').upper())
        pkt_len = int(pkt_dict.get('length') or pkt_dict.get('bytes') or 0)

        with _lock:
            f = _flows.get(key)
            if not f:
                f = Flow(ts)
                # store some L7 hints if present
                if 'tls_sni' in pkt_dict and pkt_dict.get('tls_sni'):
                    f.extra['tls_sni'] = pkt_dict.get('tls_sni')
                if 'http_host' in pkt_dict and pkt_dict.get('http_host'):
                    f.extra['http_host'] = pkt_dict.get('http_host')
                if 'dns_query' in pkt_dict and pkt_dict.get('dns_query'):
                    f.extra['dns_query'] = pkt_dict.get('dns_query')
                _flows[key] = f
            f.update(ts, pkt_len)
    except Exception:
        log.exception("Error in handle_packet")

def _emit_flow(key):
    with _lock:
        flow = _flows.pop(key, None)
    if not flow:
        return
    feats = flow.features()
    feats_logged = feats.copy()
    # Predict
    res = {'label':'unknown','score':0.0}
    try:
        res = predict_from_features(feats, _model) if _model else {'label':'unknown','score':0.0}
    except Exception:
        log.exception("Model prediction error")
    # Prepare output for storage / UI
    flow_dict = {
        'ts': int(flow.last_ts*1000),
        'iface': '-', 'src': key.src, 'dst': key.dst,
        'sport': key.sport, 'dport': key.dport, 'proto': key.proto,
        'packets': flow.packets, 'bytes': flow.bytes,
        'label': res.get('label'), 'score': float(res.get('score') or 0.0),
        'summary': str(feats_logged)
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
