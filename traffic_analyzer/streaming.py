import logging, time, json
from .features import extract_features_from_flow
from .classification import load_model, predict_from_features
from .storage import storage
from .event_bus import publish
log = logging.getLogger('ta.streaming')
_model = None
_use_nfstream = False

try:
    from nfstream import NFStreamer
    _use_nfstream = True
except Exception:
    _use_nfstream = False

def init_streaming():
    global _model
    _model = load_model()
    log.info('Streaming initialized (model loaded=%s, nfstream=%s)', _model is not None, _use_nfstream)

def _process_flow_dict(flow):
    feats = extract_features_from_flow(flow)
    label = predict_from_features(feats, _model)
    flow['label'] = label.get('label')
    storage.insert_flow(flow)
    # publish minimal event for dashboards
    try:
        publish({'ts': flow.get('ts'), 'src': flow.get('src'), 'dst': flow.get('dst'), 'proto': flow.get('proto'), 'label': flow.get('label')})
    except Exception:
        log.exception('Failed to publish event')

def handle_packet(pkt):
    # If NFStreamer available, it would create flows by itself; here we create a trivial flow per packet
    try:
        src = pkt[0][1].src if pkt and pkt.haslayer('IP') else '0.0.0.0'
        dst = pkt[0][1].dst if pkt and pkt.haslayer('IP') else '0.0.0.0'
        sport = int(getattr(pkt, 'sport', 0) or 0)
        dport = int(getattr(pkt, 'dport', 0) or 0)
        proto = getattr(pkt, 'proto', getattr(pkt, 'name', 'IP'))
        size = len(pkt)
    except Exception:
        src,dst,sport,dport,proto,size = ('0.0.0.0','0.0.0.0',0,0,'IP',0)
    flow = {'src':src,'dst':dst,'sport':sport,'dport':dport,'proto':str(proto),'packets':1,'bytes':size,'ts':int(time.time()*1000),'duration':0.001}
    _process_flow_dict(flow)

def start_nfstream(interface='eth0'):
    """If NFStreamer is available, start a background iteration over flows."""
    if not _use_nfstream:
        raise RuntimeError('NFStream not available')
    def _run():
        streamer = NFStreamer(source=interface, decode_tunnels=True, n_dpi_enabled=True, bpf_filter=None)
        for flow in streamer:
            try:
                # convert NFStream flow object to simple dict
                fd = {
                    'src': getattr(flow, 'src_ip', '0.0.0.0'),
                    'dst': getattr(flow, 'dst_ip', '0.0.0.0'),
                    'sport': int(getattr(flow, 'src_port', 0) or 0),
                    'dport': int(getattr(flow, 'dst_port', 0) or 0),
                    'proto': getattr(flow, 'protocol', 'IP'),
                    'packets': int(getattr(flow, 'num_packets', 0) or 0),
                    'bytes': int(getattr(flow, 'num_bytes', 0) or 0),
                    'ts': int(time.time()*1000),
                    'duration': float(getattr(flow, 'duration', 0.0) or 0.0)
                }
                _process_flow_dict(fd)
            except Exception:
                log.exception('Error processing NFStream flow')
    import threading
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    log.info('Started NFStream background thread on %s', interface)
