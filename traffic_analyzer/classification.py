# traffic_analyzer/classification.py
import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Optional, Tuple

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODEL_PATH = os.path.join(DATA_DIR, 'model.joblib')
os.makedirs(DATA_DIR, exist_ok=True)

FEATURE_NAMES = ['duration','packets','bytes','pkts_per_s','bytes_per_s','avg_pkt_size']

def train_demo_model(path=MODEL_PATH):
    """Train a synthetic but realistic model (6 features) and save it."""
    rng = np.random.RandomState(42)
    X = []
    y = []
    # web-like flows: short duration, moderate bytes
    for i in range(800):
        duration = rng.exponential(scale=1.0)
        packets = max(1, int(rng.poisson(10)))
        bytes_ = int(rng.normal(loc=2000, scale=800))
        pkts_per_s = packets / duration if duration>0 else packets
        bytes_per_s = bytes_ / duration if duration>0 else bytes_
        avg_pkt = bytes_/packets if packets>0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('web')
    # p2p-like flows: long duration, many packets
    for i in range(400):
        duration = rng.exponential(scale=30.0)+5
        packets = max(5, int(rng.poisson(200)))
        bytes_ = int(rng.normal(loc=200000, scale=50000))
        pkts_per_s = packets / duration if duration>0 else packets
        bytes_per_s = bytes_ / duration if duration>0 else bytes_
        avg_pkt = bytes_/packets if packets>0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('p2p')
    # dns-like flows: tiny bytes, tiny duration
    for i in range(300):
        duration = rng.exponential(scale=0.05)
        packets = 1
        bytes_ = int(rng.normal(loc=200, scale=80))
        pkts_per_s = packets / duration if duration>0 else packets
        bytes_per_s = bytes_ / duration if duration>0 else bytes_
        avg_pkt = bytes_/packets if packets>0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('dns')
    # malware/scan-like flows: many small packets short duration
    for i in range(300):
        duration = rng.exponential(scale=0.5)
        packets = max(1, int(rng.poisson(50)))
        bytes_ = int(rng.normal(loc=4000, scale=2000))
        pkts_per_s = packets / duration if duration>0 else packets
        bytes_per_s = bytes_ / duration if duration>0 else bytes_
        avg_pkt = bytes_/packets if packets>0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('malware')
    X = np.array(X)
    y = np.array(y)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    # Save model and a small metadata dict
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump({'model': clf, 'features': FEATURE_NAMES}, path)
    return path

def load_model(path=MODEL_PATH) -> Tuple[object, Optional[list]]:
    """
    Load persisted model metadata.

    Возвращаем кортеж (model, feature_names). Старые модели могли сохранять
    список признаков под ключом ``columns`` – учитываем это для обратной
    совместимости.
    """
    if not os.path.exists(path):
        # train demo model on first use
        train_demo_model(path)
    obj = joblib.load(path)
    model = obj.get('model') or obj
    features = obj.get('features') or obj.get('columns')
    if features is None:
        # fall back to defaults used в демо-модели
        features = FEATURE_NAMES
    return model, features

def _features_from_dict(d: Dict):
    """Convert feature dict to ordered list for model."""
    return [float(d.get(fname, 0.0)) for fname in FEATURE_NAMES]

def predict_from_features(feats: Dict, model=None):
    """Return {'label':..., 'score':...} using provided model or load default."""
    if model is None:
        model, _ = load_model()
    # accept dict or list/array
    if isinstance(feats, dict):
        x = np.array([_features_from_dict(feats)])
    else:
        x = np.array([feats])
    probs = None
    try:
        probs = model.predict_proba(x)[0]
        labels = model.classes_
        # pick top label and score
        top_idx = int(np.argmax(probs))
        return {'label': str(labels[top_idx]), 'score': float(probs[top_idx])}
    except Exception:
        # fallback to predict
        lab = model.predict(x)[0]
        return {'label': str(lab), 'score': 1.0}

# Backwards-compatible single-packet classifier
def classify_packet(pkt: Dict, model=None):
    """ 
    pkt: dict possibly containing duration/packets/bytes (flow), or raw packet fields.
    """
    # If pkt appears to be flow-like, use directly
    if 'duration' in pkt or 'packets' in pkt or 'bytes' in pkt:
        feats = {
            'duration': float(pkt.get('duration',0.0)),
            'packets': int(pkt.get('packets',0)),
            'bytes': int(pkt.get('bytes',0)),
            'pkts_per_s': float(pkt.get('pkts_per_s', pkt.get('packets',0))),
            'bytes_per_s': float(pkt.get('bytes_per_s', pkt.get('bytes',0))),
            'avg_pkt_size': float(pkt.get('avg_pkt_size', 0.0))
        }
    else:
        # try to build minimal features
        length = int(pkt.get('length', pkt.get('bytes', 0) or 0))
        feats = {'duration': 0.0, 'packets': 1, 'bytes': length, 'pkts_per_s': 1.0, 'bytes_per_s': float(length), 'avg_pkt_size': float(length)}
    return predict_from_features(feats, model)
