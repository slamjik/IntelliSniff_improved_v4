import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Optional, Tuple

# === Пути =====================================================================
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODEL_PATH = os.path.join(DATA_DIR, 'model.joblib')
os.makedirs(DATA_DIR, exist_ok=True)

# === Признаки модели ==========================================================
FEATURE_NAMES = ['duration', 'packets', 'bytes', 'pkts_per_s', 'bytes_per_s', 'avg_pkt_size']

# === Человеческие названия классов ============================================
LABEL_NAMES = {
    "0": "Normal",
    "1": "DoS / DDoS Attack",
    "2": "Port Scan / Recon",
    "3": "Botnet Activity",
    "4": "Brute Force / Infiltration",
    "5": "Web Attack (XSS / SQLi)",
    "6": "Exploit / Heartbleed",
    "7": "Unknown / Rare Anomaly",
}


# === Обучение демо-модели =====================================================
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
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('web')

    # p2p-like flows: long duration, many packets
    for i in range(400):
        duration = rng.exponential(scale=30.0) + 5
        packets = max(5, int(rng.poisson(200)))
        bytes_ = int(rng.normal(loc=200000, scale=50000))
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('p2p')

    # dns-like flows: tiny bytes, tiny duration
    for i in range(300):
        duration = rng.exponential(scale=0.05)
        packets = 1
        bytes_ = int(rng.normal(loc=200, scale=80))
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('dns')

    # malware/scan-like flows: many small packets short duration
    for i in range(300):
        duration = rng.exponential(scale=0.5)
        packets = max(1, int(rng.poisson(50)))
        bytes_ = int(rng.normal(loc=4000, scale=2000))
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('malware')

    X = np.array(X)
    y = np.array(y)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump({'model': clf, 'features': FEATURE_NAMES}, path)
    return path


# === Загрузка модели ==========================================================
def load_model(path=MODEL_PATH) -> Tuple[object, Optional[list]]:
    """
    Load persisted model metadata.

    Возвращает кортеж (model, feature_names). Старые модели могли сохранять
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
        # fall back к дефолтным признакам демо-модели
        features = FEATURE_NAMES
    return model, features


# === Подготовка признаков =====================================================
def _features_from_dict(d: Dict, feature_names=None):
    """Convert feature dict to ordered list for model."""
    names = feature_names or FEATURE_NAMES
    return [float(d.get(fname, 0.0)) for fname in names]


# === Предсказание =============================================================
def predict_from_features(feats: Dict, model=None, feature_names=None):
    """Return {'label': ..., 'label_name': ..., 'score': ...} using provided model or load default."""
    import pandas as pd

    loaded_features = None
    if model is None:
        model, loaded_features = load_model()

    if feature_names is None:
        if loaded_features:
            feature_names = loaded_features
        else:
            feature_names = getattr(model, 'feature_names_in_', None)

    feature_names = list(feature_names) if feature_names else FEATURE_NAMES

    try:
        # Используем DataFrame с корректными именами признаков
        if isinstance(feats, dict):
            row = [feats.get(f, 0.0) for f in feature_names]
            x = pd.DataFrame([row], columns=feature_names)
        else:
            x = pd.DataFrame([feats], columns=feature_names)

        probs = model.predict_proba(x)[0]
        labels = model.classes_
        top_idx = int(np.argmax(probs))

        return {
            'label': str(labels[top_idx]),
            'label_name': LABEL_NAMES.get(str(labels[top_idx]), f"Class {labels[top_idx]}"),
            'score': float(probs[top_idx])
        }

    except Exception:
        # fallback на predict() если модель без proba
        try:
            if isinstance(feats, dict):
                row = [feats.get(f, 0.0) for f in feature_names]
                x = pd.DataFrame([row], columns=feature_names)
            else:
                x = pd.DataFrame([feats], columns=feature_names)
            lab = model.predict(x)[0]
            return {
                'label': str(lab),
                'label_name': LABEL_NAMES.get(str(lab), f"Class {lab}"),
                'score': 1.0
            }
        except Exception:
            return {'label': 'error', 'label_name': 'Error', 'score': 0.0}


# === Совместимость с одиночными пакетами =====================================
def classify_packet(pkt: Dict, model=None, feature_names=None):
    """Classify single packet or flow-like dict."""
    if 'duration' in pkt or 'packets' in pkt or 'bytes' in pkt:
        feats = {
            'duration': float(pkt.get('duration', 0.0)),
            'packets': int(pkt.get('packets', 0)),
            'bytes': int(pkt.get('bytes', 0)),
            'pkts_per_s': float(pkt.get('pkts_per_s', pkt.get('packets', 0))),
            'bytes_per_s': float(pkt.get('bytes_per_s', pkt.get('bytes', 0))),
            'avg_pkt_size': float(pkt.get('avg_pkt_size', 0.0))
        }
    else:
        length = int(pkt.get('length', pkt.get('bytes', 0) or 0))
        feats = {
            'duration': 0.0,
            'packets': 1,
            'bytes': length,
            'pkts_per_s': 1.0,
            'bytes_per_s': float(length),
            'avg_pkt_size': float(length)
        }
    return predict_from_features(feats, model, feature_names)
