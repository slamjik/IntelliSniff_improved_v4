import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Optional, Tuple
import logging

log = logging.getLogger("ta.classification")

# === Пути =====================================================================
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODEL_PATH = os.path.join(DATA_DIR, 'model.joblib')
USER_MODEL_PATH = r"C:\Users\Olega\PycharmProjects\IntelliSniff_improved_v4\datasets\model.joblib"
os.makedirs(DATA_DIR, exist_ok=True)

# === Признаки демо-модели =====================================================
FEATURE_NAMES = ['duration', 'packets', 'bytes', 'pkts_per_s', 'bytes_per_s', 'avg_pkt_size']

# === Человеческие названия классов ============================================
LABEL_NAMES = {
    "0": "Normal Traffic",
    "1": "DoS / DDoS Attack",
    "2": "Port Scan / Recon",
    "3": "Botnet Activity",
    "4": "Brute Force / Infiltration",
    "5": "Web Attack (XSS / SQLi)",
    "6": "Exploit / Heartbleed",
    "7": "Unknown / Rare Anomaly",

    "benign": "Normal Traffic",
    "normal": "Normal Traffic",
    "nonvpn": "Normal Traffic",
    "attack": "Suspicious / Attack",
    "dos": "DoS Attack",
    "ddos": "DDoS Attack",
    "bruteforce": "Brute Force Attack",
    "portscan": "Port Scan / Recon",
    "botnet": "Botnet Activity",
    "infiltration": "Infiltration Attempt",
    "webattack": "Web Application Attack",
}


def resolve_label_name(label: Optional[object]) -> str:
    """Return human readable label for numeric or textual model output."""
    if label is None:
        return "Unknown"
    label_str = str(label)
    if label_str in LABEL_NAMES:
        return LABEL_NAMES[label_str]
    normalized = label_str.strip().lower()
    if normalized in LABEL_NAMES:
        return LABEL_NAMES[normalized]
    try:
        as_int = int(float(label_str))
    except (TypeError, ValueError):
        as_int = None
    if as_int is not None and str(as_int) in LABEL_NAMES:
        return LABEL_NAMES[str(as_int)]
    return f"Class {label_str}" if label_str else "Unknown"


# === Обучение демо-модели =====================================================
def train_demo_model(path=MODEL_PATH):
    """Train a synthetic demo model (6 features) and save it."""
    rng = np.random.RandomState(42)
    X, y = [], []

    # web-like
    for i in range(800):
        duration = rng.exponential(scale=1.0)
        packets = max(1, int(rng.poisson(10)))
        bytes_ = int(rng.normal(loc=2000, scale=800))
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('web')

    # p2p-like
    for i in range(400):
        duration = rng.exponential(scale=30.0) + 5
        packets = max(5, int(rng.poisson(200)))
        bytes_ = int(rng.normal(loc=200000, scale=50000))
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('p2p')

    # dns-like
    for i in range(300):
        duration = rng.exponential(scale=0.05)
        packets = 1
        bytes_ = int(rng.normal(loc=200, scale=80))
        pkts_per_s = packets / duration if duration > 0 else packets
        bytes_per_s = bytes_ / duration if duration > 0 else bytes_
        avg_pkt = bytes_ / packets if packets > 0 else 0
        X.append([duration, packets, bytes_, pkts_per_s, bytes_per_s, avg_pkt])
        y.append('dns')

    # malware-like
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
def load_model(path=MODEL_PATH) -> Tuple[object, list]:
    """Loads trained model (supports both demo and bundle)."""
    if not os.path.exists(path):
        print("⚠️  Model not found — training demo model...")
        train_demo_model(path)

    obj = joblib.load(path)

    if isinstance(obj, dict) and "model" in obj:
        model = obj["model"]
        features = obj.get("features") or FEATURE_NAMES
    else:
        model = obj
        features = FEATURE_NAMES

    if not hasattr(model, "predict"):
        raise RuntimeError("Invalid model loaded: missing predict()")

    return model, features


# === Предсказание =============================================================
def predict_from_features(feats: Dict, model=None, feature_names=None):
    """
    Универсальное предсказание:
    - если есть USER_MODEL_PATH с bundle {'model', 'features'} — используем его;
    - иначе fallback на локальный demo model.joblib;
    - строго собираем вход под ожидаемый список feature_names,
      чтобы не было предупреждений X does not have valid feature names.
    """
    loaded_features = None
    user_model = None

    # 1) Пытаемся загрузить твою основную модель
    if os.path.exists(USER_MODEL_PATH):
        try:
            obj = joblib.load(USER_MODEL_PATH)
            if isinstance(obj, dict) and "model" in obj:
                user_model = obj["model"]
                loaded_features = obj.get("features")
                if loaded_features:
                    log.info("✅ Using user model %s with %d features",
                             type(user_model).__name__, len(loaded_features))
        except Exception as e:
            log.warning("⚠️ Failed to load user model from %s: %s", USER_MODEL_PATH, e)

    # 2) Если пользовательская модель не загружена — fallback на demo
    if user_model is None:
        if model is None:
            model, loaded_features = load_model()
    else:
        model = user_model

    # 3) Определяем список признаков
    if feature_names is None:
        feature_names = (
            loaded_features
            or getattr(model, "feature_names_in_", None)
            or FEATURE_NAMES
        )
    feature_names = list(feature_names)

    try:
        # 4) Строим вектор строго в порядке feature_names
        #    Для каждого признака берём feats.get(name, 0.0)
        row = [feats.get(f, 0.0) for f in feature_names]
        x = pd.DataFrame([row], columns=feature_names)

        # Лог для отладки: смотрим часть колонок и нулей
        if (x == 0).all(axis=None):
            log.warning("⚠️ All-zero feature vector for flow: possible extraction issue. feats=%s", dict(list(feats.items())[:20]))
        else:
            log.debug("🧩 Built feature vector: %d features, first 10: %s",
                      x.shape[1],
                      {c: float(x.iloc[0][c]) for c in x.columns[:10]})

        # 5) Предсказание
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(x)[0]
            labels = model.classes_
            top_idx = int(np.argmax(probs))
            label_value = labels[top_idx]
            return {
                "label": str(label_value),
                "label_name": resolve_label_name(label_value),
                "score": float(probs[top_idx]),
            }
        else:
            lab = model.predict(x)[0]
            return {
                "label": str(lab),
                "label_name": resolve_label_name(lab),
                "score": 1.0,
            }

    except Exception as e:
        log.exception("Prediction failed: %s", e)
        return {"label": "error", "label_name": "Error", "score": 0.0}


# === Совместимость с одиночными пакетами ======================================
def classify_packet(pkt: Dict, model=None, feature_names=None):
    """
    Classify single packet or flow-like dict.
    Для быстрого вызова по raw-пакету остаётся простой маппинг 6 фичей.
    Основной поток всё равно использует extract_features_from_flow().
    """
    if "duration" in pkt or "packets" in pkt or "bytes" in pkt:
        feats = {
            "duration": float(pkt.get("duration", 0.0)),
            "packets": int(pkt.get("packets", 0)),
            "bytes": int(pkt.get("bytes", 0)),
            "pkts_per_s": float(pkt.get("pkts_per_s", pkt.get("packets", 0))),
            "bytes_per_s": float(pkt.get("bytes_per_s", pkt.get("bytes", 0))),
            "avg_pkt_size": float(pkt.get("avg_pkt_size", 0.0)),
        }
    else:
        length = int(pkt.get("length", pkt.get("bytes", 0) or 0))
        feats = {
            "duration": 0.0,
            "packets": 1,
            "bytes": length,
            "pkts_per_s": 1.0,
            "bytes_per_s": float(length),
            "avg_pkt_size": float(length),
        }

    return predict_from_features(feats, model, feature_names)
