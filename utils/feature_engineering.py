"""
Feature engineering helpers for IntelliSniff models.

Варианты работы:

1) Старый режим (offline / generic):
   - extract_features(flow, numeric_features=..., hash_features=...)
   - строит duration/packets/bytes/... + hash_* по SNI/JA3/и т.д.

2) Режим моделей attack/vpn:
   - extract_features(flow, expected_order=[ 'protocol', 'flow_duration', ... ])
   - мы строим полный набор из 41 признака, которые ждут обученные модели:
        'protocol',
        'flow_duration',
        'total_fwd_packets',
        'total_bwd_packets',
        ...
        'init_win_bytes_backward'
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from hashlib import blake2b
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import numpy as np

# ---------------------------------------------------------------------------
#  БАЗОВЫЕ ЧИСЛОВЫЕ ПРИЗНАКИ (старый режим)
# ---------------------------------------------------------------------------

NUMERIC_FEATURES_DEFAULT: Tuple[str, ...] = (
    "duration",
    "packets",
    "bytes",
    "pkts_per_s",
    "bytes_per_s",
    "avg_pkt_size",
    "payload_ratio",
    "burstiness",
    "down_up_ratio",
    "flow_score",
)

HASH_FEATURES: Tuple[str, ...] = (
    "tls_sni",
    "ja3",
    "user_agent",
    "http_host",
    "dns_query",
    "app",
)

# ---------------------------------------------------------------------------
#  CANONICAL 41 FEATURES ДЛЯ attack/vpn моделей
# ---------------------------------------------------------------------------

MODEL_FEATURES_41: Tuple[str, ...] = (
    "protocol",
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_packets_length_total",
    "bwd_packets_length_total",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    "down_up_ratio",
    "packet_length_min",
    "packet_length_max",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_variance",
    "avg_packet_size",
    "destination_port",
    "source_port",
    "init_win_bytes_forward",
    "init_win_bytes_backward",
)


# ---------------------------------------------------------------------------
#  Обёртка над вектором признаков
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FeatureVector:
    """Container for ordered feature vectors."""
    names: Sequence[str]
    values: np.ndarray

    def as_dict(self) -> Dict[str, float]:
        return {name: float(value) for name, value in zip(self.names, self.values)}


# ---------------------------------------------------------------------------
#  SAFE HELPERS
# ---------------------------------------------------------------------------

def _safe_float(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float, np.number)):
        try:
            v = float(value)
        except Exception:
            return default
        if math.isnan(v):
            return default
        return v
    try:
        v = float(str(value).strip())
        if math.isnan(v):
            return default
        return v
    except Exception:
        return default


def _safe_int(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, float):
        if math.isnan(value):
            return default
        return int(value)
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def _hash_feature(text: Optional[str], num_buckets: int = 32) -> float:
    if not text:
        return 0.0
    h = blake2b(str(text).encode("utf-8"), digest_size=4).digest()
    bucket = int.from_bytes(h, "little") % max(1, num_buckets)
    return float(bucket) / float(num_buckets)


# ---------------------------------------------------------------------------
#  СТАРОЕ: производные числовые фичи (duration, pkts_per_s, ...)
# ---------------------------------------------------------------------------

def _derive_numeric_features(base: Mapping[str, object]) -> Dict[str, float]:
    duration = max(_safe_float(base.get("duration")), 0.0)
    packets = max(_safe_float(base.get("packets")), 0.0)
    bytes_total = max(_safe_float(base.get("bytes")), 0.0)

    pkts_per_s = packets / duration if duration > 0 else packets
    bytes_per_s = bytes_total / duration if duration > 0 else bytes_total
    avg_pkt_size = bytes_total / packets if packets > 0 else 0.0

    payload = _safe_float(base.get("payload_bytes"))
    payload_ratio = payload / bytes_total if bytes_total > 0 else 0.0

    down_bytes = _safe_float(base.get("down_bytes"))
    up_bytes = _safe_float(base.get("up_bytes"))
    down_up_ratio = down_bytes / up_bytes if up_bytes > 0 else 0.0

    burstiness = _safe_float(base.get("burstiness"))
    if burstiness == 0 and packets > 1:
        # simple proxy: variance of inter-packet distribution
        burstiness = min(1.0, packets / max(1.0, duration))

    flow_score = (
        _safe_float(base.get("entropy"))
        + _safe_float(base.get("iat_std"))
        + _safe_float(base.get("flow_psh_flags"))
    ) / 3.0

    derived = {
        "duration": duration,
        "packets": packets,
        "bytes": bytes_total,
        "pkts_per_s": pkts_per_s,
        "bytes_per_s": bytes_per_s,
        "avg_pkt_size": avg_pkt_size,
        "payload_ratio": payload_ratio,
        "burstiness": burstiness,
        "down_up_ratio": down_up_ratio,
        "flow_score": flow_score,
    }
    return derived


# ---------------------------------------------------------------------------
#  НОВОЕ: маппинг в 41 фичу под attack/vpn модели
# ---------------------------------------------------------------------------

def _build_model_features_41(flow: Mapping[str, object]) -> Dict[str, float]:
    """
    Построить dict с 41 фичей, которые ждут RandomForest-модели.

    flow — это твой "сырой" словарь потока (то, что летит в pipeline),
    в нём обычно есть примерно такое:
        duration, packets, bytes, payload_bytes, down_bytes, up_bytes,
        proto/sport/dport, iat_std, entropy, и т.д.

    Мы пробуем аккуратно выцепить всё, что можем, остальное — в нули.
    """
    base = dict(flow)
    derived = _derive_numeric_features(base)

    def g(*keys: str, default: float = 0.0) -> float:
        """Попробовать взять по нескольким потенциальным именам."""
        for k in keys:
            if k in base:
                return _safe_float(base.get(k))
            if k in derived:
                return _safe_float(derived.get(k))
        return default

    features: Dict[str, float] = {}

    # 1. protocol
    features["protocol"] = g("protocol", "proto", default=0.0)

    # 2. flow_duration
    features["flow_duration"] = g("flow_duration", "duration")

    # 3–4. total_fwd_packets / total_bwd_packets
    packets = g("packets")
    # если есть направленные — используем их:
    fwd_pkts = g("total_fwd_packets", "fwd_packets", "src2dst_packets", "up_packets")
    bwd_pkts = g("total_bwd_packets", "bwd_packets", "dst2src_packets", "down_packets")

    if fwd_pkts == 0 and bwd_pkts == 0 and packets > 0:
        # если ничего нет — считаем пополам, лучше чем по нулям
        fwd_pkts = packets / 2.0
        bwd_pkts = packets - fwd_pkts

    features["total_fwd_packets"] = fwd_pkts
    features["total_bwd_packets"] = bwd_pkts

    # 5–6. суммы байт вперёд/назад
    fwd_bytes = g("fwd_bytes", "src2dst_bytes", "up_bytes")
    bwd_bytes = g("bwd_bytes", "dst2src_bytes", "down_bytes")
    if fwd_bytes == 0 and bwd_bytes == 0:
        # fallback — делим общий bytes, если направленных нет
        total_bytes = g("bytes")
        if total_bytes > 0:
            fwd_bytes = total_bytes / 2.0
            bwd_bytes = total_bytes - fwd_bytes
    features["fwd_packets_length_total"] = fwd_bytes
    features["bwd_packets_length_total"] = bwd_bytes

    # 7–10. fwd_packet_length_* (если нет, оценим через средний размер pacкета)
    avg_pkt_size = g("avg_packet_size", "avg_pkt_size")
    features["fwd_packet_length_max"] = g("fwd_pkt_len_max", "src2dst_max_payload", default=avg_pkt_size)
    features["fwd_packet_length_min"] = g("fwd_pkt_len_min", "src2dst_min_payload", default=avg_pkt_size)
    features["fwd_packet_length_mean"] = g("fwd_pkt_len_mean", "src2dst_mean_payload", default=avg_pkt_size)
    features["fwd_packet_length_std"] = g("fwd_pkt_len_std", "src2dst_std_payload", default=0.0)

    # 11–14. bwd_packet_length_*
    features["bwd_packet_length_max"] = g("bwd_pkt_len_max", "dst2src_max_payload", default=avg_pkt_size)
    features["bwd_packet_length_min"] = g("bwd_pkt_len_min", "dst2src_min_payload", default=avg_pkt_size)
    features["bwd_packet_length_mean"] = g("bwd_pkt_len_mean", "dst2src_mean_payload", default=avg_pkt_size)
    features["bwd_packet_length_std"] = g("bwd_pkt_len_std", "dst2src_std_payload", default=0.0)

    # 15–16. flow_*_per_s
    features["flow_bytes_per_s"] = g("flow_bytes_per_s", "bytes_per_s")
    features["flow_packets_per_s"] = g("flow_packets_per_s", "pkts_per_s")

    # 17–20. flow_iat_*
    features["flow_iat_mean"] = g("flow_iat_mean", "iat_mean")
    features["flow_iat_std"] = g("flow_iat_std", "iat_std")
    features["flow_iat_max"] = g("flow_iat_max")
    features["flow_iat_min"] = g("flow_iat_min")

    # 21–25. fwd_iat_*
    features["fwd_iat_total"] = g("fwd_iat_total", "src2dst_iat_total")
    features["fwd_iat_mean"] = g("fwd_iat_mean", "src2dst_iat_mean")
    features["fwd_iat_std"] = g("fwd_iat_std", "src2dst_iat_std")
    features["fwd_iat_max"] = g("fwd_iat_max", "src2dst_iat_max")
    features["fwd_iat_min"] = g("fwd_iat_min", "src2dst_iat_min")

    # 26–30. bwd_iat_*
    features["bwd_iat_total"] = g("bwd_iat_total", "dst2src_iat_total")
    features["bwd_iat_mean"] = g("bwd_iat_mean", "dst2src_iat_mean")
    features["bwd_iat_std"] = g("bwd_iat_std", "dst2src_iat_std")
    features["bwd_iat_max"] = g("bwd_iat_max", "dst2src_iat_max")
    features["bwd_iat_min"] = g("bwd_iat_min", "dst2src_iat_min")

    # 31. down_up_ratio
    #    либо уже есть, либо считаем заново
    dur_ratio = g("down_up_ratio")
    if dur_ratio == 0.0:
        down_bytes = g("down_bytes")
        up_bytes = g("up_bytes")
        dur_ratio = down_bytes / up_bytes if up_bytes > 0 else 0.0
    features["down_up_ratio"] = dur_ratio

    # 32–37. packet_length_* + variance + avg_packet_size
    pkt_min = g("packet_length_min", "min_payload")
    pkt_max = g("packet_length_max", "max_payload")
    pkt_mean = g("packet_length_mean", "mean_payload", default=avg_pkt_size)
    pkt_std = g("packet_length_std", "std_payload")
    if pkt_std == 0.0 and pkt_mean == 0.0 and avg_pkt_size > 0:
        pkt_mean = avg_pkt_size

    features["packet_length_min"] = pkt_min
    features["packet_length_max"] = pkt_max
    features["packet_length_mean"] = pkt_mean
    features["packet_length_std"] = pkt_std
    features["packet_length_variance"] = pkt_std ** 2
    features["avg_packet_size"] = avg_pkt_size

    # 38–39. порты
    features["destination_port"] = g("destination_port", "dport", "dst_port")
    features["source_port"] = g("source_port", "sport", "src_port")

    # 40–41. init window bytes
    features["init_win_bytes_forward"] = g("init_win_bytes_forward")
    features["init_win_bytes_backward"] = g("init_win_bytes_backward")

    # Гарантируем, что ВСЕ 41 фича присутствует
    for name in MODEL_FEATURES_41:
        features.setdefault(name, 0.0)

    return features


# ---------------------------------------------------------------------------
#  ОСНОВНАЯ ФУНКЦИЯ extract_features
# ---------------------------------------------------------------------------

def extract_features(
    flow: Mapping[str, object],
    numeric_features: Sequence[str] = NUMERIC_FEATURES_DEFAULT,
    hash_features: Sequence[str] = HASH_FEATURES,
    num_hash_buckets: int = 32,
    expected_order: Optional[Sequence[str]] = None,
) -> FeatureVector:
    """
    Build a deterministic feature vector from heterogeneous flow data.

    Режимы:
      • если expected_order задан → строим фичи под attack/vpn модели
      • иначе → старый режим (duration/packets/... + hash_*)
    """

    # === НОВЫЙ РЕЖИМ: под attack/vpn RandomForest модели ===
    if expected_order:
        # 1) Строим полный набор 41 фич (или больше, если нужно)
        full_features = _build_model_features_41(flow)

        # 2) Отдаём в нужном порядке (expected_order обычно == MODEL_FEATURES_41)
        ordered_values: List[float] = []
        for name in expected_order:
            ordered_values.append(_safe_float(full_features.get(name, 0.0)))
        return FeatureVector(names=list(expected_order), values=np.array(ordered_values, dtype=float))

    # === СТАРЫЙ РЕЖИМ (generic numeric + hash features) ===
    base_numeric = _derive_numeric_features(flow)
    vector_values: List[float] = []
    vector_names: List[str] = []

    for name in numeric_features:
        vector_names.append(name)
        vector_values.append(float(base_numeric.get(name, _safe_float(flow.get(name)))))

    for feature in hash_features:
        hashed_name = f"hash_{feature}"
        vector_names.append(hashed_name)
        vector_values.append(_hash_feature(flow.get(feature), num_hash_buckets))

    return FeatureVector(names=vector_names, values=np.array(vector_values, dtype=float))


# ---------------------------------------------------------------------------
#  MERGE + REORDER HELPERS (как раньше)
# ---------------------------------------------------------------------------

def merge_feature_sources(*sources: Mapping[str, object]) -> Dict[str, object]:
    """Merge multiple dictionaries preferring the later ones."""
    merged: Dict[str, object] = {}
    for src in sources:
        if not src:
            continue
        merged.update(src)
    return merged


def ensure_feature_order(vector: FeatureVector, order: Optional[Sequence[str]]) -> FeatureVector:
    """Re-order existing vector to match expected feature order."""
    if not order:
        return vector
    index = {name: idx for idx, name in enumerate(vector.names)}
    values = np.array(
        [vector.values[index.get(name, -1)] if name in index else 0.0 for name in order],
        dtype=float,
    )
    return FeatureVector(names=list(order), values=values)
