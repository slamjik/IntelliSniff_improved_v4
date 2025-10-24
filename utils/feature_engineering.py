"""Feature engineering helpers for IntelliSniff models.

The helpers are intentionally lightweight so that they can be reused both in the
streaming inference pipeline and in offline training scripts.  They normalise
heterogeneous flow dictionaries into a consistent numerical feature vector and
optionally include hashed representations of textual fields (SNI/JA3/etc.).
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import blake2b
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import numpy as np

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


@dataclass(frozen=True)
class FeatureVector:
    """Container for ordered feature vectors."""

    names: Sequence[str]
    values: np.ndarray

    def as_dict(self) -> Dict[str, float]:
        return {name: float(value) for name, value in zip(self.names, self.values)}


def _safe_float(value: object, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float, np.number)):
        return float(value)
    try:
        return float(str(value).strip())
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
        if np.isnan(value):
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


def extract_features(flow: Mapping[str, object],
                     numeric_features: Sequence[str] = NUMERIC_FEATURES_DEFAULT,
                     hash_features: Sequence[str] = HASH_FEATURES,
                     num_hash_buckets: int = 32) -> FeatureVector:
    """Build a deterministic feature vector from heterogeneous flow data.

    Parameters
    ----------
    flow:
        Raw flow dictionary produced by capture/streaming pipeline.
    numeric_features:
        Names of numeric features to include; missing ones are synthesised.
    hash_features:
        Textual fields that will be transformed into hashed numerical buckets.
    num_hash_buckets:
        Resolution of hash buckets for categorical features.
    """

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
    values = np.array([vector.values[index.get(name, -1)] if name in index else 0.0 for name in order], dtype=float)
    return FeatureVector(names=list(order), values=values)
