"""Feature engineering utilities for IntelliSniff models.

This module produces the exact 41 CICFlowMeter-style features expected by
trained models. It is resilient to partially populated flow dictionaries coming
from packet aggregation or NFStream and guarantees deterministic ordering with
no NaN values.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Mapping, MutableMapping, Optional, Sequence

import numpy as np

# Ordered feature list expected by the joblib bundles
MODEL_FEATURES_41: Sequence[str] = (
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


@dataclass(frozen=True)
class FeatureVector:
    names: Sequence[str]
    values: np.ndarray

    def as_dict(self) -> Dict[str, float]:
        return {name: float(value) for name, value in zip(self.names, self.values)}


# ---------------------------------------------------------------------------
# SAFE HELPERS
# ---------------------------------------------------------------------------

def _clean_number(value: object, default: float = 0.0) -> float:
    """Convert to finite float; fall back to default on failure/NaN."""
    if value is None:
        return default
    if isinstance(value, bool):
        return float(value)
    try:
        num = float(value)
    except Exception:
        try:
            num = float(str(value).strip())
        except Exception:
            return default
    if math.isnan(num) or math.isinf(num):
        return default
    return num


def _proto_to_number(proto: object) -> float:
    mapping = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58, "ARP": 2054}
    if proto is None:
        return 0.0
    try:
        return float(int(proto))
    except Exception:
        return float(mapping.get(str(proto).upper(), 0))


def _first_existing(data: Mapping[str, object], keys: Sequence[str], default: float = 0.0) -> float:
    for key in keys:
        if key in data:
            return _clean_number(data.get(key), default=default)
    return default


# ---------------------------------------------------------------------------
# CORE 41-FEATURE BUILDER
# ---------------------------------------------------------------------------

def _compute_directional_lengths(data: Mapping[str, object], prefix: str, total_bytes: float, packets: float) -> Dict[str, float]:
    max_v = _first_existing(data, [f"{prefix}_packet_length_max", f"{prefix}_pkt_len_max", f"{prefix}_max_payload"], default=None)
    min_v = _first_existing(data, [f"{prefix}_packet_length_min", f"{prefix}_pkt_len_min", f"{prefix}_min_payload"], default=None)
    mean_v = _first_existing(data, [f"{prefix}_packet_length_mean", f"{prefix}_pkt_len_mean", f"{prefix}_mean_payload"], default=None)
    std_v = _first_existing(data, [f"{prefix}_packet_length_std", f"{prefix}_pkt_len_std", f"{prefix}_std_payload"], default=None)

    if packets > 0 and mean_v in (None, 0):
        mean_v = total_bytes / packets if packets else 0.0
    if packets <= 0 and (mean_v is None or mean_v == 0):
        mean_v = 0.0
    if min_v is None:
        min_v = mean_v
    if max_v is None:
        max_v = mean_v
    if std_v is None:
        std_v = 0.0

    return {
        "max": _clean_number(max_v),
        "min": _clean_number(min_v),
        "mean": _clean_number(mean_v),
        "std": _clean_number(std_v),
    }


def _compute_iat_stats(data: Mapping[str, object], prefix: str, packets: float, duration: float) -> Dict[str, float]:
    mean_v = _first_existing(data, [f"{prefix}_iat_mean"], default=None)
    std_v = _first_existing(data, [f"{prefix}_iat_std"], default=None)
    max_v = _first_existing(data, [f"{prefix}_iat_max"], default=None)
    min_v = _first_existing(data, [f"{prefix}_iat_min"], default=None)
    total_v = _first_existing(data, [f"{prefix}_iat_total"], default=None)

    count_intervals = max(0.0, packets - 1.0)
    if count_intervals > 0 and duration > 0 and mean_v in (None, 0):
        mean_v = duration / count_intervals
    if total_v in (None, 0) and mean_v not in (None, 0):
        total_v = mean_v * count_intervals
    if min_v is None:
        min_v = mean_v or 0.0
    if max_v is None:
        max_v = mean_v or 0.0
    if std_v is None:
        std_v = 0.0

    return {
        "total": _clean_number(total_v),
        "mean": _clean_number(mean_v),
        "std": _clean_number(std_v),
        "max": _clean_number(max_v),
        "min": _clean_number(min_v),
    }


def build_feature_dict(flow: Mapping[str, object]) -> Dict[str, float]:
    """Return a dict with all 41 model features filled and cleaned."""
    data: MutableMapping[str, object] = dict(flow or {})

    # Duration
    duration = _first_existing(data, ["flow_duration", "duration"], default=None)
    if duration in (None, 0):
        start = _first_existing(data, ["first_ts", "start_ts", "start_time"], default=None)
        end = _first_existing(data, ["last_ts", "end_ts", "end_time"], default=None)
        if start not in (None, 0) and end not in (None, 0):
            duration = max(0.0, _clean_number(end) - _clean_number(start))
    duration = _clean_number(duration)

    # Packet and byte counters
    fwd_packets = _first_existing(data, ["total_fwd_packets", "fwd_packets", "src2dst_packets", "up_packets"], default=0.0)
    bwd_packets = _first_existing(data, ["total_bwd_packets", "bwd_packets", "dst2src_packets", "down_packets"], default=0.0)
    total_packets_reported = _first_existing(data, ["packets", "total_packets"], default=0.0)
    if fwd_packets == 0 and bwd_packets == 0 and total_packets_reported > 0:
        fwd_packets = total_packets_reported / 2.0
        bwd_packets = total_packets_reported - fwd_packets
    total_packets = fwd_packets + bwd_packets

    fwd_bytes = _first_existing(data, ["fwd_packets_length_total", "fwd_bytes", "src2dst_bytes", "up_bytes"], default=0.0)
    bwd_bytes = _first_existing(data, ["bwd_packets_length_total", "bwd_bytes", "dst2src_bytes", "down_bytes"], default=0.0)
    total_bytes = fwd_bytes + bwd_bytes
    if total_bytes == 0:
        total_bytes = _first_existing(data, ["bytes", "total_bytes"], default=0.0)
        if total_bytes and fwd_bytes == 0 and bwd_bytes == 0:
            fwd_bytes = total_bytes / 2.0
            bwd_bytes = total_bytes - fwd_bytes

    # Packet length statistics per direction
    fwd_len = _compute_directional_lengths(data, "fwd", fwd_bytes, fwd_packets)
    bwd_len = _compute_directional_lengths(data, "bwd", bwd_bytes, bwd_packets)

    # Overall packet length statistics
    pkt_min = _first_existing(data, ["packet_length_min", "min_payload", "min_packet_length"], default=None)
    pkt_max = _first_existing(data, ["packet_length_max", "max_payload", "max_packet_length"], default=None)
    pkt_mean = _first_existing(data, ["packet_length_mean", "mean_payload"], default=None)
    pkt_std = _first_existing(data, ["packet_length_std", "std_payload"], default=None)

    if pkt_mean in (None, 0) and total_packets > 0:
        pkt_mean = total_bytes / total_packets
    if pkt_min is None or pkt_min == 0:
        pkt_min = min(fwd_len["min"], bwd_len["min"]) if total_packets > 0 else 0.0
    if pkt_max is None or pkt_max == 0:
        pkt_max = max(fwd_len["max"], bwd_len["max"]) if total_packets > 0 else 0.0
    if pkt_std is None:
        pkt_std = 0.0
    pkt_variance = _clean_number(pkt_std) ** 2

    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0.0

    # Rates
    flow_packets_per_s = total_packets / duration if duration > 0 else total_packets
    flow_bytes_per_s = total_bytes / duration if duration > 0 else total_bytes

    # IAT stats
    flow_iat = _compute_iat_stats(data, "flow", total_packets, duration)
    fwd_iat = _compute_iat_stats(data, "fwd", fwd_packets, duration)
    bwd_iat = _compute_iat_stats(data, "bwd", bwd_packets, duration)

    # Ratio
    down_up_ratio = 0.0
    if fwd_bytes > 0:
        down_up_ratio = bwd_bytes / fwd_bytes

    # Ports and TCP windows
    destination_port = _first_existing(data, ["destination_port", "dport", "dst_port"], default=0.0)
    source_port = _first_existing(data, ["source_port", "sport", "src_port"], default=0.0)
    init_win_bytes_forward = _first_existing(data, ["init_win_bytes_forward", "init_win_fwd"], default=0.0)
    init_win_bytes_backward = _first_existing(data, ["init_win_bytes_backward", "init_win_bwd"], default=0.0)

    protocol = _first_existing(data, ["protocol"], default=None)
    if protocol in (None, 0):
        protocol = _proto_to_number(data.get("proto"))
    else:
        protocol = _proto_to_number(protocol)

    features: Dict[str, float] = {
        "protocol": protocol,
        "flow_duration": duration,
        "total_fwd_packets": fwd_packets,
        "total_bwd_packets": bwd_packets,
        "fwd_packets_length_total": fwd_bytes,
        "bwd_packets_length_total": bwd_bytes,
        "fwd_packet_length_max": fwd_len["max"],
        "fwd_packet_length_min": fwd_len["min"],
        "fwd_packet_length_mean": fwd_len["mean"],
        "fwd_packet_length_std": fwd_len["std"],
        "bwd_packet_length_max": bwd_len["max"],
        "bwd_packet_length_min": bwd_len["min"],
        "bwd_packet_length_mean": bwd_len["mean"],
        "bwd_packet_length_std": bwd_len["std"],
        "flow_bytes_per_s": flow_bytes_per_s,
        "flow_packets_per_s": flow_packets_per_s,
        "flow_iat_mean": flow_iat["mean"],
        "flow_iat_std": flow_iat["std"],
        "flow_iat_max": flow_iat["max"],
        "flow_iat_min": flow_iat["min"],
        "fwd_iat_total": fwd_iat["total"],
        "fwd_iat_mean": fwd_iat["mean"],
        "fwd_iat_std": fwd_iat["std"],
        "fwd_iat_max": fwd_iat["max"],
        "fwd_iat_min": fwd_iat["min"],
        "bwd_iat_total": bwd_iat["total"],
        "bwd_iat_mean": bwd_iat["mean"],
        "bwd_iat_std": bwd_iat["std"],
        "bwd_iat_max": bwd_iat["max"],
        "bwd_iat_min": bwd_iat["min"],
        "down_up_ratio": down_up_ratio,
        "packet_length_min": _clean_number(pkt_min),
        "packet_length_max": _clean_number(pkt_max),
        "packet_length_mean": _clean_number(pkt_mean),
        "packet_length_std": _clean_number(pkt_std),
        "packet_length_variance": pkt_variance,
        "avg_packet_size": _clean_number(avg_packet_size),
        "destination_port": destination_port,
        "source_port": source_port,
        "init_win_bytes_forward": init_win_bytes_forward,
        "init_win_bytes_backward": init_win_bytes_backward,
    }

    # Ensure all fields exist and are finite
    for name in MODEL_FEATURES_41:
        features[name] = _clean_number(features.get(name, 0.0))

    return features


def extract_features(flow: Mapping[str, object], expected_order: Optional[Sequence[str]] = None) -> FeatureVector:
    feature_dict = build_feature_dict(flow)
    order = list(expected_order) if expected_order else list(MODEL_FEATURES_41)
    values = np.array([feature_dict.get(name, 0.0) for name in order], dtype=float)
    return FeatureVector(names=order, values=values)


# ---------------------------------------------------------------------------
# MERGE HELPERS
# ---------------------------------------------------------------------------

def merge_feature_sources(*sources: Mapping[str, object]) -> Dict[str, object]:
    merged: Dict[str, object] = {}
    for src in sources:
        if not src:
            continue
        merged.update(src)
    return merged


def ensure_feature_order(vector: FeatureVector, order: Optional[Sequence[str]]) -> FeatureVector:
    if not order:
        return vector
    index = {name: idx for idx, name in enumerate(vector.names)}
    values = np.array([vector.values[index.get(name, -1)] if name in index else 0.0 for name in order], dtype=float)
    return FeatureVector(names=list(order), values=values)
