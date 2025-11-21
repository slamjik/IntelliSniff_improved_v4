"""Feature bridge for streaming flows.

Ensures full compatibility with old models AND the new streaming engine by
providing a consistent feature dictionary for the ML predictor.
"""

from __future__ import annotations
from typing import Dict, Any
import logging

log = logging.getLogger("ta.features")


# ============================================================
# HELPERS
# ============================================================

def _to_float(x) -> float:
    if x is None:
        return 0.0
    try:
        return float(x)
    except Exception:
        try:
            return float(int(x))
        except Exception:
            return 0.0


def _safe_div(num: float, den: float) -> float:
    try:
        num = float(num)
        den = float(den)
        return num / den if den != 0 else 0.0
    except Exception:
        return 0.0


# ============================================================
# MAIN BRIDGE
# ============================================================

def extract_features_from_flow(flow: Dict[str, Any]) -> Dict[str, float]:
    """
    Мост (bridge) между:

    streaming.py → snake_case
    моделью      → CICFlowMeter (flow duration, fwd packets length total, ...)

    Возвращает объединённый набор метрик:
    - оригинальные snake_case (новый формат)
    - CICFlowMeter-style (старый формат)
    """

    # ------------------------------------------
    # 1. СНАЧАЛА НОРМАЛИЗУЕМ ВСЕ SNAKE_CASE
    # ------------------------------------------
    base: Dict[str, float] = {}
    for k, v in flow.items():
        base[k] = _to_float(v)

    # ------------------------------------------
    # 2. DERIVED МЕТРИКИ
    # ------------------------------------------
    duration = base.get("flow_duration", base.get("duration", 0.0))
    base.setdefault("duration", duration)
    packets = base.get("packets", 0.0)
    bytes_total = base.get("bytes", 0.0)

    if duration > 0:
        pkts_per_s = packets / duration
        bytes_per_s = bytes_total / duration
    else:
        pkts_per_s = packets
        bytes_per_s = bytes_total

    base.setdefault("pkts_per_s", pkts_per_s)
    base.setdefault("bytes_per_s", bytes_per_s)
    base.setdefault("avg_pkt_size", _safe_div(bytes_total, packets))

    # ------------------------------------------
    # 3. СОЗДАЕМ CIC-ВЕРСИИ ТЕХ ЖЕ ПОЛЕЙ
    # ------------------------------------------
    cic: Dict[str, float] = {
        # БАЗОВЫЕ ОСНОВНЫЕ ПОЛЯ
        "flow duration": duration,
        "flow iat mean": base.get("flow_iat_mean", 0.0),
        "flow iat max": base.get("flow_iat_max", 0.0),
        "flow iat min": base.get("flow_iat_min", 0.0),

        "total fwd packets": base.get("total_fwd_packets", 0.0),
        "total backward packets": base.get("total_bwd_packets", 0.0),

        "fwd packets length total": base.get("fwd_packets_length_total", 0.0),
        "bwd packets length total": base.get("bwd_packets_length_total", 0.0),

        # SPEED METRICS
        "flow packets/s": base.get("pkts_per_s", base.get("flow_packets_per_s", 0.0)),
        "flow bytes/s": base.get("bytes_per_s", base.get("flow_bytes_per_s", 0.0)),

        # LENGTH METRICS
        "packet length min": base.get("packet_length_min", base.get("min_packet_length", 0.0)),
        "packet length max": base.get("packet_length_max", base.get("max_packet_length", 0.0)),
        "packet length mean": base.get("packet_length_mean", 0.0),
        "packet length std": base.get("packet_length_std", 0.0),

        "avg packet size": base.get("avg_pkt_size", 0.0),

        # PORTS
        "destination port": base.get("destination_port", 0.0),
        "source port": base.get("source_port", 0.0),

        # RATIO
        "down/up ratio": base.get("down_up_ratio", 0.0),

        # WINDOWS
        "init win bytes forward": base.get("init_win_bytes_forward", 0.0),
        "init win bytes backward": base.get("init_win_bytes_backward", 0.0),
    }

    # ------------------------------------------
    # 4. ОБЪЕДИНЯЕМ SNAKE_CASE и CIC
    # ------------------------------------------
    features = {**base, **cic}

    # ДЕБАГ В ЛОГИ
    try:
        sample = {k: features[k] for k in list(features.keys())[:12]}
        log.debug("Features OK → sample: %s", sample)
    except Exception:
        pass

    return features
