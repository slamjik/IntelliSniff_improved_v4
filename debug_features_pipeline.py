"""
Отладочный прогон пайплайна: Flow -> _to_feature_input -> extract_features_from_flow -> predictor.predict

Запуск (из venv, из корня проекта):
    python debug_features_pipeline.py
"""

import logging
import time
import json

from traffic_analyzer.streaming import Flow, FlowKey
from traffic_analyzer.features import extract_features_from_flow
from traffic_analyzer.ml_runtime import get_predictor


def _dump_section(title: str, data: dict, keys=None):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)
    if keys is None:
        # печатаем первые 40 ключей
        for i, (k, v) in enumerate(data.items()):
            if i >= 40:
                print("... (остальное обрезано)")
                break
            print(f"{k:30s} = {v}")
    else:
        for k in keys:
            print(f"{k:30s} = {data.get(k, '<нет ключа>')}")


def build_fake_flow() -> Flow:
    """
    Создаём искусственный поток, чтобы гарантированно были НЕ нулевые значения.
    Это обход всего capture, тупо руками кормим Flow пакетами.
    """
    now = time.time()
    key = FlowKey(
        src="10.0.0.10",
        dst="1.1.1.1",
        sport=54321,
        dport=443,
        proto="TCP",
    )
    flow = Flow(now, key, iface="debug0")

    # Имитируем 5 пакетов вперёд и 3 назад
    ts = now
    for i in range(5):
        pkt_dict = {
            "ts": ts,
            "src": "10.0.0.10",
            "dst": "1.1.1.1",
            "sport": 54321,
            "dport": 443,
            "proto": "TCP",
            "length": 100 + i * 20,
            "iface": "debug0",
            "application_name": "DEBUG_APP",
        }
        flow.update(ts, pkt_dict["length"], pkt_dict, is_forward=True)
        ts += 0.01

    for i in range(3):
        pkt_dict = {
            "ts": ts,
            "src": "1.1.1.1",
            "dst": "10.0.0.10",
            "sport": 443,
            "dport": 54321,
            "proto": "TCP",
            "length": 150 + i * 30,
            "iface": "debug0",
            "application_name": "DEBUG_APP",
        }
        flow.update(ts, pkt_dict["length"], pkt_dict, is_forward=False)
        ts += 0.015

    return flow


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    print("=== DEBUG PIPELINE START ===")

    # 1) Строим фейковый поток
    flow = build_fake_flow()

    # 2) Сырые признаки из streaming.Flow._to_feature_input()
    raw_features = flow._to_feature_input()
    _dump_section("STEP 1: _to_feature_input() (snake_case)", raw_features)

    # 3) Признаки после features.extract_features_from_flow (наш мост)
    bridged_features = extract_features_from_flow(raw_features)
    interesting = [
        "flow_duration", "flow duration",
        "flow_iat_mean", "flow iat mean",
        "flow_iat_max", "flow iat max",
        "flow_iat_min", "flow iat min",
        "fwd_packets_length_total", "fwd packets length total",
        "bwd_packets_length_total", "bwd packets length total",
        "pkts_per_s", "flow packets/s",
        "bytes_per_s", "flow bytes/s",
        "avg_pkt_size", "avg packet size",
        "init_win_bytes_forward", "init win bytes forward",
        "init_win_bytes_backward", "init win bytes backward",
        "destination_port", "destination port",
        "source_port", "source port",
    ]
    _dump_section("STEP 2: extract_features_from_flow() (bridge)", bridged_features, interesting)

    # 4) Гоним это в модель
    predictor = get_predictor()
    payload = dict(bridged_features)
    payload["iface"] = flow.iface
    payload["duration"] = bridged_features.get("duration", bridged_features.get("flow_duration"))

    print("\nОтправляем в модель payload с количеством признаков:", len(payload))

    res = predictor.predict(payload, task="attack")

    print("\n=== MODEL RESULT ===")
    print(json.dumps(res, indent=2, ensure_ascii=False))

    # 5) Если есть explanation — смотрим, какие фичи там фигурируют
    explanation = res.get("explanation") or []
    if isinstance(explanation, dict):
        expl_items = explanation.items()
    else:
        expl_items = explanation

    print("\n=== EXPLANATION KEYS (TOP 30) ===")
    i = 0
    for item in expl_items:
        if i >= 30:
            print("... (остальное обрезано)")
            break
        print(item)
        i += 1

    print("\n=== DEBUG PIPELINE END ===")


if __name__ == "__main__":
    main()
