"""
Shared ML runtime singletons for IntelliSniff (updated for new ModelManager).
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from ml.model_manager import ModelManager
from ml.drift_detector import DriftDetector
from ml.auto_updater import AutoUpdater
from ml.inference import StreamPredictor

log = logging.getLogger("ta.ml_runtime")


@lru_cache(maxsize=1)
def get_model_manager() -> ModelManager:
    """
    Создаёт ModelManager с корректным путём base_dir.
    base_dir = IntelliSniff_improved_v4/ml
    """
    # traffic_analyzer/ml_runtime.py → .. → ml/
    base_dir = Path(__file__).resolve().parent.parent / "ml"
    base_dir = base_dir.resolve()

    log.info(f"📁 ModelManager base_dir = {base_dir}")

    return ModelManager(base_dir)


@lru_cache(maxsize=1)
def get_drift_detector() -> DriftDetector:
    """Создаёт детектор дрейфа."""
    manager = get_model_manager()
    return DriftDetector(metrics_path=str(manager.metrics_path))


@lru_cache(maxsize=1)
def get_auto_updater() -> AutoUpdater:
    """Автоматическое обновление модели."""
    manager = get_model_manager()
    drift = get_drift_detector()
    return AutoUpdater(manager, drift_detector=drift)


@lru_cache(maxsize=1)
def get_predictor() -> StreamPredictor:
    """
    Основной объект предсказателя.
    StreamPredictor сам подгрузит:
      - активную attack модель
      - активную vpn модель
    """
    manager = get_model_manager()
    drift = get_drift_detector()
    updater = get_auto_updater()

    predictor = StreamPredictor(
        model_manager=manager,
        drift_detector=drift,
        auto_updater=updater
    )

    log.info("🧠 StreamPredictor initialized with new ModelManager")

    return predictor
