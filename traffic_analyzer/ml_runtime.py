"""Shared ML runtime singletons for IntelliSniff."""
from __future__ import annotations

from functools import lru_cache

from ml.auto_updater import AutoUpdater
from ml.drift_detector import DriftDetector
from ml.inference import StreamPredictor
from ml.model_manager import ModelManager


@lru_cache(maxsize=1)
def get_model_manager() -> ModelManager:
    return ModelManager()


@lru_cache(maxsize=1)
def get_drift_detector() -> DriftDetector:
    manager = get_model_manager()
    return DriftDetector(metrics_path=str(manager.metrics_path))


@lru_cache(maxsize=1)
def get_auto_updater() -> AutoUpdater:
    manager = get_model_manager()
    drift = get_drift_detector()
    return AutoUpdater(manager, drift_detector=drift)


@lru_cache(maxsize=1)
def get_predictor() -> StreamPredictor:
    manager = get_model_manager()
    drift = get_drift_detector()
    updater = get_auto_updater()
    return StreamPredictor(manager, drift_detector=drift, auto_updater=updater)
