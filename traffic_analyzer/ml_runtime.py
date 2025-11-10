"""Shared ML runtime singletons for IntelliSniff (updated for bundle model)."""
from __future__ import annotations

import logging
import os
from functools import lru_cache

from ml.auto_updater import AutoUpdater
from ml.drift_detector import DriftDetector
from ml.inference import StreamPredictor
from ml.model_manager import ModelManager

from .classification import load_model  # 👈 теперь используется твоя функция загрузки модели

log = logging.getLogger("ta.ml_runtime")


@lru_cache(maxsize=1)
def get_model_manager() -> ModelManager:
    """
    Возвращает менеджер модели.
    Если bundle (model.joblib) существует, загружаем его напрямую через load_model().
    """
    manager = ModelManager()

    try:
        model, features = load_model()
        manager.model = model
        manager.feature_names = features
        log.info(f"✅ Loaded external model.joblib bundle ({len(features)} features)")
    except Exception as e:
        log.warning(f"⚠️ Could not load model.joblib directly, fallback to ModelManager default: {e}")

    return manager


@lru_cache(maxsize=1)
def get_drift_detector() -> DriftDetector:
    """Возвращает детектор дрейфа для текущей модели."""
    manager = get_model_manager()
    return DriftDetector(metrics_path=str(manager.metrics_path))


@lru_cache(maxsize=1)
def get_auto_updater() -> AutoUpdater:
    """Автообновление модели при деградации."""
    manager = get_model_manager()
    drift = get_drift_detector()
    return AutoUpdater(manager, drift_detector=drift)


@lru_cache(maxsize=1)
def get_predictor() -> StreamPredictor:
    """
    Создаёт основной объект предсказателя (StreamPredictor),
    использующий bundle-модель и системы дрейфа/обновления.
    """
    manager = get_model_manager()
    drift = get_drift_detector()
    updater = get_auto_updater()
    predictor = StreamPredictor(manager, drift_detector=drift, auto_updater=updater)

    # 💡 Если в менеджере уже есть bundle-модель, применяем её
    if getattr(manager, "model", None):
        predictor.model = manager.model
        predictor.features = manager.feature_names
        log.info("🧠 StreamPredictor linked to external RandomForest model bundle")

    return predictor
