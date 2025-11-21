"""
Inference-пайплайн для потоковых предсказаний IntelliSniff.

Исправлено:
  ✔ извлекаем feature_names из активной модели (ModelInfo)
  ✔ переставляем признаки под 41-фичевую модель обучения
  ✔ extract_features теперь работает с expected_order
  ✔ полная совместимость с bundle dict и старым ModelManager
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Mapping, Optional

import pandas as pd

from utils.feature_engineering import (
    ensure_feature_order,
    extract_features,
    merge_feature_sources,
)

log = logging.getLogger("ml.inference")


class StreamPredictor:
    """
    Главный класс для онлайновых предсказаний.

    Использование:
        predictor = StreamPredictor(model_manager, drift_detector, auto_updater)
        result = predictor.predict(flow_dict, task="attack")
    """

    def __init__(
        self,
        model_manager,
        drift_detector=None,
        auto_updater=None,
        buffer_path: Optional[str] = None,
        buffer_size: int = 200,
    ):
        self.model_manager = model_manager
        self.drift_detector = drift_detector
        self.auto_updater = auto_updater

        # буфер последних предсказаний для UI
        self.buffer_path = Path(
            buffer_path
            or Path(__file__).resolve().parent / "data" / "live_buffer.json"
        )
        self.buffer_path.parent.mkdir(parents=True, exist_ok=True)

        self.buffer_size = buffer_size
        self._buffer: Deque[Dict[str, object]] = deque(maxlen=buffer_size)
        self._load_buffer()

    # ==========================================================================
    # BUFFER LOAD/SAVE
    # ==========================================================================

    def _load_buffer(self) -> None:
        if not self.buffer_path.exists():
            return
        try:
            raw = json.loads(self.buffer_path.read_text(encoding="utf-8"))
            for item in raw[-self.buffer_size:]:
                self._buffer.append(item)
        except Exception as exc:
            log.warning("Failed to load live buffer: %s", exc)

    def _flush_buffer(self) -> None:
        try:
            self.buffer_path.write_text(
                json.dumps(list(self._buffer), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            log.warning("Unable to persist live buffer: %s", exc)

    # ==========================================================================
    # MAIN PREDICT
    # ==========================================================================

    def predict(
        self,
        features: Mapping[str, object],
        task: str = "attack",
        metadata: Optional[Mapping[str, object]] = None,
    ) -> Dict[str, object]:
        """
        Основной метод предсказания.
        """

        # 1. Сливаем все источники признаков
        merged = merge_feature_sources(features, metadata or {})

        # 2. Берём активную модель (нужно для порядка признаков!)
        active = self.model_manager.get_active_model_info(task)
        if not active:
            return {"label": "unknown", "score": 0.0, "reason": "no active model"}

        # --- извлекаем список признаков модели ---
        if hasattr(active, "feature_names"):
            target_features = list(getattr(active, "feature_names", []) or [])
        elif isinstance(active, dict):
            target_features = list(
                active.get("feature_names")
                or active.get("features")
                or []
            )
        else:
            target_features = []

        # --- версия модели ---
        if hasattr(active, "version"):
            version = int(active.version)
        elif isinstance(active, dict):
            version = int(active.get("version", 1))
        else:
            version = 1

        # 3. Генерация FeatureVector → строго в порядке target_features
        if target_features:
            vector = extract_features(
                merged,
                expected_order=target_features
            )
        else:
            log.warning("⚠ No feature_names in active model; fallback to raw extract")
            vector = extract_features(merged)

        # 4. DataFrame для sklearn
        df = pd.DataFrame([vector.values], columns=vector.names)

        # 5. Загружаем модель
        model_obj = self.model_manager._load_model_object(task, version)
        if isinstance(model_obj, dict) and "model" in model_obj:
            model = model_obj["model"]
        else:
            model = model_obj

        # 6. Предсказание
        try:
            raw_pred = model.predict(df)[0]
            label = int(raw_pred)
        except Exception as exc:
            log.error(f"Prediction failed: {exc}")
            return {"label": "unknown", "score": 0.0, "reason": str(exc)}

        try:
            score = float(max(model.predict_proba(df)[0]))
        except Exception:
            score = 0.0

        result = {
            "label": label,
            "score": score,
            "task": task,
            "version": version,
            "timestamp": time.time(),
        }

        # 7. Explanation
        explanation = self._explain(model, vector)
        result["explanation"] = explanation

        # 8. Drift detector
        if self.drift_detector:
            try:
                drift = self.drift_detector.update(task, vector)
                result["drift"] = drift
            except Exception:
                pass

        # 9. Auto-updater
        if self.auto_updater:
            try:
                self.auto_updater.record_prediction(task, result, vector)
            except Exception:
                pass

        # 10. Buffer
        self._buffer.append(result)
        self._flush_buffer()

        return result

    # ==========================================================================
    # BATCH
    # ==========================================================================

    def batch_predict(self, rows: Iterable[Mapping[str, object]], task="attack"):
        return [self.predict(row, task=task) for row in rows]

    # ==========================================================================
    # EXPLANATION
    # ==========================================================================

    def _explain(self, model, vector):
        try:
            importances = getattr(model, "feature_importances_", None)
            if importances is None:
                return []

            pairs = list(zip(vector.names, importances))
            pairs.sort(key=lambda x: abs(x[1]), reverse=True)

            explanation = []
            for name, imp in pairs[:5]:
                idx = vector.names.index(name)
                explanation.append({
                    "feature": name,
                    "importance": float(imp),
                    "value": float(vector.values[idx]),
                })

            return explanation
        except Exception:
            return []

    # ==========================================================================
    # ACCESSOR
    # ==========================================================================

    def get_buffer(self) -> List[Dict[str, object]]:
        return list(self._buffer)
