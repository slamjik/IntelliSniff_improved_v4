"""
Inference-пайплайн для потоковых предсказаний IntelliSniff.

Особенности:
  - принимает сырые признаки (features + metadata)
  - приводит их к FeatureVector через utils.feature_engineering.extract_features
  - упорядочивает признаки под конкретную обученную модель
  - аккуратно работает с разными версиями ModelManager:
      * get_active_model_info может вернуть dict или ModelInfo
      * _load_model_object может вернуть sklearn-модель или bundle(dict)
  - пишет все предсказания в live_buffer.json (для UI)
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

        :param features: словарь с признаками по потоку
        :param task: "attack" / "vpn" (и т.п.)
        :param metadata: дополнительная инфа (iface, host, и т.д.)
        """

        # 1. Склеиваем фичи и метаданные в один dict
        merged = merge_feature_sources(features, metadata or {})

        # 2. Превращаем всё это в FeatureVector (names + values)
        vector = extract_features(merged)

        # 3. Берём активную модель
        active = self.model_manager.get_active_model_info(task)
        if not active:
            return {"label": "unknown", "score": 0.0, "reason": "no active model"}

        # --- аккуратно достаём версию и список признаков из active ---
        # active может быть ModelInfo или dict
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

        if hasattr(active, "version"):
            version = int(active.version)
        elif isinstance(active, dict):
            version = int(active.get("version", 1))
        else:
            version = 1

        # если по какой-то причине список признаков пустой — работаем как есть
        if not target_features:
            log.warning(
                "No feature_names for task=%s, using raw FeatureVector order", task
            )
            ordered = vector
        else:
            # 4. Переставляем вектор под нужный порядок фичей модели
            ordered = ensure_feature_order(vector, target_features)

        # 5. Готовим DataFrame для sklearn
        df = pd.DataFrame([ordered.values], columns=ordered.names)

        # 6. Загружаем объект модели
        model_obj = self.model_manager._load_model_object(task, version)

        # _load_model_object может вернуть:
        #   • чистую sklearn-модель
        #   • bundle dict { "model": ..., "features": ..., ... }
        if isinstance(model_obj, dict) and "model" in model_obj:
            model = model_obj["model"]
        else:
            model = model_obj

        # 7. Предсказание
        try:
            raw_pred = model.predict(df)[0]
            label = int(raw_pred)
        except Exception as exc:
            log.error("Prediction failed for task=%s: %s", task, exc)
            return {
                "label": "unknown",
                "score": 0.0,
                "reason": f"prediction failed: {exc}",
            }

        try:
            proba_arr = model.predict_proba(df)[0]
            proba = float(max(proba_arr))
        except Exception:
            # если у модели нет predict_proba
            proba = 0.0

        payload = {
            "label": label,
            "score": proba,
            "task": task,
            "version": version,
        }

        # 8. Explanation (feature importances + реальные значения фичей)
        explanation = self._explain(model, ordered)

        result = {
            **payload,
            "explanation": explanation,
            "timestamp": time.time(),
        }

        # 9. Пишем в live_buffer
        self._buffer.append(result)
        self._flush_buffer()

        # 10. Drift detector
        if self.drift_detector:
            try:
                drift = self.drift_detector.update(task, ordered)
                result["drift"] = drift
            except Exception as exc:
                log.debug("DriftDetector error: %s", exc)

        # 11. Auto-updater
        if self.auto_updater:
            try:
                self.auto_updater.record_prediction(task, result, ordered)
            except Exception as exc:
                log.debug("AutoUpdater error: %s", exc)

        return result

    # ==========================================================================
    # BATCH
    # ==========================================================================

    def batch_predict(
        self,
        rows: Iterable[Mapping[str, object]],
        task: str = "attack",
    ) -> List[Dict[str, object]]:
        """
        Батчевый режим (используется для оффлайн-проверок / отладки).
        """
        return [self.predict(row, task=task) for row in rows]

    # ==========================================================================
    # EXPLANATION
    # ==========================================================================

    def _explain(self, model, ordered_vector) -> List[Dict[str, float]]:
        """
        Строим простое объяснение:
          - берём feature_importances_ у модели (если есть)
          - сортируем по абсолютной важности
          - показываем топ-5 важнейших признаков с их значениями
        """
        try:
            importances = getattr(model, "feature_importances_", None)
            if importances is None:
                return []

            names = list(ordered_vector.names)
            values = list(ordered_vector.values)

            pairs = list(zip(names, importances))
            pairs.sort(key=lambda x: abs(x[1]), reverse=True)

            explanation: List[Dict[str, float]] = []
            for name, weight in pairs[:5]:
                try:
                    idx = names.index(name)
                    val = float(values[idx])
                except Exception:
                    val = 0.0
                explanation.append(
                    {
                        "feature": name,
                        "importance": float(weight),
                        "value": val,
                    }
                )

            return explanation

        except Exception as exc:
            log.debug("Failed to build explanation: %s", exc)
            return []

    # ==========================================================================
    # ACCESSOR
    # ==========================================================================

    def get_buffer(self) -> List[Dict[str, object]]:
        """
        Возвращает список последних предсказаний (для /ml/predictions).
        """
        return list(self._buffer)
