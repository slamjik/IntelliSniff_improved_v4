"""Streaming inference pipeline.

Loads the active model bundle, builds the exact feature vector expected by the
model, and records results in a rolling buffer for the UI. All missing fields
are zero-filled and NaNs are removed to prevent runtime errors.
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Mapping, Optional

import pandas as pd

from utils.feature_engineering import MODEL_FEATURES_41, extract_features, merge_feature_sources

log = logging.getLogger("ml.inference")


class StreamPredictor:
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

        self.buffer_path = Path(buffer_path or Path(__file__).resolve().parent / "data" / "live_buffer.json")
        self.buffer_path.parent.mkdir(parents=True, exist_ok=True)

        self._buffer: Deque[Dict[str, object]] = deque(maxlen=buffer_size)
        self._load_buffer()

    # ------------------------------------------------------------------
    def _load_buffer(self) -> None:
        if not self.buffer_path.exists():
            return
        try:
            raw = json.loads(self.buffer_path.read_text(encoding="utf-8"))
            for item in raw:
                self._buffer.append(item)
        except Exception:
            log.warning("Failed to load live buffer", exc_info=True)

    def _flush_buffer(self) -> None:
        try:
            self.buffer_path.write_text(
                json.dumps(list(self._buffer), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            log.warning("Unable to persist live buffer", exc_info=True)

    # ------------------------------------------------------------------
    def _select_feature_order(self, active_model) -> List[str]:
        if active_model and getattr(active_model, "feature_names", None):
            return list(active_model.feature_names)
        if isinstance(active_model, dict):
            return list(active_model.get("features") or active_model.get("feature_names") or [])
        return list(MODEL_FEATURES_41)

    # ------------------------------------------------------------------
    def predict(
        self,
        features: Mapping[str, object],
        task: str = "attack",
        metadata: Optional[Mapping[str, object]] = None,
    ) -> Dict[str, object]:
        merged = merge_feature_sources(features, metadata or {})

        active = self.model_manager.get_active_model_info(task)
        if not active:
            return {"label": "unknown", "score": 0.0, "reason": "no active model"}

        feature_order = self._select_feature_order(active)
        vector = extract_features(merged, expected_order=feature_order)
        clean_values = pd.Series(vector.values)
        clean_values = pd.to_numeric(clean_values.replace([pd.NA, pd.NaT], 0), errors="coerce").fillna(0.0)
        df = pd.DataFrame([clean_values.to_numpy()], columns=vector.names)

        model = active.model or self.model_manager._load_model_object(task, active.version)

        try:
            raw_pred = model.predict(df)[0]
            label = raw_pred if not hasattr(raw_pred, "item") else raw_pred.item()
        except Exception:
            log.exception("Prediction failed")
            return {"label": "unknown", "score": 0.0, "reason": "prediction failed"}

        try:
            proba = model.predict_proba(df)[0]
            score = float(max(proba))
        except Exception:
            score = 0.0

        result = {
            "label": label,
            "label_name": str(label),
            "score": score,
            "confidence": score,
            "task": task,
            "version": active.version,
            "timestamp": time.time(),
        }

        result["explanation"] = self._explain(model, vector)

        if self.drift_detector:
            try:
                result["drift"] = self.drift_detector.update(task, vector)
            except Exception:
                log.debug("Drift detector update failed", exc_info=True)

        if self.auto_updater:
            try:
                self.auto_updater.record_prediction(task, result, vector)
            except Exception:
                log.debug("Auto-updater hook failed", exc_info=True)

        self._buffer.append(result)
        self._flush_buffer()

        return result

    # ------------------------------------------------------------------
    def batch_predict(self, rows: Iterable[Mapping[str, object]], task: str = "attack") -> List[Dict[str, object]]:
        return [self.predict(row, task=task) for row in rows]

    # ------------------------------------------------------------------
    def _explain(self, model, vector) -> List[Dict[str, object]]:
        try:
            importances = getattr(model, "feature_importances_", None)
            if importances is None:
                return []
            pairs = sorted(zip(vector.names, importances), key=lambda x: abs(x[1]), reverse=True)
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

    # ------------------------------------------------------------------
    def get_buffer(self) -> List[Dict[str, object]]:
        return list(self._buffer)
