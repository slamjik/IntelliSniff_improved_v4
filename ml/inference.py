"""Inference helpers for streaming predictions."""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Mapping, Optional


from utils.feature_engineering import ensure_feature_order, extract_features, merge_feature_sources

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
        self.buffer_size = buffer_size
        self._buffer: Deque[Dict[str, object]] = deque(maxlen=buffer_size)
        self._load_buffer()

    # ------------------------------------------------------------------
    def _load_buffer(self) -> None:
        if not self.buffer_path.exists():
            return
        try:
            data = json.loads(self.buffer_path.read_text(encoding="utf-8"))
            for item in data[-self.buffer_size :]:
                self._buffer.append(item)
        except Exception as exc:
            log.warning("Failed to load live buffer: %s", exc)

    def _flush_buffer(self) -> None:
        try:
            self.buffer_path.write_text(json.dumps(list(self._buffer), ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            log.warning("Unable to persist live buffer: %s", exc)

    # ------------------------------------------------------------------
    def predict(self, features: Mapping[str, object], task: str = "attack", metadata: Optional[Mapping[str, object]] = None) -> Dict[str, object]:
        merged = merge_feature_sources(features, metadata or {})
        vector = extract_features(merged)
        active = self.model_manager.get_active_model_info(task)
        vector = ensure_feature_order(vector, active.feature_names if active else None)
        payload = self.model_manager.predict(merged, task)
        explanation = self._explain(task, payload, vector)
        result = {
            **payload,
            "explanation": explanation,
            "timestamp": time.time(),
        }
        self._buffer.append(result)
        self._flush_buffer()
        if self.drift_detector:
            drift_status = self.drift_detector.update(task, vector)
            result["drift"] = drift_status
        if self.auto_updater:
            self.auto_updater.record_prediction(task, result, vector)
        return result

    def batch_predict(self, rows: Iterable[Mapping[str, object]], task: str = "attack") -> List[Dict[str, object]]:
        return [self.predict(row, task=task) for row in rows]

    # ------------------------------------------------------------------
    def _explain(self, task: str, payload: Mapping[str, object], vector) -> List[Dict[str, float]]:
        try:
            model_info = self.model_manager.get_active_model_info(task)
            if not model_info:
                return []
            model, features = self.model_manager._load_model(task, model_info.version)
            importances = getattr(model, "feature_importances_", None)
            if importances is None:
                return []
            pairs = sorted(zip(model_info.feature_names or vector.names, importances), key=lambda x: abs(x[1]), reverse=True)
            explanation = []
            for name, weight in pairs[:5]:
                idx = (vector.names.index(name) if name in vector.names else None)
                value = float(vector.values[idx]) if idx is not None else 0.0
                explanation.append({"feature": name, "importance": float(weight), "value": value})
            return explanation
        except Exception as exc:
            log.debug("Failed to build explanation: %s", exc)
            return []

    def get_buffer(self) -> List[Dict[str, object]]:
        return list(self._buffer)

