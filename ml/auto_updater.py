"""Automated model validation and activation for IntelliSniff."""
from __future__ import annotations

import csv
import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional

from traffic_analyzer import event_bus
from utils import validation

log = logging.getLogger("ml.auto_updater")


class AutoUpdater:
    def __init__(
        self,
        model_manager,
        drift_detector=None,
        candidates_path: Optional[str] = None,
        confidence_threshold: float = 0.9,
    ):
        self.model_manager = model_manager
        self.drift_detector = drift_detector
        self.candidates_path = Path(candidates_path or Path(__file__).resolve().parent / "data" / "training_candidates.csv")
        self.candidates_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.candidates_path.exists():
            self.candidates_path.write_text("task,label,confidence,timestamp\n", encoding="utf-8")
        self.confidence_threshold = confidence_threshold
        self.enabled = True

    # ------------------------------------------------------------------
    def record_prediction(self, task: str, prediction: Dict[str, object], feature_vector) -> None:
        if not self.enabled:
            return
        confidence = float(prediction.get("confidence", 0.0))
        if confidence < self.confidence_threshold:
            return
        header = ["task", "label", "confidence", "timestamp"] + list(feature_vector.names)
        row = [
            task,
            prediction.get("label", "unknown"),
            f"{confidence:.4f}",
            str(prediction.get("timestamp", time.time())),
        ] + [f"{float(value):.6f}" for value in feature_vector.values]
        try:
            file_exists = self.candidates_path.exists() and self.candidates_path.stat().st_size > 0
            with self.candidates_path.open("a", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                if not file_exists:
                    writer.writerow(header)
                writer.writerow(row)
        except Exception as exc:
            log.warning("Failed to append training candidate: %s", exc)

    # ------------------------------------------------------------------
    def toggle(self, enabled: bool) -> None:
        self.enabled = bool(enabled)
        event_bus.publish("auto_update", {"enabled": self.enabled})

    def discover_new_models(self, task: str) -> Dict[str, str]:
        """Return models located in the models directory but not registered yet."""
        task = task.lower()
        registered = {info.get("path") for info in self.model_manager.get_versions(task)}
        discovered = {}
        for path in (self.model_manager.models_dir).glob(f"*{task}*.pkl"):
            rel = os.path.relpath(path, self.model_manager.base_dir)
            if rel not in registered:
                discovered[path.name] = rel
        return discovered

    def validate_and_maybe_activate(self, task: str, model_filename: str, dataset_path: Optional[str] = None) -> Dict[str, object]:
        task = task.lower()
        candidate_path = (self.model_manager.base_dir / "models" / task / model_filename).resolve()
        if not candidate_path.exists():
            fallback = (self.model_manager.base_dir / "models" / model_filename).resolve()
            candidate_path = fallback
        if not candidate_path.exists():
            raise FileNotFoundError(candidate_path)
        dataset_file = Path(dataset_path) if dataset_path else self.candidates_path
        if not dataset_file.is_absolute():
            dataset_file = (self.model_manager.base_dir / dataset_file).resolve()
        report = validation.evaluate_model(str(candidate_path), str(dataset_file), task)
        current = self.model_manager.get_active_model_info(task)
        current_metrics = self.model_manager.get_metrics(task, current.version) if current else {}
        if validation.compare_models(current_metrics, report.metrics):
            metadata = {
                "trained_at": report.evaluated_at,
                "notes": f"Auto-validated on {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(report.evaluated_at))}",
            }
            storage_path = f"models/{task}/{model_filename}" if (self.model_manager.base_dir / "models" / task / model_filename).exists() else f"models/{model_filename}"
            self.model_manager.register_model(task, model_filename, storage_path, metadata=metadata)
            self.model_manager.update_metrics(task, model_filename, report.metrics)
            self.model_manager.switch_model(task, model_filename)
            event_bus.publish("model_update", {
                "task": task,
                "version": model_filename,
                "status": "activated",
                "metrics": report.metrics,
            })
            return {"status": "activated", "report": report.to_dict()}
        event_bus.publish("model_update", {
            "task": task,
            "version": model_filename,
            "status": "rejected",
            "metrics": report.metrics,
        })
        return {"status": "rejected", "report": report.to_dict()}

