"""Streaming drift detection utilities."""
from __future__ import annotations

import json
import logging
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, Iterable, Mapping, Optional

import numpy as np

from traffic_analyzer import event_bus

log = logging.getLogger("ml.drift")


def _js_divergence(p: np.ndarray, q: np.ndarray) -> float:
    p = p.astype(float)
    q = q.astype(float)
    p_sum = p.sum()
    q_sum = q.sum()
    if p_sum == 0 or q_sum == 0:
        return 0.0
    p = p / p_sum
    q = q / q_sum
    m = 0.5 * (p + q)
    with np.errstate(divide="ignore", invalid="ignore"):
        logp = np.where(p > 0, np.log2(p / m), 0.0)
        logq = np.where(q > 0, np.log2(q / m), 0.0)
    return float(0.5 * (np.sum(p * logp) + np.sum(q * logq)))


class DriftDetector:
    def __init__(
        self,
        metrics_path: Optional[str] = None,
        window_size: int = 200,
        js_threshold: float = 0.3,
        z_threshold: float = 3.5,
    ):
        self.metrics_path = Path(metrics_path or Path(__file__).resolve().parent / "versions" / "metrics.json")
        self.window_size = window_size
        self.js_threshold = js_threshold
        self.z_threshold = z_threshold
        self._baseline = self._load_baseline()
        self._windows: Dict[str, Deque[np.ndarray]] = defaultdict(lambda: deque(maxlen=window_size))
        self._last_alert: Dict[str, Dict[str, float]] = {}

    # ------------------------------------------------------------------
    def _load_baseline(self) -> Dict[str, Dict[str, object]]:
        if not self.metrics_path.exists():
            return {}
        try:
            return json.loads(self.metrics_path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("Failed to load baseline metrics: %s", exc)
            return {}

    def _feature_stats(self, task: str) -> Dict[str, Dict[str, float]]:
        task_metrics = self._baseline.get(task, {})
        for version, metrics in task_metrics.items():
            if "feature_stats" in metrics:
                return metrics["feature_stats"]
        # fallback default
        return {"mean": {}, "std": {}}

    # ------------------------------------------------------------------
    def update(self, task: str, vector) -> Dict[str, float]:
        arr = np.asarray(vector.values, dtype=float)
        window = self._windows[task]
        window.append(arr)
        status = {
            "jsd": 0.0,
            "z_score": 0.0,
            "drift": False,
        }
        if len(window) < max(5, int(self.window_size * 0.2)):
            return status
        stacked = np.vstack(window)
        mean = stacked.mean(axis=0)
        std = stacked.std(axis=0) + 1e-6
        baseline = self._feature_stats(task)
        baseline_mean = np.array([baseline.get("mean", {}).get(str(i), 0.0) for i in range(mean.shape[0])])
        baseline_std = np.array([baseline.get("std", {}).get(str(i), 1.0) for i in range(std.shape[0])])
        z_scores = np.abs((mean - baseline_mean) / (baseline_std + 1e-6))
        status["z_score"] = float(np.max(z_scores))

        # build histogram along first feature as proxy
        hist_bins = np.linspace(stacked[:, 0].min(), stacked[:, 0].max() + 1e-9, 20)
        current_hist, _ = np.histogram(stacked[:, 0], bins=hist_bins)
        baseline_hist = baseline.get("hist", np.ones_like(current_hist))
        baseline_hist = np.asarray(baseline_hist)
        status["jsd"] = _js_divergence(current_hist, baseline_hist)
        status["drift"] = bool(status["jsd"] > self.js_threshold or status["z_score"] > self.z_threshold)
        if status["drift"]:
            alert = {
                "task": task,
                "jsd": status["jsd"],
                "z_score": status["z_score"],
                "window": len(window),
                "drift": True,
            }
            if self._should_emit(task, alert):
                event_bus.publish("drift", alert)
                log.warning("Drift detected for %s: jsd=%.3f z=%.2f", task, alert["jsd"], alert["z_score"])
            self._last_alert[task] = alert
        else:
            self._last_alert[task] = {
                "task": task,
                "jsd": status["jsd"],
                "z_score": status["z_score"],
                "window": len(window),
                "drift": False,
            }
        return status

    def _should_emit(self, task: str, alert: Dict[str, float]) -> bool:
        previous = self._last_alert.get(task)
        if not previous:
            return True
        return abs(alert["jsd"] - previous.get("jsd", 0.0)) > 0.05 or abs(alert["z_score"] - previous.get("z_score", 0.0)) > 0.5

    def get_status(self) -> Dict[str, Dict[str, float]]:
        return {task: dict(alert) for task, alert in self._last_alert.items()}

