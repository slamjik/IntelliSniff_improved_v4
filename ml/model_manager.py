"""Model registry and lifecycle management for IntelliSniff."""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional

import joblib
import numpy as np

from traffic_analyzer.classification import (
    load_model as legacy_load_model,
    resolve_label_name,
    train_demo_model,
)
from utils.feature_engineering import HASH_FEATURES, NUMERIC_FEATURES_DEFAULT, ensure_feature_order, extract_features

log = logging.getLogger("ml.model_manager")

SUPPORTED_TASKS = ("attack", "vpn", "anomaly")


@dataclass
class ModelInfo:
    task: str
    version: str
    path: Path
    feature_names: List[str]
    created_at: Optional[float]
    trained_at: Optional[float]
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "task": self.task,
            "version": self.version,
            "path": str(self.path),
            "feature_names": self.feature_names,
            "created_at": self.created_at,
            "trained_at": self.trained_at,
            "notes": self.notes,
        }


class ModelManager:
    """Loads, caches and switches models across different detection tasks."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = Path(base_dir or Path(__file__).resolve().parent)
        self.models_dir = self.base_dir / "models"
        self.versions_dir = self.base_dir / "versions"
        self.registry_path = self.versions_dir / "registry.json"
        self.metrics_path = self.versions_dir / "metrics.json"
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.versions_dir.mkdir(parents=True, exist_ok=True)

        self._registry = self._load_registry()
        self._metrics = self._load_metrics()
        self._cache: Dict[tuple[str, str], object] = {}
        self._feature_cache: Dict[tuple[str, str], List[str]] = {}
        self._lock = threading.RLock()
        self._ensure_demo_models()

    # ------------------------------------------------------------------
    # Registry helpers
    def _load_registry(self) -> Dict[str, Dict[str, object]]:
        if not self.registry_path.exists():
            return {}
        try:
            return json.loads(self.registry_path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.error("Failed to load registry: %s", exc)
            return {}

    def _load_metrics(self) -> Dict[str, Dict[str, object]]:
        if not self.metrics_path.exists():
            return {}
        try:
            return json.loads(self.metrics_path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.error("Failed to load metrics: %s", exc)
            return {}

    def _write_registry(self) -> None:
        self.registry_path.write_text(json.dumps(self._registry, indent=2, ensure_ascii=False), encoding="utf-8")

    def _write_metrics(self) -> None:
        self.metrics_path.write_text(json.dumps(self._metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    def _ensure_task_section(self, task: str) -> Dict[str, object]:
        task = task.lower()
        if task not in self._registry:
            self._registry[task] = {"active": None, "available": {}}
        return self._registry[task]

    def list_tasks(self) -> List[str]:
        return sorted(set(self._registry.keys()) | set(SUPPORTED_TASKS))

    # ------------------------------------------------------------------
    def _ensure_demo_models(self) -> None:
        """Create demo models if registry references files that do not exist."""
        for task in SUPPORTED_TASKS:
            section = self._ensure_task_section(task)
            active = section.get("active")
            available = section.setdefault("available", {})
            if not available and active:
                available[active] = {"path": f"models/{active}"}
            if not section.get("active"):
                demo_name = f"model_{task}_demo.pkl"
                section["active"] = demo_name
                available.setdefault(demo_name, {"path": f"models/{demo_name}"})
            # create file if missing
            info = available.get(section["active"])
            if not info:
                continue
            path = self.base_dir / info.get("path", f"models/{section['active']}")
            if path.exists():
                continue
            try:
                if task == "attack":
                    train_demo_model(str(path))
                else:
                    self._create_synthetic_model(path, task)
                info["created_at"] = info.get("created_at") or time.time()
                info["trained_at"] = info.get("trained_at") or time.time()
            except Exception as exc:
                log.warning("Unable to create demo model for %s: %s", task, exc)
        self._write_registry()

    def _create_synthetic_model(self, path: Path, task: str) -> None:
        from sklearn.ensemble import RandomForestClassifier

        rng = np.random.default_rng(42)
        numeric = len(NUMERIC_FEATURES_DEFAULT)
        hashed = len(HASH_FEATURES)
        feature_names = list(NUMERIC_FEATURES_DEFAULT) + [f"hash_{name}" for name in HASH_FEATURES]
        X = rng.normal(size=(500, numeric))
        hash_values = rng.random(size=(500, hashed))
        features = np.hstack([X, hash_values])
        if task == "vpn":
            y = (features[:, 0] * 0.6 + features[:, 3] * 0.3 + features[:, -2] > 0.5).astype(int)
        else:  # anomaly
            y = (np.abs(features[:, 1]) + features[:, 4] * 0.4 + features[:, -1] > 1.2).astype(int)
        clf = RandomForestClassifier(n_estimators=120, random_state=42)
        clf.fit(features, y)
        joblib.dump({
            "model": clf,
            "features": feature_names,
            "trained_at": time.time(),
            "task": task,
        }, path)

    # ------------------------------------------------------------------
    def _resolve_model_path(self, task: str, version: Optional[str] = None) -> Optional[Path]:
        task = task.lower()
        section = self._ensure_task_section(task)
        version = version or section.get("active")
        if not version:
            return None
        info = section.get("available", {}).get(version)
        if info is None:
            return None
        rel_path = info.get("path") or f"models/{version}"
        return (self.base_dir / rel_path).resolve()

    def _load_model(self, task: str, version: Optional[str] = None) -> tuple[object, List[str]]:
        with self._lock:
            version = version or self._ensure_task_section(task).get("active")
            cache_key = (task, version)
            if cache_key in self._cache:
                return self._cache[cache_key], self._feature_cache.get(cache_key, [])
            path = self._resolve_model_path(task, version)
            if path and path.exists():
                obj = joblib.load(path)
                model = obj.get("model") if isinstance(obj, dict) else obj
                features = None
                for key in ("features", "feature_names", "columns"):
                    if isinstance(obj, dict) and key in obj:
                        features = list(obj[key])
                        break
                self._cache[cache_key] = model
                self._feature_cache[cache_key] = features or []
                return model, self._feature_cache[cache_key]
            # fallback to legacy model
            legacy_model, legacy_features = legacy_load_model()
            self._cache[cache_key] = legacy_model
            self._feature_cache[cache_key] = list(legacy_features or [])
            return legacy_model, self._feature_cache[cache_key]

    # ------------------------------------------------------------------
    def get_versions(self, task: str) -> List[Dict[str, object]]:
        task = task.lower()
        section = self._ensure_task_section(task)
        available = section.get("available", {})
        items = []
        metrics = self._metrics.get(task, {})
        for version, meta in available.items():
            info = {
                "version": version,
                "path": meta.get("path"),
                "created_at": meta.get("created_at"),
                "trained_at": meta.get("trained_at"),
                "notes": meta.get("notes"),
                "active": version == section.get("active"),
            }
            info.update({f"metric_{k}": v for k, v in metrics.get(version, {}).items()})
            items.append(info)
        return sorted(items, key=lambda x: x["version"])

    def get_active_model_info(self, task: str) -> Optional[ModelInfo]:
        task = task.lower()
        section = self._ensure_task_section(task)
        version = section.get("active")
        if not version:
            return None
        path = self._resolve_model_path(task, version)
        model, features = self._load_model(task, version)
        meta = section.get("available", {}).get(version, {})
        return ModelInfo(
            task=task,
            version=version,
            path=path or Path(""),
            feature_names=features,
            created_at=meta.get("created_at"),
            trained_at=meta.get("trained_at"),
            notes=meta.get("notes"),
        )

    # ------------------------------------------------------------------
    def predict(self, raw_features: Mapping[str, object], task: str) -> Dict[str, object]:
        task = task.lower()
        model, feature_names = self._load_model(task)
        info = self.get_active_model_info(task)
        feature_vector = extract_features(
            raw_features,
            expected_order=feature_names if feature_names else None,
        )
        feature_vector = ensure_feature_order(feature_vector, feature_names)
        inputs = feature_vector.values.reshape(1, -1)
        probs = None
        try:
            proba = getattr(model, "predict_proba", None)
            if callable(proba):
                probs = proba(inputs)[0]
                classes = getattr(model, "classes_", list(range(len(probs))))
                idx = int(np.argmax(probs))
                label = classes[idx]
                confidence = float(probs[idx])
            else:
                preds = model.predict(inputs)
                label = preds[0]
                confidence = 1.0
        except Exception as exc:
            log.exception("Prediction failed for task %s: %s", task, exc)
            label = "error"
            confidence = 0.0

        label_name = resolve_label_name(label) if label is not None else "Unknown"
        result = {
            "task": task,
            "label": label if label is None else str(label),
            "label_name": label_name,
            "confidence": float(confidence),
            "score": float(confidence),
            "version": info.version if info else None,
            "feature_vector": feature_vector.as_dict(),
        }
        if probs is not None:
            result["probabilities"] = {
                str(cls): float(prob) for cls, prob in zip(getattr(model, "classes_", []), probs)
            }
        return result

    # ------------------------------------------------------------------
    def switch_model(self, task: str, version: str) -> Dict[str, object]:
        task = task.lower()
        with self._lock:
            section = self._ensure_task_section(task)
            if version not in section.get("available", {}):
                raise ValueError(f"Version {version} not registered for task {task}")
            section["active"] = version
            # purge cache so new model loads on next prediction
            for key in list(self._cache.keys()):
                if key[0] == task:
                    self._cache.pop(key, None)
                    self._feature_cache.pop(key, None)
            self._write_registry()
        log.info("Activated model %s for task %s", version, task)
        info = self.get_active_model_info(task)
        return info.to_dict() if info else {"task": task, "version": version}

    def register_model(self, task: str, version: str, path: str, metadata: Optional[Dict[str, object]] = None) -> None:
        task = task.lower()
        metadata = metadata or {}
        with self._lock:
            section = self._ensure_task_section(task)
            available = section.setdefault("available", {})
            entry = available.setdefault(version, {})
            entry.update(metadata)
            entry["path"] = path
            entry.setdefault("created_at", time.time())
            self._write_registry()

    def update_metrics(self, task: str, version: str, metrics: Mapping[str, object]) -> None:
        task = task.lower()
        with self._lock:
            task_metrics = self._metrics.setdefault(task, {})
            task_metrics[version] = dict(metrics)
            self._write_metrics()
    def get_metrics(self, task: str, version: Optional[str] = None) -> Dict[str, object]:
        task = task.lower()
        task_metrics = self._metrics.get(task, {})
        if version:
            return dict(task_metrics.get(version, {}))
        section = self._ensure_task_section(task)
        active = section.get("active")
        return dict(task_metrics.get(active, {}))

