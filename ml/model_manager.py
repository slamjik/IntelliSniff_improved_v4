"""Model management for IntelliSniff.

This manager always exposes feature names from the joblib bundle and ensures the
active model object is served from the bundle's "model" key. It also provides a
stable version listing so the UI selectors remain populated even if only a
single model exists.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional

import joblib

log = logging.getLogger("ml.model_manager")


class ModelInfo:
    def __init__(self, version: str, file: Path, feature_names: Optional[list], model):
        self.version = str(version)
        self.file = str(file)
        self.feature_names = list(feature_names or [])
        self.model = model

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "file": self.file,
            "feature_names": self.feature_names,
        }


class ModelManager:
    TASKS = ["attack", "vpn", "anomaly"]

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.data_dir = self.base_dir / "data"
        self.models_dir = self.base_dir / "models"
        self.versions_dir = self.base_dir / "versions"
        self.metrics_path = self.versions_dir / "metrics.json"
        self.registry_path = self.versions_dir / "registry.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.versions_dir.mkdir(parents=True, exist_ok=True)


        self._bundles: Dict[str, Dict[str, Dict[str, object]]] = {task: {} for task in self.TASKS}
        self._active: Dict[str, Optional[str]] = {task: None for task in self.TASKS}

        self.available_versions: Dict[str, list] = {task: [] for task in self.TASKS}
        self._metrics: Dict[str, Dict[str, dict]] = {}
        self._registry: Dict[str, dict] = {}

        self._load_bundles()
        self._load_registry()
        self._load_metrics()

        self._refresh_available_versions()

    # ------------------------------------------------------------------
    def _load_bundles(self) -> None:
        """Discover real joblib models from ml/models/<task> directories."""
        for task in self.TASKS:
            task_dir = self.models_dir / task
            task_dir.mkdir(parents=True, exist_ok=True)
            bundles: Dict[str, Dict[str, object]] = {}
            for file in sorted(task_dir.glob("*.joblib")):
                try:
                    loaded = joblib.load(file)
                    if isinstance(loaded, dict):
                        model_obj = loaded.get("model") or loaded
                        feature_names = loaded.get("features") or loaded.get("feature_names")
                    else:
                        model_obj = loaded
                        feature_names = getattr(loaded, "feature_names", None)
                        loaded = {"model": loaded, "features": feature_names}
                    bundles[file.name] = {
                        "bundle": loaded,
                        "file": file,
                        "model": model_obj,
                        "features": feature_names or [],
                    }
                    log.info("Loaded %s model bundle %s", task, file.name)
                except Exception:
                    log.exception("Failed to load model bundle %s", file)
            self._bundles[task] = bundles
            # pick an active version later based on registry or first available

    # ------------------------------------------------------------------
    def get_active_model_info(self, task: str) -> Optional[ModelInfo]:
        task = task or "attack"
        bundle_info = self._bundles.get(task, {}).get(self._active.get(task))
        if not bundle_info:
            return None
        bundle = bundle_info["bundle"]
        file = bundle_info["file"]
        model_obj = bundle_info.get("model") or bundle.get("model")
        features = bundle_info.get("features") or bundle.get("features") or bundle.get("feature_names") or []
        return ModelInfo(version=self._active.get(task) or file.name, file=file, feature_names=features, model=model_obj)

    # ------------------------------------------------------------------
    def _load_model_object(self, task: str, version: Optional[int] = None):
        task = task or "attack"
        version = str(version or self._active.get(task))
        bundle_info = self._bundles.get(task, {}).get(version)
        if not bundle_info:
            raise ValueError(f"Model for task {task} v{version} not found")
        return bundle_info["bundle"].get("model")

    # ------------------------------------------------------------------
    def set_active_model(self, task: str, version: str) -> bool:
        version = str(version)
        if version in self._bundles.get(task, {}):
            self._active[task] = version
            self._registry.setdefault(task, {"active": version, "available": {}})
            self._registry[task]["active"] = version
            self._save_registry()
            return True
        raise ValueError(f"No version {version} for task {task}")

    # ------------------------------------------------------------------
    def get_versions(self, task: str):
        """Return versions for UI: always at least one active version."""
        task = task or "attack"
        versions = []

        active_version = self._active.get(task)

        for ver, meta in self._bundles.get(task, {}).items():
            versions.append({
                "version": ver,
                "active": str(ver) == str(active_version),
                "path": str(meta.get("file")),
            })


        if not versions:
            reg_info = self._registry.get(task, {}) if isinstance(self._registry, dict) else {}
            available = reg_info.get("available", {}) if isinstance(reg_info, dict) else {}
            for ver, meta in available.items():
                versions.append({
                    "version": ver,
                    "active": str(ver) == str(reg_info.get("active")),
                    "path": str(meta.get("path")) if isinstance(meta, dict) else None,
                })

        return versions

    @property
    def registry(self) -> Dict[str, Dict[str, object]]:
        """Compatibility snapshot used by API."""
        reg: Dict[str, Dict[str, object]] = {}
        for task in self.TASKS:
            active_version = self._active.get(task)
            reg[task] = {
                "active": {
                    "version": active_version,
                    "file": str(self._bundles[task][active_version]["file"]) if self._bundles.get(task) and active_version in self._bundles[task] else None,
                },
                "versions": self.get_versions(task),
            }
        return reg

    # ------------------------------------------------------------------
    def _load_registry(self) -> None:
        if self.registry_path.exists():
            try:
                self._registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
            except Exception:
                log.warning("Failed to read registry.json", exc_info=True)
                self._registry = {}
        else:

            self._registry = {task: {"active": None, "available": {}} for task in self.TASKS}

        for task in self.TASKS:
            reg_active = self._registry.get(task, {}).get("active")
            bundles = self._bundles.get(task, {})
            if reg_active and reg_active in bundles:
                self._active[task] = str(reg_active)
            elif bundles:
                self._active[task] = str(sorted(bundles.keys())[0])
            else:
                self._active[task] = None


    def _save_registry(self) -> None:
        try:
            self.registry_path.write_text(json.dumps(self._registry, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            log.warning("Failed to persist registry.json", exc_info=True)

    def _load_metrics(self) -> None:
        if self.metrics_path.exists():
            try:
                self._metrics = json.loads(self.metrics_path.read_text(encoding="utf-8"))
            except Exception:
                log.warning("Failed to read metrics.json", exc_info=True)
                self._metrics = {}
        else:
            self._metrics = {}


    def _refresh_available_versions(self) -> None:
        """Expose versions to API/UI combining discovered bundles with metrics."""
        self.available_versions = {task: [] for task in self.TASKS}
        for task in self.TASKS:
            metrics_for_task = self._metrics.get(task, {}) if isinstance(self._metrics, dict) else {}
            for ver, bundle in self._bundles.get(task, {}).items():
                entry = {"version": ver, "path": str(bundle.get("file"))}
                if isinstance(metrics_for_task, dict) and metrics_for_task.get(str(ver)):
                    metrics = metrics_for_task.get(str(ver))
                    if isinstance(metrics, dict):
                        entry.update(metrics)
                self.available_versions[task].append(entry)

    def reload(self) -> None:
        """Rescan model folders and rebuild registry snapshot."""
        self._bundles = {task: {} for task in self.TASKS}
        self._active = {task: None for task in self.TASKS}
        self._load_bundles()
        self._load_registry()
        self._load_metrics()
        self._refresh_available_versions()

    def get_metrics(self, task: str, version: str | int) -> dict:
        task = task or "attack"
        return self._metrics.get(task, {}).get(str(version), {})

    def update_metrics(self, task: str, version: str | int, metrics: dict) -> None:
        task = task or "attack"
        self._metrics.setdefault(task, {})[str(version)] = metrics or {}
        self._save_metrics()
        self._load_metrics()

        self._refresh_available_versions()


    def _save_metrics(self) -> None:
        try:
            self.metrics_path.write_text(json.dumps(self._metrics, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            log.warning("Failed to persist metrics.json", exc_info=True)

    def register_model(self, task: str, version: str | int, path: str, metadata: Optional[dict] = None) -> None:
        task = task or "attack"
        self._registry.setdefault(task, {"active": version, "available": {}})
        self._registry[task].setdefault("available", {})[str(version)] = {"path": path, **(metadata or {})}
        self._save_registry()

        self._refresh_available_versions()

    def switch_model(self, task: str, version: str | int) -> None:
        task = task or "attack"
        self._registry.setdefault(task, {"active": version, "available": {}})
        self._registry[task]["active"] = str(version)

        self._active[task] = str(version)
        self._save_registry()
        self._refresh_available_versions()

