"""Model management for IntelliSniff.

This manager always exposes feature names from the joblib bundle and ensures the
active model object is served from the bundle's "model" key. It also provides a
stable version listing so the UI selectors remain populated even if only a
single model exists.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, Optional

import joblib

log = logging.getLogger("ml.model_manager")


class ModelInfo:
    def __init__(self, version: int, file: Path, feature_names: Optional[list], model):
        self.version = int(version)
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

        self._bundles: Dict[str, Dict[int, Dict[str, object]]] = {task: {} for task in self.TASKS}
        self._active: Dict[str, int] = {task: 1 for task in self.TASKS}
        self.available_versions: Dict[str, list] = {task: [] for task in self.TASKS}
        self._metrics: Dict[str, Dict[str, dict]] = {}
        self._registry: Dict[str, dict] = {}

        self._load_bundles()
        self._load_registry()
        self._load_metrics()

    # ------------------------------------------------------------------
    def _load_bundles(self) -> None:
        """Discover joblib bundles and prime registry."""
        for task in self.TASKS:
            pattern = f"{task}_model_*.joblib"
            for file in self.data_dir.glob(pattern):
                match = re.search(r"_(\d+)\.joblib$", file.name)
                if not match:
                    continue
                version = int(match.group(1))
                try:
                    bundle = joblib.load(file)
                    if not isinstance(bundle, dict) or "model" not in bundle:
                        log.warning("Bundle %s missing model key", file)
                        continue
                    self._bundles[task][version] = {"bundle": bundle, "file": file}
                    log.info("Loaded %s bundle v%s", task, version)
                except Exception:
                    log.exception("Failed to load model bundle %s", file)
            if self._bundles[task]:
                self._active[task] = max(self._bundles[task])
            else:
                # placeholder registry so UI still has a version to show
                self._bundles[task][1] = {"bundle": {"model": None, "features": []}, "file": self.data_dir / f"{task}_model_1.joblib"}
                self._active[task] = 1

    # ------------------------------------------------------------------
    def get_active_model_info(self, task: str) -> Optional[ModelInfo]:
        task = task or "attack"
        bundle_info = self._bundles.get(task, {}).get(self._active.get(task, 1))
        if not bundle_info:
            return None
        bundle = bundle_info["bundle"]
        file = bundle_info["file"]
        model_obj = bundle.get("model")
        features = bundle.get("features") or bundle.get("feature_names") or []
        return ModelInfo(version=self._active.get(task, 1), file=file, feature_names=features, model=model_obj)

    # ------------------------------------------------------------------
    def _load_model_object(self, task: str, version: Optional[int] = None):
        task = task or "attack"
        version = int(version or self._active.get(task, 1))
        bundle_info = self._bundles.get(task, {}).get(version)
        if not bundle_info:
            raise ValueError(f"Model for task {task} v{version} not found")
        return bundle_info["bundle"].get("model")

    # ------------------------------------------------------------------
    def set_active_model(self, task: str, version: int) -> bool:
        if version in self._bundles.get(task, {}):
            self._active[task] = version
            return True
        raise ValueError(f"No version {version} for task {task}")

    # ------------------------------------------------------------------
    def get_versions(self, task: str):
        """Return versions for UI: always at least one active version."""
        task = task or "attack"
        versions = []
        active_version = self._active.get(task, 1)

        registry_info = self._registry.get(task, {})
        available = registry_info.get("available", {}) if isinstance(registry_info, dict) else {}
        for ver, meta in available.items():
            versions.append(
                {
                    "version": ver,
                    "active": str(ver) == str(registry_info.get("active", active_version)),
                    "path": str(meta.get("path")) if isinstance(meta, dict) else None,
                }
            )

        if not versions:
            for ver in sorted(self._bundles.get(task, {})):
                versions.append({"version": ver, "active": ver == active_version, "path": str(self._bundles[task][ver]["file"])})

        if not versions:
            versions = [{"version": 1, "active": True}]
        return versions

    @property
    def registry(self) -> Dict[str, Dict[str, object]]:
        """Compatibility snapshot used by API."""
        reg: Dict[str, Dict[str, object]] = {}
        for task in self.TASKS:
            active_version = self._active.get(task, 1)
            reg[task] = {
                "active": {"version": active_version, "file": str(self._bundles[task][active_version]["file"]) if self._bundles.get(task) else None},
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
            self._registry = {task: {"active": 1, "available": {}} for task in self.TASKS}

        for task in self.TASKS:
            active_version = self._registry.get(task, {}).get("active")
            if active_version is not None:
                try:
                    self._active[task] = int(active_version)
                except Exception:
                    self._active[task] = 1

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

        self.available_versions = {task: [] for task in self.TASKS}
        for task, versions in self._metrics.items():
            if not isinstance(versions, dict):
                continue
            for ver, metrics in versions.items():
                entry = {"version": ver}
                if isinstance(metrics, dict):
                    entry.update(metrics)
                self.available_versions.setdefault(task, []).append(entry)

    def get_metrics(self, task: str, version: str | int) -> dict:
        task = task or "attack"
        return self._metrics.get(task, {}).get(str(version), {})

    def update_metrics(self, task: str, version: str | int, metrics: dict) -> None:
        task = task or "attack"
        self._metrics.setdefault(task, {})[str(version)] = metrics or {}
        self._save_metrics()
        self._load_metrics()

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

    def switch_model(self, task: str, version: str | int) -> None:
        task = task or "attack"
        self._registry.setdefault(task, {"active": version, "available": {}})
        self._registry[task]["active"] = str(version)
        try:
            self._active[task] = int(version)
        except Exception:
            self._active[task] = 1
        self._save_registry()
