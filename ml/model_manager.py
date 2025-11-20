import json
from pathlib import Path
import logging
import joblib
import re

log = logging.getLogger("ml.model_manager")


# ==============================================================
#   ОБЪЕКТНАЯ ОБЁРТКА ДЛЯ active модели
# ==============================================================

class ModelInfo:
    def __init__(self, version: int, file: str, features: list):
        self.version = version
        self.file = file
        self.feature_names = features

    def to_dict(self):
        return {
            "version": self.version,
            "file": self.file,
            "feature_names": self.feature_names,
        }


# ==============================================================
#   MODEL MANAGER (главный менеджер моделей)
# ==============================================================

class ModelManager:
    """
    Полный рабочий менеджер моделей:
      ✔ читает registry
      ✔ ищет файлы attack_model_X.joblib / vpn_model_X.joblib
      ✔ загружает sklearn model + features
      ✔ отдаёт ModelInfo вместо голого dict
      ✔ совместим с inference.py, api.py, UI
    """

    TASKS = ["attack", "vpn"]

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)              # ml/
        self.data_dir = self.base_dir / "data"      # ml/data/
        self.registry_path = self.data_dir / "model_registry.json"

        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Файл для DriftDetector
        self.metrics_path = self.data_dir / "metrics.json"

        # Загружаем registry
        self.registry = self._load_registry()

        # Ищем модели
        self._discover_models()

        # Сохраняем registry обратно
        self._save_registry()

    # ==============================================================
    #   ЗАГРУЗКА / СОХРАНЕНИЕ registry
    # ==============================================================

    def _load_registry(self):
        """Загружаем JSON или создаём пустую структуру."""
        if not self.registry_path.exists():
            log.info("📄 Создаю новый model_registry.json")

            return {
                task: {
                    "active": None,
                    "versions": []
                }
                for task in self.TASKS
            }

        try:
            with open(self.registry_path, "r", encoding="utf-8") as f:
                reg = json.load(f)

            # гарантируем структуру
            for task in self.TASKS:
                reg.setdefault(task, {})
                reg[task].setdefault("active", None)
                reg[task].setdefault("versions", [])

            return reg

        except Exception as ex:
            log.error("❌ Ошибка чтения registry: %s", ex)
            return {
                task: {"active": None, "versions": []}
                for task in self.TASKS
            }

    def _save_registry(self):
        """Сохраняем registry.json"""
        try:
            with open(self.registry_path, "w", encoding="utf-8") as f:
                json.dump(self.registry, f, ensure_ascii=False, indent=2)
        except Exception as ex:
            log.error("❌ Не удалось сохранить registry: %s", ex)

    # ==============================================================
    #   АВТО-ПОИСК МОДЕЛЕЙ
    # ==============================================================

    def _discover_models(self):
        """
        Ищет файлы вида:
            attack_model_1.joblib
            vpn_model_1.joblib
        и автоматически регистрирует.
        """
        for task in self.TASKS:
            pattern = f"{task}_model_*.joblib"
            files = list(self.data_dir.glob(pattern))

            if not files:
                log.warning(f"⚠️ Моделей не найдено для '{task}'")
                continue

            versions = []

            for f in files:
                m = re.search(rf"{task}_model_(\d+)\.joblib$", f.name)
                if not m:
                    continue

                version = int(m.group(1))

                versions.append({
                    "version": version,
                    "file": str(f),
                })

            versions_sorted = sorted(versions, key=lambda x: x["version"])

            self.registry[task]["versions"] = versions_sorted
            self.registry[task]["active"] = versions_sorted[-1]

            log.info(f"🧩 {task}: найдено моделей {len(versions_sorted)}, активная → v{versions_sorted[-1]['version']}")

    # ==============================================================
    #   ЗАГРУЗКА ACTIVE МОДЕЛИ
    # ==============================================================

    def get_active_model_info(self, task: str):
        """
        Возвращает ИМЕННО ModelInfo — не dict.
        Это нужно inference.py и predictor.
        """
        reg = self.registry.get(task)
        if not reg:
            return None

        active = reg["active"]
        if not active:
            return None

        file = active["file"]
        version = active["version"]

        # загружаем joblib
        bundle = joblib.load(file)

        # bundle содержит:
        #   model
        #   features
        #   trained_at
        features = bundle.get("features")

        return ModelInfo(
            version=version,
            file=file,
            features=features
        )

    # ==============================================================
    #   ЗАГРУЗКА ОБЪЕКТА SKLEARN МОДЕЛИ
    # ==============================================================

    def _load_model_object(self, task: str, version: int):
        for v in self.registry[task]["versions"]:
            if v["version"] == version:
                bundle = joblib.load(v["file"])
                return bundle["model"]

        raise ValueError(f"❌ Модель {task} версии v{version} не найдена!")

    # ==============================================================
    #   ПЕРЕКЛЮЧЕНИЕ МОДЕЛЕЙ
    # ==============================================================

    def set_active_model(self, task: str, version: int):
        """Назначает активную модель."""
        for v in self.registry[task]["versions"]:
            if v["version"] == version:
                self.registry[task]["active"] = v
                self._save_registry()
                log.info(f"🔄 Активная модель {task} → v{version}")
                return True

        raise ValueError(f"❌ Нет модели {task} v{version}")

    # ==============================================================
    #   ДОСТУПНЫЕ ВЕРСИИ (для UI)
    # ==============================================================

    @property
    def available_versions(self):
        return {
            task: [v["version"] for v in self.registry[task]["versions"]]
            for task in self.TASKS
        }
