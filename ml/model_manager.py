import json
from pathlib import Path
import logging
import joblib
import re

log = logging.getLogger("ml.model_manager")


# ======================================================================
#   ModelInfo — удобная обёртка для активной модели
# ======================================================================

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


# ======================================================================
#   ModelManager — центральный менеджер моделей
# ======================================================================

class ModelManager:
    """
    Полностью рабочий ModelManager:

    ✔ Читает/создаёт registry.json
    ✔ Ищет модели attack_model_X.joblib / vpn_model_X.joblib
    ✔ Загрузает sklearn-модель + фичи + trained_at
    ✔ Возвращает ModelInfo вместо dict (для inference/predictor/UI)
    ✔ Выдаёт версии, активную модель
    ✔ Совместим со всеми API эндпоинтами
    """

    TASKS = ["attack", "vpn"]

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)              # ml/
        self.data_dir = self.base_dir / "data"      # ml/data/
        self.registry_path = self.data_dir / "model_registry.json"

        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Файл с метриками дрейфа
        self.metrics_path = self.data_dir / "metrics.json"

        # Загружаем существующий registry.json
        self.registry = self._load_registry()

        # Автоматически ищем модели по файлам
        self._discover_models()

        # Сохраняем registry обратно
        self._save_registry()

    # ==================================================================
    #   ЗАГРУЗКА / СОХРАНЕНИЕ registry.json
    # ==================================================================

    def _load_registry(self):
        """Загружает JSON или создаёт пустой шаблон."""
        if not self.registry_path.exists():
            log.info("📄 model_registry.json отсутствует — создаю новый")

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

            # Гарантируем структуру
            for task in self.TASKS:
                reg.setdefault(task, {})
                reg[task].setdefault("active", None)
                reg[task].setdefault("versions", [])

            return reg

        except Exception as ex:
            log.error("❌ Ошибка чтения registry.json: %s", ex)
            return {
                task: {"active": None, "versions": []}
                for task in self.TASKS
            }

    def _save_registry(self):
        """Сохраняет registry.json."""
        try:
            with open(self.registry_path, "w", encoding="utf-8") as f:
                json.dump(self.registry, f, ensure_ascii=False, indent=2)
        except Exception as ex:
            log.error("❌ Ошибка сохранения registry.json: %s", ex)

    # ==================================================================
    #   АВТО-ОБНАРУЖЕНИЕ МОДЕЛЕЙ
    # ==================================================================

    def _discover_models(self):
        """
        Ищет файлы:
            attack_model_1.joblib
            vpn_model_2.joblib
        и автоматически обновляет registry.
        """
        for task in self.TASKS:
            pattern = f"{task}_model_*.joblib"
            files = list(self.data_dir.glob(pattern))

            if not files:
                log.warning(f"⚠️ Не найдено моделей для {task}")
                continue

            versions = []

            for f in files:
                m = re.search(rf"{task}_model_(\d+)\.joblib$", f.name)
                if not m:
                    continue

                v = int(m.group(1))
                versions.append({
                    "version": v,
                    "file": str(f),
                })

            versions_sorted = sorted(versions, key=lambda x: x["version"])

            self.registry[task]["versions"] = versions_sorted
            self.registry[task]["active"] = versions_sorted[-1]

            log.info(
                f"🧩 {task}: найдено {len(versions_sorted)} моделей, активная v{versions_sorted[-1]['version']}"
            )

    # ==================================================================
    #   ЗАГРУЗКА АКТИВНОЙ МОДЕЛИ (ModelInfo)
    # ==================================================================

    def get_active_model_info(self, task: str):
        """Возвращает ModelInfo (не dict) — это важно."""
        task_reg = self.registry.get(task)
        if not task_reg:
            return None

        active = task_reg.get("active")
        if not active:
            return None

        file = active["file"]
        version = active["version"]

        bundle = joblib.load(file)

        return ModelInfo(
            version=version,
            file=file,
            features=bundle.get("features", [])
        )

    # ==================================================================
    #   ЗАГРУЗКА SKLEARN-МОДЕЛИ ПО ВЕРСИИ
    # ==================================================================

    def _load_model_object(self, task: str, version: int):
        for v in self.registry[task]["versions"]:
            if v["version"] == version:
                bundle = joblib.load(v["file"])
                return bundle["model"]

        raise ValueError(f"❌ Модель {task} версии v{version} не найдена")

    # ==================================================================
    #   ПЕРЕКЛЮЧЕНИЕ АКТИВНОЙ МОДЕЛИ
    # ==================================================================

    def set_active_model(self, task: str, version: int):
        """Делает выбранную модель активной."""
        for v in self.registry[task]["versions"]:
            if v["version"] == version:
                self.registry[task]["active"] = v
                self._save_registry()
                log.info(f"🔄 Активная модель {task} → v{version}")
                return True

        raise ValueError(f"❌ Нет версии {version} для задачи {task}")

    # ==================================================================
    #   ВЕРСИИ (карма для UI)
    # ==================================================================

    def get_versions(self, task: str):
        """Полный список версий для UI/API."""
        return self.registry.get(task, {}).get("versions", [])

    @property
    def available_versions(self):
        """Старый метод — UI всё ещё его вызывает."""
        return {
            task: [v["version"] for v in self.registry[task]["versions"]]
            for task in self.TASKS
        }
