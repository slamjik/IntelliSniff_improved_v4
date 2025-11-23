import json
import os
import traceback
from pprint import pprint

from traffic_analyzer.ml_runtime import (
    get_model_manager,
    get_predictor,
    get_drift_detector,
    get_auto_updater,
)


def print_header(title):
    print("\n" + "=" * 80)
    print("🔍 " + title)
    print("=" * 80)


def safe_run(title, func):
    print_header(title)
    try:
        res = func()
        print("✅ OK")
        if res is not None:
            pprint(res)
        return res
    except Exception as e:
        print("❌ ERROR:", e)
        traceback.print_exc()
        return None


# =============================================================================
# 1. ModelManager debugging
# =============================================================================

def debug_model_manager():
    manager = get_model_manager()

    print_header("Пути ModelManager")
    print("base_dir =", manager.base_dir)
    print("data_dir =", manager.data_dir)
    print("registry =", manager.registry_path)

    safe_run("Чтение model_registry.json", lambda: manager.registry)
    safe_run("Список задач (TASKS)", lambda: manager.TASKS)

    for task in manager.TASKS:
        safe_run(
            f"Версии для задачи: {task}",
            lambda t=task: manager.available_versions.get(t)
        )


# =============================================================================
# 2. Проверяем, грузятся ли модели правильно
# =============================================================================

def debug_models_load():
    manager = get_model_manager()

    for task in manager.TASKS:

        def check_load(task=task):
            info = manager.get_active_model_info(task)
            print("Активная модель:", info)

            if info is None:
                return "❌ Нет активной модели"

            # NEW: ModelInfo API
            version = info.version
            print("→ Loading version:", version)

            bundle = manager._load_model_object(task, version)
            return {
                "version": version,
                "model_keys": list(bundle.keys()),
                "features_count": len(bundle["features"]),
                "model_type": type(bundle["model"]).__name__,
            }

        safe_run(f"Загрузка активной модели '{task}'", check_load)


# =============================================================================
# 3. Проверка features.json
# =============================================================================

def debug_features():
    path = os.path.join(
        os.path.dirname(__file__), "..", "ml", "data", "features.json"
    )

    print_header("Проверка features.json")
    if not os.path.exists(path):
        print("❌ features.json отсутствует:", path)
        return

    with open(path, "r") as f:
        data = json.load(f)

    print("Всего признаков:", len(data))
    pprint(data[:25])


# =============================================================================
# 4. Проверка predictor
# =============================================================================

def debug_predictor():
    predictor = get_predictor()

    example = {f"f{i}": float(i) for i in range(1, 43)}

    print_header("Пробуем сделать предсказание атак модели")
    safe_run(
        "predict(attack)",
        lambda: predictor.predict(example, task="attack")
    )

    print_header("Пробуем сделать предсказание vpn модели")
    safe_run(
        "predict(vpn)",
        lambda: predictor.predict(example, task="vpn")
    )


# =============================================================================
# 5. Проверка API-компонентов напрямую
# =============================================================================

def debug_tasks_from_api():

    from traffic_analyzer.api import (
        api_get_versions,
        api_model_status,
    )

    print_header("Проверка API функций напрямую, без FastAPI")

    safe_run("/get_versions attack", lambda: api_get_versions("attack"))
    safe_run("/get_versions vpn", lambda: api_get_versions("vpn"))
    safe_run("/model_status", lambda: api_model_status())


# =============================================================================
# FULL DEBUG ENTRY
# =============================================================================

def full_debug():
    print("\n\n==============================")
    print("🚀 FULL INTELLISNIFF ML DEBUG")
    print("==============================\n")

    debug_model_manager()
    debug_models_load()
    debug_features()
    debug_predictor()
    debug_tasks_from_api()

    print("\n🎉 ОТЛАДКА ЗАВЕРШЕНА\n")


if __name__ == "__main__":
    full_debug()
