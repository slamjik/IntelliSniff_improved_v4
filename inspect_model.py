"""
Полная диагностика модели model.joblib.
Запуск:
    python inspect_model.py
"""

import json
import joblib
import inspect
from pathlib import Path
from pprint import pprint
import sys

print("\n=== MODEL INSPECT TOOL ===")

# путь к модели
possible_paths = [
    "model.joblib",
    "traffic_analyzer/data/model.joblib",
    "traffic_analyzer/model.joblib",
    "data/model.joblib",
]

model_path = None
for p in possible_paths:
    if Path(p).exists():
        model_path = p
        break

if not model_path:
    print("❌ model.joblib не найден")
    sys.exit(1)

print(f"📦 Используем модель: {model_path}")

# загружаем модель как есть
obj = joblib.load(model_path)

print("\n=== RAW OBJECT TYPE ===")
print(type(obj), "\n")

# если это dict — печатаем ключи верхнего уровня
if isinstance(obj, dict):
    print("=== TOP-LEVEL DICT KEYS ===")
    print(list(obj.keys()))

    if "model" in obj:
        model = obj["model"]
        print("\n=== MODEL OBJECT TYPE ===")
        print(type(model))

    else:
        model = None
else:
    model = obj


print("\n=== MODEL ATTRIBUTES ===")
attrs = [a for a in dir(model) if not a.startswith("_")]
for a in attrs:
    try:
        v = getattr(model, a)
        if isinstance(v, (int, float, bool, str, list, tuple)):
            print(f"{a}: {v}")
        elif isinstance(v, dict):
            print(f"{a}: dict({len(v)})")
        else:
            print(f"{a}: {type(v)}")
    except Exception as e:
        print(f"{a}: <error {e}>")

# --- FEATURE NAMES ---
print("\n=== FEATURE NAMES MODEL EXPECTS ===")
try:
    names = model.feature_names_in_
    print("feature_names_in_:")
    pprint(list(names))
except Exception as e:
    print("⚠ model.feature_names_in_ не найден:", e)

# ---- If model is a pipeline ----
if "steps" in dir(model):
    try:
        print("\n=== PIPELINE STEPS ===")
        pprint(model.steps)
    except:
        pass

# --- FEATURE IMPORTANCES ---
print("\n=== FEATURE IMPORTANCE ===")
try:
    fi = model.feature_importances_
    n = len(fi)
    print(f"Количество фичей: {n}")
    print("Top 20:")
    for i, imp in enumerate(fi[:20]):
        print(f"{i:3d}: {imp}")
except Exception as e:
    print("⚠ feature_importances_ недоступно:", e)

# --- CLASSES ---
print("\n=== MODEL CLASSES ===")
try:
    pprint(model.classes_)
except Exception as e:
    print("⚠ model.classes_ отсутствует:", e)

# --- Parameters ---
print("\n=== MODEL PARAMETERS ===")
try:
    params = model.get_params()
    pprint(params)
except Exception as e:
    print("⚠ get_params() ошибка:", e)

# --- Try SHAP compatibility ---
print("\n=== CHECKING SHAP COMPATIBILITY ===")
try:
    import shap

    try:
        explainer = shap.TreeExplainer(model)
        print("SHAP TreeExplainer OK")
    except Exception as e:
        print("TreeExplainer ERROR:", e)

except ImportError:
    print("SHAP не установлен")


print("\n=== END ===")
