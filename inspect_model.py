"""
Поддерживает структуру моделей IntelliSniff:
attack_model_1.joblib
vpn_model_1.joblib
Внутри: {"model": sklearn_model, "features": [...]}
"""

import joblib
import json
from pathlib import Path
from pprint import pprint
import sys

print("\n=== INTELLISNIFF MODEL INSPECTOR ===")

# --- ИЩЕМ ВСЕ JOBLIB МОДЕЛИ В ml/data ---
BASE = Path("ml/data")
if not BASE.exists():
    print("❌ Папка ml/data не найдена")
    sys.exit(1)

models = sorted(BASE.glob("*_model_*.joblib"))
if not models:
    print("❌ В ml/data нет файлов *_model_*.joblib")
    sys.exit(1)

print(f"\n🔍 Найдены модели ({len(models)}):")
for m in models:
    print("  •", m.name)

print("\n======================\n")


# ------------------------------------------------------------------
# ФУНКЦИЯ ПЕЧАТИ МОДЕЛИ
# ------------------------------------------------------------------
def inspect_bundle(path: Path):
    print(f"\n=== 📦 Модель: {path.name} ===")

    bundle = joblib.load(path)

    if not isinstance(bundle, dict):
        print("❌ Файл НЕ является bundle dict → непонятный формат")
        return

    keys = list(bundle.keys())
    print("🔑 Ключи:", keys)

    model = bundle.get("model")
    features = bundle.get("features")
    trained = bundle.get("trained_at")

    print(f"\n📌 trained_at: {trained}")
    print(f"📌 Количество фичей: {len(features) if features else 0}")

    if features:
        print("\n=== FEATURES ===")
        pprint(features)

    # ------------------------------------------------------------------
    # ATRIBUTES
    # ------------------------------------------------------------------
    if model is None:
        print("❌ model отсутствует в bundle")
        return

    print("\n=== MODEL OBJECT TYPE ===")
    print(type(model))

    print("\n=== MODEL ATTRIBUTES ===")
    attrs = [a for a in dir(model) if not a.startswith("_")]
    for a in attrs:
        try:
            v = getattr(model, a)
            if isinstance(v, (int, float, str)):
                print(f"{a}: {v}")
            elif isinstance(v, list):
                print(f"{a}: list({len(v)})")
            elif isinstance(v, dict):
                print(f"{a}: dict({len(v)})")
            else:
                print(f"{a}: {type(v)}")
        except:
            pass

    # ------------------------------------------------------------------
    # pipeline?
    # ------------------------------------------------------------------
    if hasattr(model, "steps"):
        print("\n=== PIPELINE STEPS ===")
        pprint(model.steps)

    # ------------------------------------------------------------------
    # feature_names_in_
    # ------------------------------------------------------------------
    print("\n=== MODEL.feature_names_in_ ===")
    try:
        pprint(list(model.feature_names_in_))
    except Exception as e:
        print("⚠ feature_names_in_ отсутствует:", e)

    # ------------------------------------------------------------------
    # feature_importances_
    # ------------------------------------------------------------------
    print("\n=== FEATURE IMPORTANCE ===")
    try:
        fi = model.feature_importances_
        print(f"Всего: {len(fi)}")
        print("Top 20:")
        for i, imp in enumerate(fi[:20]):
            print(f"{i:3d}: {imp}")
    except Exception as e:
        print("⚠ Нет feature_importances_:", e)

    # ------------------------------------------------------------------
    # classes_
    # ------------------------------------------------------------------
    print("\n=== MODEL CLASSES ===")
    try:
        pprint(model.classes_)
    except Exception as e:
        print("⚠ Нет .classes_:", e)

    # ------------------------------------------------------------------
    # parameters
    # ------------------------------------------------------------------
    print("\n=== MODEL PARAMETERS ===")
    try:
        pprint(model.get_params())
    except Exception as e:
        print("⚠ Ошибка get_params():", e)

    print("\n====================\n")


# ------------------------------------------------------------------
# Запуск для всех моделей
# ------------------------------------------------------------------
for m in models:
    inspect_bundle(m)

print("\n=== END ===")
