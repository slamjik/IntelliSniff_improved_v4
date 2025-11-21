"""
Training script for IntelliSniff ML model.

Особенности:
 - Читает список признаков из ml/data/features.json
 - Обучает модель только на этих признаках
 - Сохраняет модель в model.joblib вместе со списком признаков
 - Полностью совместим с новым inference.py
"""

import argparse
import os
import sys
import time
import json
import logging
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

import seaborn as sns
import matplotlib.pyplot as plt


# ============================================================================
# Пути
# ============================================================================

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "merged_detailed.parquet")
FEATURES_PATH = os.path.join(DATA_DIR, "features.json")

log = logging.getLogger("IntelliSniff.train_model")


# ============================================================================
# Загрузка списка признаков
# ============================================================================

def load_feature_list(path=FEATURES_PATH):
    """
    Загружает список признаков из JSON.
    Это *единственный источник истины* для обучения и инференса.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"❌ Файл списка признаков не найден: {path}")

    with open(path, "r") as f:
        features = json.load(f)

    print(f"📌 Загружено признаков: {len(features)} шт.")
    return features


# ============================================================================
# Загрузка датасета
# ============================================================================

def load_dataset(path=DATASET_PATH, label_type="binary"):
    """
    Загружает parquet-файл с объединёнными CICIDS / VPN / Benign данными.
    """
    print(f"📂 Загружаю датасет: {path}")
    df = pd.read_parquet(path)

    # Выбор метки
    if label_type == "multi" and "label_multi" in df.columns:
        y = LabelEncoder().fit_transform(df["label_multi"])
    elif "label_binary" in df.columns:
        y = df["label_binary"]
    elif "label" in df.columns:
        y = df["label"]
    else:
        raise ValueError("❌ В датасете нет label / label_binary / label_multi")

    print(f"🔎 Найдено {df.shape[0]:,} строк и {df.shape[1]} столбцов")
    return df, y


# ============================================================================
# Обучение модели
# ============================================================================

def train_and_save(df, y, features, out_path=MODEL_PATH):
    """
    Обучает RandomForestClassifier на фиксированном списке признаков.
    """

    print("\n🧩 Используем признаки:")
    for f in features:
        print("  •", f)

    # На всякий случай проверяем, что все фичи есть в датасете
    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(f"❌ В датасете отсутствуют признаки: {missing}")

    # Формируем X
    X = df[features].fillna(0).astype(np.float32)
    print(f"📊 Матрица признаков: {X.shape[0]:,} строк × {X.shape[1]} фичей")

    # Разбивка train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    # Весы классов
    classes = np.unique(y_train)
    class_weights = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight_dict = dict(zip(classes, class_weights))

    # База модели
    rf_base = RandomForestClassifier(
        class_weight=class_weight_dict,
        random_state=42,
        n_jobs=-1,
    )

    # Гиперпараметры для RandomizedSearch
    param_dist = {
        "n_estimators": [200, 300, 400],
        "max_depth": [10, 20, 30, None],
        "min_samples_split": [2, 3, 5],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"],
    }

    print("\n🔍 Подбор гиперпараметров...")
    search = RandomizedSearchCV(
        rf_base,
        param_distributions=param_dist,
        n_iter=8,
        cv=3,
        scoring="accuracy",
        n_jobs=-1,
        verbose=1,
        random_state=42,
    )

    search.fit(X_train, y_train)
    best_model = search.best_estimator_

    print(f"🏆 Лучшие параметры: {search.best_params_}")

    print("🌲 Обучение финальной модели...")
    best_model.fit(X_train, y_train)
    y_pred = best_model.predict(X_test)

    print("\n📊 ОТЧЁТ:")
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"🎯 Accuracy: {accuracy_score(y_test, y_pred):.4f}")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix — IntelliSniff Model")
    plt.xlabel("Предсказано")
    plt.ylabel("Истинный класс")
    plt.tight_layout()
    plt.savefig(os.path.join(DATA_DIR, "confusion_matrix.png"))
    print("🖼️ confusion_matrix.png сохранена.")

    # Сохраняем bundle модели
    joblib.dump(
        {
            "model": best_model,
            "features": features,
            "trained_at": time.time(),
        },
        out_path
    )

    print(f"\n💾 Модель сохранена: {out_path}")
    return out_path


# ============================================================================
# MAIN
# ============================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(description="Тренировка ML модели IntelliSniff")
    parser.add_argument("--dataset", type=str, default=None, help="Путь к parquet/csv датасету")
    parser.add_argument("--label-type", choices=["binary", "multi"], default="binary")
    args = parser.parse_args(argv)

    dataset_path = args.dataset or DATASET_PATH

    df, y = load_dataset(dataset_path, args.label_type)
    features = load_feature_list()

    result = train_and_save(df, y, features, out_path=MODEL_PATH)
    print(f"✅ Модель обучена и сохранена в: {result}")


if __name__ == "__main__":
    main(sys.argv[1:])
