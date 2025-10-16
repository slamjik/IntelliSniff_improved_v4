import argparse
import os
import sys
import time
import logging

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# === ПУТИ ===============================================================
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "merged_detailed.parquet")

log = logging.getLogger("IntelliSniff.train_model")


# === ЗАГРУЗКА ============================================================
def load_dataset(path=DATASET_PATH, label_type="binary"):
    """Загружает parquet и подготавливает X, y"""
    print(f"📂 Loading dataset from {path}")
    df = pd.read_parquet(path)

    # Выбор метки
    if label_type == "multi" and "label_multi" in df.columns:
        y = df["label_multi"]
        y = LabelEncoder().fit_transform(y)
    elif "label_binary" in df.columns:
        y = df["label_binary"]
    elif "label" in df.columns:
        y = df["label"]
    else:
        raise ValueError("❌ Dataset missing label column")

    # Выбор признаков
    drop_cols = [c for c in ["label", "label_binary", "label_multi"] if c in df.columns]
    X = df.drop(columns=drop_cols, errors="ignore")

    # Преобразование типов
    X = X.select_dtypes(include=[np.number]).fillna(0).astype(np.float32)
    print(f"✅ Dataset loaded: {X.shape[0]:,} rows, {X.shape[1]} features")
    return X, y


# === ОБУЧЕНИЕ ============================================================
def train_and_save(X, y, out_path=MODEL_PATH):
    """Обучает RandomForest и сохраняет модель"""
    # Удаляем старую модель, если есть
    if os.path.exists(out_path):
        try:
            os.remove(out_path)
            print(f"🧹 Старый файл модели удалён: {out_path}")
        except PermissionError:
            print(f"⚠️ Не удалось удалить старую модель (файл занят). Закрой процессы и повтори.")
            return None

    print("⚙️  Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
    )

    print("🌲 Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("\n📊 [TRAIN REPORT]")
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")

    joblib.dump({
        "model": clf,
        "features": X.columns.tolist(),
        "trained_at": time.time(),
    }, out_path)

    print(f"💾 Model saved to: {out_path}")
    return out_path


# === АВТО-ПЕРЕОБУЧЕНИЕ ===================================================
def retrain_if_needed(force=False):
    """Переобучает модель, если датасет изменился"""
    if not os.path.exists(DATASET_PATH):
        print("❌ Merged dataset not found:", DATASET_PATH)
        return None

    if not os.path.exists(MODEL_PATH):
        print("📘 No model found — training new one...")
        X, y = load_dataset()
        return train_and_save(X, y)

    model_mtime = os.path.getmtime(MODEL_PATH)
    data_mtime = os.path.getmtime(DATASET_PATH)
    if force or data_mtime > model_mtime:
        print("🔁 Dataset is newer — retraining model...")
        X, y = load_dataset()
        return train_and_save(X, y)

    print("✅ Model is up-to-date.")
    return MODEL_PATH


def train_from_dataset(dataset_path=None, label_type="binary", out_path=MODEL_PATH):
    """Высокоуровневая обёртка: загрузить датасет и обучить модель."""
    dataset_path = dataset_path or DATASET_PATH
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    X, y = load_dataset(path=dataset_path, label_type=label_type)
    return train_and_save(X, y, out_path=out_path)


def train_demo_model(out_path=MODEL_PATH):
    """Обучает синтетическую демо-модель (используется в UI)."""
    from .classification import train_demo_model as _train_demo_model

    return _train_demo_model(out_path)


def main(argv=None):
    """CLI-вход для python -m traffic_analyzer.train_model"""
    parser = argparse.ArgumentParser(description="Train IntelliSniff model")
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Путь к parquet/csv датасету (по умолчанию datasets/merged_detailed.parquet)",
    )
    parser.add_argument(
        "--label-type",
        choices=["binary", "multi"],
        default="binary",
        help="Тип меток для обучения",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Игнорировать проверку времени модификации модели при --retrain-if-needed",
    )
    parser.add_argument(
        "--retrain-if-needed",
        action="store_true",
        help="Переобучить модель только если датасет новее существующей модели",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Обучить синтетическую демо-модель вместо реального датасета",
    )
    args = parser.parse_args(argv)

    if args.demo:
        path = train_demo_model()
        print(f"✅ Demo model saved to {path}")
        return path

    if args.retrain_if_needed:
        return retrain_if_needed(force=args.force)

    dataset_path = args.dataset or DATASET_PATH
    result = train_from_dataset(dataset_path, args.label_type)
    print(f"✅ Model trained from {dataset_path} -> {result}")
    return result


# === MAIN ================================================================
if __name__ == "__main__":
    main(sys.argv[1:])
