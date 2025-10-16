import os
import sys
import time
import joblib
import logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
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
        "trained_at": time.time()
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


# === MAIN ================================================================
if __name__ == "__main__":
    label_mode = "binary"  # можно также "multi"
    if len(sys.argv) > 1 and sys.argv[1] in ("binary", "multi"):
        label_mode = sys.argv[1]

    X, y = load_dataset(label_type=label_mode)
    train_and_save(X, y)
