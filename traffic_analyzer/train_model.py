import argparse
import os
import sys
import time
import logging
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
import seaborn as sns
import matplotlib.pyplot as plt


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

    # выбор метки
    if label_type == "multi" and "label_multi" in df.columns:
        y = LabelEncoder().fit_transform(df["label_multi"])
    elif "label_binary" in df.columns:
        y = df["label_binary"]
    elif "label" in df.columns:
        y = df["label"]
    else:
        raise ValueError("❌ Dataset missing label column")

    # выбор признаков
    drop_cols = [c for c in ["label", "label_binary", "label_multi"] if c in df.columns]
    X = df.drop(columns=drop_cols, errors="ignore").select_dtypes(include=[np.number]).fillna(0).astype(np.float32)

    print(f"✅ Dataset loaded: {X.shape[0]:,} rows, {X.shape[1]} features")
    return X, y


# === РАСШИРЕННОЕ ОБУЧЕНИЕ ==============================================
def train_and_save(X, y, out_path=MODEL_PATH):
    """Обучает RandomForest с автооптимизацией и сохраняет модель"""
    if os.path.exists(out_path):
        try:
            os.remove(out_path)
            print(f"🧹 Старый файл модели удалён: {out_path}")
        except PermissionError:
            print(f"⚠️ Не удалось удалить старую модель. Закрой процессы и повтори.")
            return None

    print("⚙️  Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
    )

    # 🧩 Ограничим выборку для RandomizedSearch, чтобы не упасть по памяти
    if len(X_train) > 200_000:
        print(f"⚙️ Dataset too large for full search ({len(X_train):,} rows) → sampling 200,000 for tuning...")
        sample_idx = np.random.choice(len(X_train), 200_000, replace=False)
        X_sample = X_train.iloc[sample_idx]
        y_sample = y_train[sample_idx]  # ← вот это исправление
    else:
        X_sample, y_sample = X_train, y_train

    # расчет весов классов
    classes = np.unique(y_sample)
    from sklearn.utils.class_weight import compute_class_weight
    class_weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_sample)
    class_weight_dict = dict(zip(classes, class_weights))

    print("🔍 Auto-tuning hyperparameters (RandomizedSearchCV)...")
    rf_base = RandomForestClassifier(class_weight=class_weight_dict, random_state=42, n_jobs=-1)
    param_dist = {
        "n_estimators": [200, 300, 400],
        "max_depth": [10, 20, 30, None],
        "min_samples_split": [2, 3, 5],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"],
    }

    from sklearn.model_selection import RandomizedSearchCV
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
    search.fit(X_sample, y_sample)
    clf = search.best_estimator_

    print(f"🏆 Best Params: {search.best_params_}")

    print("🌲 Training optimized RandomForestClassifier on full data...")
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    print("\n📊 [TRAIN REPORT]")
    from sklearn.metrics import classification_report, accuracy_score
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")

    import seaborn as sns, matplotlib.pyplot as plt
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix — IntelliSniff Model")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(os.path.join(DATA_DIR, "confusion_matrix.png"))
    print(f"🖼️ Confusion matrix saved to {os.path.join(DATA_DIR, 'confusion_matrix.png')}")

    joblib.dump(
        {"model": clf, "features": X.columns.tolist(), "trained_at": time.time()},
        out_path,
    )
    print(f"💾 Model saved to: {out_path}")
    return out_path

    # === ОЦЕНКА =======================================================
    print("\n📊 [TRAIN REPORT]")
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")

    # === CONFUSION MATRIX ============================================
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix — IntelliSniff Model")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(os.path.join(DATA_DIR, "confusion_matrix.png"))
    print(f"🖼️ Confusion matrix saved to {os.path.join(DATA_DIR, 'confusion_matrix.png')}")

    # === СОХРАНЕНИЕ ==================================================
    joblib.dump(
        {"model": clf, "features": X.columns.tolist(), "trained_at": time.time()},
        out_path,
    )
    print(f"💾 Model saved to: {out_path}")
    return out_path


# === ЗАПУСК ==============================================================
def train_from_dataset(dataset_path=None, label_type="binary", out_path=MODEL_PATH):
    dataset_path = dataset_path or DATASET_PATH
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    X, y = load_dataset(path=dataset_path, label_type=label_type)
    return train_and_save(X, y, out_path=out_path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train IntelliSniff model (enhanced)")
    parser.add_argument("--dataset", type=str, default=None, help="Путь к parquet/csv датасету")
    parser.add_argument("--label-type", choices=["binary", "multi"], default="binary")
    args = parser.parse_args(argv)

    dataset_path = args.dataset or DATASET_PATH
    result = train_from_dataset(dataset_path, args.label_type)
    print(f"✅ Model trained from {dataset_path} -> {result}")
    return result


if __name__ == "__main__":
    main(sys.argv[1:])
