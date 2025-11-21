"""
Improved VPN detection training script.
Стратегия: балансировка датасета
 - Берём весь VPN-трафик (часто мало)
 - Берём x3 больше НЕ VPN случайным образом
 - Объединяем
 - Обучаем RandomForest
"""

import os
import json
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
import seaborn as sns
import matplotlib.pyplot as plt


BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "merged_snake.parquet")
FEATURES_PATH = os.path.join(DATA_DIR, "features.json")
MODEL_PATH = os.path.join(DATA_DIR, "vpn_model.joblib")


def load_features():
    with open(FEATURES_PATH, "r") as f:
        return json.load(f)


def main():
    print("📂 Загружаю датасет...")
    df = pd.read_parquet(DATASET_PATH)

    print(f"🔢 Всего строк: {len(df):,}")

    # === VPN LABEL ==============================================================
    df["vpn_binary"] = df["label"].str.contains("VPN", case=False, na=False).astype(int)

    df_vpn = df[df["vpn_binary"] == 1]
    df_non = df[df["vpn_binary"] == 0]

    print(f"🔵 VPN строк: {len(df_vpn):,}")
    print(f"⚪ NON-VPN строк: {len(df_non):,}")

    # ==== BALANCING ==============================================================
    TARGET_RATIO = 3   # берём x3 больше НЕ VPN

    non_needed = len(df_vpn) * TARGET_RATIO

    df_non_sampled = df_non.sample(non_needed, random_state=42)

    df_balanced = pd.concat([df_vpn, df_non_sampled], axis=0)
    df_balanced = df_balanced.sample(frac=1, random_state=42)  # перемешиваем

    print(f"⚖️ Итоговый размер после балансировки: {len(df_balanced):,}")

    y = df_balanced["vpn_binary"]
    FEATURES = load_features()

    for f in FEATURES:
        if f not in df_balanced.columns:
            raise ValueError(f"❌ Признак отсутствует: {f}")

    X = df_balanced[FEATURES].fillna(0).astype(np.float32)

    # === Train/Test Split =======================================================
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, stratify=y, test_size=0.2, random_state=42
    )

    # === Balanced Class Weights ==================================================
    classes = np.unique(y_train)
    cw = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight = dict(zip(classes, cw))

    # === MODEL ===================================================================
    model = RandomForestClassifier(
        n_estimators=220,
        max_depth=25,
        max_features="sqrt",
        class_weight=class_weight,
        n_jobs=-1,
        random_state=42
    )

    print("🌲 Обучение VPN модели...")
    model.fit(X_train, y_train)

    # === Evaluation ==============================================================
    y_pred = model.predict(X_test)

    print("\n📊 ОТЧЁТ:")
    print(classification_report(y_test, y_pred))
    print("🎯 Accuracy:", accuracy_score(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
    plt.title("Confusion Matrix — VPN Model (Balanced)")
    plt.tight_layout()
    plt.savefig(os.path.join(DATA_DIR, "vpn_confusion.png"))

    # === Save model ==============================================================
    joblib.dump(
        {"model": model, "features": FEATURES, "trained_at": time.time()},
        MODEL_PATH
    )

    print(f"\n💾 Готово! Улучшенная VPN-модель сохранена: {MODEL_PATH}")


if __name__ == "__main__":
    main()
