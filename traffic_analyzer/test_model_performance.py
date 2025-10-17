import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import seaborn as sns
import matplotlib.pyplot as plt

# === Пути ===
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "merged_detailed.parquet")

# === Загрузка модели ===
print(f"📦 Loading model from: {MODEL_PATH}")
bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
features = bundle["features"]

# === Загрузка датасета ===
print(f"📂 Loading dataset: {DATASET_PATH}")
df = pd.read_parquet(DATASET_PATH)

# Определяем целевую метку
if "label_multi" in df.columns:
    y = df["label_multi"]
elif "label_binary" in df.columns:
    y = df["label_binary"]
elif "label" in df.columns:
    y = df["label"]
else:
    raise ValueError("❌ No label column found in dataset")

# Преобразуем признаки
X = df[features].copy()
X = X.select_dtypes(include=[np.number]).fillna(0).astype(np.float32)

# Кодируем метки, если нужно
if not np.issubdtype(y.dtype, np.number):
    y = LabelEncoder().fit_transform(y)

# === Предсказания ===
print("🔍 Running predictions...")
start = time.time()
y_pred = model.predict(X)
end = time.time()
print(f"⚡ Inference time: {end - start:.2f}s for {len(X):,} samples")

# === Отчёт ===
print("\n📊 [MODEL EVALUATION REPORT]")
print(classification_report(y, y_pred, zero_division=0))
print(f"✅ Accuracy: {accuracy_score(y, y_pred):.4f}")

# === Матрица ошибок ===
cm = confusion_matrix(y, y_pred)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=False, cmap="Blues")
plt.title("Confusion Matrix — IntelliSniff Model (Test Evaluation)")
plt.xlabel("Predicted")
plt.ylabel("Actual")

out_path = os.path.join(DATA_DIR, "confusion_matrix_test.png")
plt.savefig(out_path, dpi=200)
plt.close()
print(f"🖼️ Confusion matrix saved to {out_path}")
