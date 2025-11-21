import os
import json
import joblib
import numpy as np
import pandas as pd
from tabulate import tabulate

BASE_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.join(BASE_DIR, "..", "datasets", "merged_snake.parquet")

ATTACK_MODEL_PATH = os.path.join(BASE_DIR, "data", "attack_model.joblib")
VPN_MODEL_PATH = os.path.join(BASE_DIR, "data", "vpn_model.joblib")
FEATURES_PATH = os.path.join(BASE_DIR, "data", "features.json")


# ============== Helper: safe extract ==============
def ensure_features(df, FEATURES):
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise ValueError("❌ В датасете нет признаков:\n" + "\n".join(missing))
    return df[FEATURES].fillna(0).astype(np.float32)


def sample_rows(df, count):
    count = min(len(df), count)
    return df.sample(count, random_state=42)


def main():
    print("\n📂 Загружаю датасет...")
    df = pd.read_parquet(DATASET_PATH)

    print(f"Всего строк: {len(df):,}")

    # ==== Labels extracted from dataset ====
    df["vpn_binary"] = df["label"].str.contains("VPN", case=False, na=False).astype(int)
    df["attack_binary"] = df["label_binary"]

    # ==== Load models ====
    attack_bundle = joblib.load(ATTACK_MODEL_PATH)
    vpn_bundle = joblib.load(VPN_MODEL_PATH)

    attack_model = attack_bundle["model"]
    vpn_model = vpn_bundle["model"]

    FEATURES = attack_bundle["features"]  # идентичны для обеих моделей

    print("\n📦 Модели загружены.")
    print(f"Фичей используется: {len(FEATURES)}")

    # ==== Сэмплинг реальных атак и benign ====
    print("\n🎯 Формирую тестовый набор...")

    slices = {
        "Benign": sample_rows(df[df["attack_binary"] == 0], 20),
        "DoS": sample_rows(df[df["label"].str.contains("DoS", na=False)], 10),
        "DDoS": sample_rows(df[df["label"].str.contains("DDoS", na=False)], 10),
        "PortScan": sample_rows(df[df["label"].str.contains("PortScan", na=False)], 10),
        "Botnet": sample_rows(df[df["label"].str.contains("Bot", na=False)], 10),
        "Bruteforce": sample_rows(df[df["label"].str.contains("Brute", na=False)], 10),
        "WebAttack": sample_rows(df[df["label"].str.contains("Web Attack", na=False)], 10),
        "VPN": sample_rows(df[df["vpn_binary"] == 1], 10),
        "Non-VPN": sample_rows(df[df["vpn_binary"] == 0], 10),
    }

    rows = []
    for label, part in slices.items():
        for _, row in part.iterrows():
            rows.append((label, row))

    print(f"🔢 Всего тестовых потоков: {len(rows)}")

    # ==== Тестирование ====
    results = []

    for label, row in rows:
        vec = ensure_features(pd.DataFrame([row]), FEATURES)

        attack_pred = attack_model.predict(vec)[0]
        attack_prob = attack_model.predict_proba(vec)[0].max()

        vpn_pred = vpn_model.predict(vec)[0]
        vpn_prob = vpn_model.predict_proba(vec)[0].max()

        results.append([
            label,
            int(row["attack_binary"]),
            int(row["vpn_binary"]),
            attack_pred,
            round(attack_prob, 4),
            vpn_pred,
            round(vpn_prob, 4)
        ])

    # ==== Табличный вывод ====
    print("\n📊 РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")
    print(tabulate(
        results,
        headers=[
            "Real Class",
            "Real Attack", "Real VPN",
            "Pred Attack", "Attack Prob",
            "Pred VPN", "VPN Prob"
        ],
        tablefmt="grid"
    ))

    # ==== Сводка ====
    attack_correct = sum(r[1] == r[3] for r in results)
    vpn_correct = sum(r[2] == r[5] for r in results)

    print("\n🎯 Attack Accuracy:", attack_correct / len(results))
    print("🎯 VPN Accuracy:", vpn_correct / len(results))

    print("\n🟢 Тест завершён! Оба классификатора проверены.")


if __name__ == "__main__":
    main()
