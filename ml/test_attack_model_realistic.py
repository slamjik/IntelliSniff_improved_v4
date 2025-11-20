import os
import json
import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "data", "attack_model.joblib")
FEATURES_PATH = os.path.join(BASE_DIR, "data", "features.json")

# ================== 1. ЛЁГКАЯ АТАКА (DoS/DDoS Hulk/LOIC) ======================
def gen_easy_attack(features):
    d = {f: 0.0 for f in features}

    # Протокол — чаще всего TCP или UDP
    d["protocol"] = np.random.choice([6, 17])

    # Огромный поток пакетов
    d["total_fwd_packets"] = np.random.randint(5000, 15000)
    d["total_bwd_packets"] = np.random.randint(1000, 5000)

    # Ультра высокая скорость
    d["flow_bytes_per_s"] = np.random.randint(1_000_000, 5_000_000)
    d["flow_packets_per_s"] = np.random.randint(5000, 15000)

    # Минимальный IAT
    d["flow_iat_mean"] = np.random.randint(1, 30)
    d["flow_iat_std"] = np.random.randint(1, 15)

    d["packet_length_mean"] = np.random.randint(800, 1500)
    d["packet_length_std"] = np.random.randint(100, 400)

    return d


# ================== 2. СРЕДНЯЯ АТАКА (PORTSCAN / NMAP) ========================
def gen_medium_attack(features):
    d = {f: 0.0 for f in features}

    d["protocol"] = np.random.choice([6, 17])

    # Маленькие bursts
    d["total_fwd_packets"] = np.random.randint(80, 200)
    d["total_bwd_packets"] = np.random.randint(20, 80)

    d["flow_packets_per_s"] = np.random.randint(300, 1000)
    d["flow_bytes_per_s"] = np.random.randint(50_000, 150_000)

    # Маленькие пакеты
    d["packet_length_mean"] = np.random.randint(50, 200)
    d["packet_length_std"] = np.random.randint(10, 60)

    # Ритмичные IAT
    d["flow_iat_mean"] = np.random.randint(200, 800)
    d["flow_iat_std"] = np.random.randint(50, 200)

    return d


# ================== 3. ТЯЖЁЛАЯ АТАКА (Slowloris / SlowHTTPTest) ===============
def gen_hard_attack(features):
    d = {f: 0.0 for f in features}

    d["protocol"] = 6  # почти всегда TCP

    # Мало пакетов → но атака
    d["total_fwd_packets"] = np.random.randint(10, 40)
    d["total_bwd_packets"] = np.random.randint(1, 10)

    d["flow_packets_per_s"] = np.random.randint(1, 10)
    d["flow_bytes_per_s"] = np.random.randint(5_000, 20_000)

    # Огромные интервалы
    d["flow_iat_mean"] = np.random.randint(50_000, 150_000)
    d["flow_iat_std"] = np.random.randint(20_000, 80_000)

    d["packet_length_mean"] = np.random.randint(200, 800)
    d["packet_length_std"] = np.random.randint(100, 400)

    return d


# ================== 4. BOTNET / MALWARE C&C ========================
def gen_botnet_attack(features):
    d = {f: 0.0 for f in features}

    d["protocol"] = np.random.choice([6, 17])

    d["total_fwd_packets"] = np.random.randint(100, 300)
    d["total_bwd_packets"] = np.random.randint(50, 200)

    d["flow_bytes_per_s"] = np.random.randint(20_000, 80_000)
    d["flow_packets_per_s"] = np.random.randint(100, 400)

    # Нестабильные IAT
    d["flow_iat_mean"] = np.random.randint(2000, 7000)
    d["flow_iat_std"] = np.random.randint(500, 3000)

    d["packet_length_mean"] = np.random.randint(200, 700)
    d["packet_length_std"] = np.random.randint(100, 400)

    return d


def main():
    print("📂 Загружаю модель...")
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    features = bundle["features"]

    tests = {
        "🟢 Лёгкая атака (DoS/DDoS)": gen_easy_attack(features),
        "🟡 Средняя атака (PortScan)": gen_medium_attack(features),
        "🔴 Тяжёлая атака (Slowloris)": gen_hard_attack(features),
        "🟣 Botnet / Malware C&C": gen_botnet_attack(features)
    }

    print("\n🔎 Тестирование attack-модели на реалистичных образцах...\n")

    for title, flow in tests.items():
        df = pd.DataFrame([flow], columns=features).fillna(0).astype(np.float32)
        pred = model.predict(df)[0]
        prob = model.predict_proba(df)[0].max()

        print("==============================================")
        print(title)
        print(f"Предсказание: {pred} (1 = attack)")
        print(f"Уверенность: {prob:.4f}")

    print("==============================================")


if __name__ == "__main__":
    main()
