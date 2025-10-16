
import re
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.io import arff
from sklearn.utils import resample
from tqdm import tqdm

# === ПУТИ ===================================================================
BASE_DIR = Path(__file__).resolve().parent
DATASETS_DIR = (BASE_DIR.parent / "datasets").resolve()
OUT_PARQUET = DATASETS_DIR / "merged_detailed.parquet"
OUT_REPORT = DATASETS_DIR / "merge_report.csv"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ================================================
def make_unique_columns(columns):
    """Делает имена колонок уникальными"""
    seen = {}
    result = []
    for c in columns:
        if c not in seen:
            seen[c] = 1
            result.append(c)
        else:
            seen[c] += 1
            result.append(f"{c}_{seen[c]}")
    return result


def optimize_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """Автоматическая оптимизация типов"""
    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = df[col].astype("float32")
    for col in df.select_dtypes(include=["int64"]).columns:
        df[col] = df[col].astype("int32")
    return df


def safe_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Пытается преобразовать строки в числа, игнорируя ошибки"""
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = pd.to_numeric(df[col], errors="ignore")
    return df


# === НОРМАЛИЗАЦИЯ КОЛОНОК ====================================================
ALIASES = {
    r"^flow duration": "flow duration",
    r"^destination port": "destination port",
    r"^src port|source port": "source port",
    r"^total fwd packets": "total fwd packets",
    r"^total backward packets": "total backward packets",
    r"^total fwd bytes|total length of fwd packets": "total fwd bytes",
    r"^total backward bytes|total length of bwd packets": "total backward bytes",
    r"^protocol": "protocol",
    r"^label|^class|^attack": "label",
}


def clean_cols(df: pd.DataFrame) -> pd.DataFrame:
    """Очистка имён колонок"""
    new_cols = []
    for c in df.columns:
        cc = str(c).lower().strip()
        cc = cc.replace("\ufeff", "")
        cc = re.sub(r"[\s_]+", " ", cc)
        cc = re.sub(r"[^a-z0-9 /]", "", cc)
        for pat, repl in ALIASES.items():
            if re.search(pat, cc):
                cc = repl
        new_cols.append(cc)
    df.columns = make_unique_columns(new_cols)
    return df


def find_label(df: pd.DataFrame):
    """Поиск колонки с метками"""
    for col in df.columns:
        if re.search(r"label|class|attack|category|type", col):
            return df[col]
    return pd.Series(["benign"] * len(df))


def unify_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Добавляет недостающие ключевые колонки"""
    base_cols = [
        "flow duration", "destination port", "source port",
        "total fwd packets", "total backward packets",
        "total fwd bytes", "total backward bytes", "protocol"
    ]
    for col in base_cols:
        if col not in df.columns:
            df[col] = 0
    return df


def map_label_columns(label_series):
    """Создаёт бинарную и мультиклассовую метку"""
    label_series = label_series.astype(str).str.lower().str.strip()
    y_bin = label_series.apply(
        lambda x: 0 if any(t in x for t in ["benign", "normal", "legit", "background", "nonvpn"]) else 1
    )
    y_multi = label_series.apply(
        lambda x: (
            "benign" if any(t in x for t in ["benign", "normal", "legit", "background", "nonvpn"]) else
            ("dos" if "dos" in x else
             "ddos" if "ddos" in x else
             "bruteforce" if "brute" in x else
             "portscan" if "scan" in x else
             "botnet" if "bot" in x else
             "infiltration" if "infil" in x else
             "webattack" if "web" in x else
             "attack")
        )
    )
    return y_bin, y_multi


# === ЧТЕНИЕ ==================================================================
def read_any(path):
    """Загружает CSV, Parquet или ARFF"""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(path, low_memory=False)
    if suffix == ".parquet":
        return pd.read_parquet(path)
    if suffix == ".arff":
        data, _ = arff.loadarff(path)
        df = pd.DataFrame(data)
        df = df.applymap(lambda x: x.decode("utf-8") if isinstance(x, (bytes, bytearray)) else x)
        df = df.replace("", np.nan).dropna(how="all")
        return df
    else:
        raise ValueError(f"❌ Unsupported format: {path}")


# === ГЛАВНАЯ ФУНКЦИЯ =========================================================
def process():
    if OUT_PARQUET.exists():
        OUT_PARQUET.unlink()
        print(f"🧹 Old file removed: {OUT_PARQUET}")

    files = [p for p in DATASETS_DIR.rglob("*") if p.suffix.lower() in (".csv", ".parquet", ".arff")]
    if not files:
        print("❌ No datasets found in", DATASETS_DIR)
        return

    print(f"🔍 Found {len(files)} dataset files\n")

    parts, stats = [], []
    for f in tqdm(files, desc="Reading & normalizing"):
        try:
            df = read_any(f)
            df = clean_cols(df)
            df = safe_numeric(df)

            label_raw = find_label(df)
            df["__label__"] = label_raw
            df = unify_schema(df)
            y_bin, y_multi = map_label_columns(df["__label__"])
            df = df.drop(columns=["__label__"], errors="ignore")

            df = pd.concat([df, pd.DataFrame({
                "label_binary": y_bin,
                "label_multi": y_multi
            }, index=df.index)], axis=1)

            df = df.reset_index(drop=True)
            df.columns = make_unique_columns(df.columns)
            df = df.replace([np.inf, -np.inf], np.nan).dropna(how="all")

            df = optimize_dtypes(df)

            parts.append(df)
            stats.append((f.name, len(df)))
        except Exception as e:
            print(f"⚠️ {f.name}: {e}")

    if not parts:
        print("❌ No datasets processed")
        return

    print("🔄 Concatenating all datasets...")
    merged = pd.concat(parts, ignore_index=True)
    merged = merged.replace([np.inf, -np.inf], np.nan).dropna(how="all")

    # === Балансировка =======================================================
    if "label_binary" in merged.columns:
        counts = merged["label_binary"].value_counts()
        if len(counts) == 2 and counts.min() > 0:
            maj, minc = counts.idxmax(), counts.idxmin()
            if counts[maj] / counts[minc] > 10:
                print("⚖️ Balancing classes (oversampling)...")
                maj_df = merged[merged["label_binary"] == maj]
                min_df = merged[merged["label_binary"] == minc]
                min_up = resample(min_df, replace=True, n_samples=int(len(maj_df) * 0.5), random_state=42)
                merged = pd.concat([maj_df, min_up], ignore_index=True).sample(frac=1.0, random_state=42)

    merged = optimize_dtypes(merged)
    merged.to_parquet(OUT_PARQUET, index=False)
    print(f"\n💾 Saved: {OUT_PARQUET}")
    print(f"📊 Total rows: {len(merged):,}")

    # === Отчёт ==============================================================
    report = pd.DataFrame(stats, columns=["dataset", "rows"])
    report.to_csv(OUT_REPORT, index=False)
    print(f"🧾 Merge report saved to: {OUT_REPORT}")


# === MAIN ===================================================================
def main():
    process()


if __name__ == "__main__":
    main()
