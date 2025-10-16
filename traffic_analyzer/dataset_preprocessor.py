"""
Dataset preprocessor for CICIDS2017, CICIDS2018 and ISCX VPN datasets.
Automatically detects .csv and .parquet files inside ./datasets/.
Run: python -m traffic_analyzer.dataset_preprocessor
Output: datasets/merged_dataset.csv
"""
import os, glob, pandas as pd, numpy as np, logging, pathlib

log = logging.getLogger("ta.dataset_preprocessor")

BASE = os.path.join(os.path.dirname(__file__), '..', 'datasets')
OUT = os.path.join(BASE, 'merged_dataset.csv')
os.makedirs(BASE, exist_ok=True)

def infer_and_map(df):
    cols = {c.lower(): c for c in df.columns}
    duration = None
    for key in ['flow duration', 'duration(ms)', 'duration']:
        if key in cols:
            duration = df[cols[key]].astype(float) / 1000.0 if 'ms' in key else df[cols[key]].astype(float)
            break
    if duration is None:
        duration = pd.Series(np.maximum(1e-6, np.zeros(len(df))), index=df.index)

    packets = None
    for k in [('total fwd packets','total backward packets'), ('total packets',''), ('fwd pkt len mean','')]:
        if k[0] in cols:
            if k[1] and k[1] in cols:
                packets = df[cols[k[0]]].fillna(0).astype(float) + df[cols[k[1]]].fillna(0).astype(float)
            else:
                packets = df[cols[k[0]]].fillna(0).astype(float)
            break
    if packets is None:
        packets = pd.Series(np.ones(len(df)), index=df.index)

    bytes_ = None
    for key in ['total fwd bytes','total backw bytes','total length of fwd packets','total length of bwd packets','total length']:
        if key in cols:
            bytes_ = df[cols[key]].fillna(0).astype(float)
            break
    if bytes_ is None:
        b = 0; found = False
        for k in ['total fwd bytes','total backw bytes']:
            if k in cols:
                b += df[cols[k]].fillna(0).astype(float)
                found = True
        if found: bytes_ = b
    if bytes_ is None:
        bytes_ = packets * 100.0

    sport = None; dport = None
    for key in ['source port','src port','sport','srcport']:
        if key in cols:
            sport = df[cols[key]].fillna(0).astype(int)
            break
    for key in ['destination port','dst port','dport','dstport']:
        if key in cols:
            dport = df[cols[key]].fillna(0).astype(int)
            break
    if sport is None: sport = pd.Series(np.zeros(len(df)), index=df.index).astype(int)
    if dport is None: dport = pd.Series(np.zeros(len(df)), index=df.index).astype(int)

    proto = None
    for key in ['protocol','proto']:
        if key in cols:
            proto = df[cols[key]].fillna(0)
            proto = proto.apply(lambda x: 6 if str(x).lower().startswith('tcp') else (17 if str(x).lower().startswith('udp') else (int(x) if str(x).isdigit() else 0)))
            break
    if proto is None:
        proto = pd.Series(np.zeros(len(df)), index=df.index).astype(int)

    label = None
    for key in ['label','classification','attack','traffic type']:
        if key in cols:
            label = df[cols[key]].astype(str).str.lower()
            break
    if label is None:
        label = pd.Series(['benign'] * len(df), index=df.index)

    label_bin = label.apply(lambda x: 0 if any(tok in str(x) for tok in ['benign','normal','background','legitimate','good','non']) else 1)

    return pd.DataFrame({
        'duration': duration,
        'packets': packets,
        'bytes': bytes_,
        'sport': sport,
        'dport': dport,
        'proto': proto,
        'label': label_bin
    })

def process_all(dataset_dir=BASE, out_path=OUT, max_rows_per_file=None):
    # remove old merged dataset to avoid duplicates
    if os.path.exists(out_path):
        os.remove(out_path)
        print(f"🧹 Удалён старый файл {out_path}")

    files = [str(p) for p in pathlib.Path(dataset_dir).rglob('*') if p.suffix in ['.csv', '.parquet']]
    if not files:
        print("❌ Не найдено файлов .csv или .parquet в", dataset_dir)
        return None

    print(f"🔍 Найдено {len(files)} файлов для объединения\n")

    parts = []
    stats = []
    for f in files:
        try:
            if f.endswith('.parquet'):
                df = pd.read_parquet(f)
            else:
                df = pd.read_csv(f, low_memory=False)
            mapped = infer_and_map(df)
            if max_rows_per_file and len(mapped) > max_rows_per_file:
                mapped = mapped.sample(max_rows_per_file, random_state=42)
            parts.append(mapped)
            stats.append((os.path.basename(f), len(mapped)))
            print(f"✅ {os.path.basename(f)}: {len(mapped)} строк")
        except Exception as e:
            print(f"⚠️ Ошибка при чтении {os.path.basename(f)}: {e}")

    if not parts:
        print("❌ Не удалось обработать ни один файл")
        return None

    merged = pd.concat(parts, ignore_index=True)
    merged = merged.replace([np.inf, -np.inf], np.nan).dropna()

    counts = merged['label'].value_counts()
    if len(counts) == 2:
        maj, minc = counts.idxmax(), counts.idxmin()
        ratio = counts[maj] / max(1, counts[minc])
        if ratio > 10:
            target = int(counts[minc] * 3)
            maj_df = merged[merged['label'] == maj].sample(target, random_state=42)
            min_df = merged[merged['label'] == minc]
            merged = pd.concat([maj_df, min_df], ignore_index=True).sample(frac=1.0, random_state=42)

    merged.to_csv(out_path, index=False)
    print(f"\n💾 Сохранён объединённый датасет: {out_path}")
    print(f"📊 Всего строк: {len(merged)}\n")

    print("📋 Обзор по файлам:")
    for name, count in stats:
        print(f"  {name:<45} {count:>10}")

    return out_path

if __name__ == "__main__":
    process_all()
