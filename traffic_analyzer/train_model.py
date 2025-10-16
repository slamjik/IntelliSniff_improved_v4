
import os, sys, time, joblib, logging
import pandas as pd, numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
os.makedirs(DATA_DIR, exist_ok=True)
log = logging.getLogger("ta.train_model")

def load_csvs(files):
    dfs = []
    for f in files:
        dfs.append(pd.read_csv(f))
    if not dfs:
        return None
    return pd.concat(dfs, ignore_index=True)

def train_and_save(csv_files=None, demo=False, out_path=MODEL_PATH):
    if demo or not csv_files:
        from .dataset_preprocessor import process_all, BASE
        merged = process_all(dataset_dir=BASE)
        if merged is None:
            # fallback to synthetic demo
            print("[INFO] No datasets found, using synthetic demo dataset")
            X, y = generate_demo_dataset(2000)
        else:
            df = pd.read_csv(merged)
            if 'label' not in df.columns:
                raise ValueError("Merged dataset missing 'label' column")
            y = df['label']
            X = df.drop(columns=['label'])
    else:
        df = load_csvs(csv_files)
        if 'label' not in df.columns:
            raise ValueError("CSV files must contain 'label' column for supervised training.")
        y = df['label']
        X = df.drop(columns=['label'])

    # basic numeric fill and conversion
    X = X.fillna(0)
    X = X.select_dtypes(include=[float, int, 'int64', 'float64']).astype(float)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y if len(set(y))>1 else None)
    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print("[TRAIN REPORT]")
    print(classification_report(y_test, y_pred))
    # save model and metadata
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    joblib.dump({'model': clf, 'columns': list(X.columns), 'trained_at': time.time()}, out_path)
    print(f"[OK] Model saved to {out_path}")
    return out_path

# simple synthetic demo generator (copied from earlier)
def generate_demo_dataset(n=1000, random_state=42):
    rng = np.random.RandomState(random_state)
    duration = rng.exponential(scale=1.0, size=n)
    packets = rng.poisson(lam=5, size=n)
    bytes_ = packets * (rng.uniform(40, 1500, size=n))
    sport = rng.randint(1024, 65535, size=n)
    dport = rng.choice([80, 443, 53, 22, 123, 8080, 3306], size=n, p=[0.25,0.25,0.1,0.05,0.05,0.15,0.15])
    proto = rng.choice([6,17], size=n, p=[0.7,0.3])
    score = (packets * duration * (bytes_/1000.0)) + (proto==17)*5
    y = (score > np.percentile(score, 70)).astype(int)
    X = pd.DataFrame({
        'duration': duration,
        'packets': packets,
        'bytes': bytes_,
        'sport': sport,
        'dport': dport,
        'proto': proto
    })
    return X, pd.Series(y, name='label')

def retrain_if_needed(merged_dataset_path=None, force=False):
    """Retrain model if merged dataset is newer than existing model, or if force=True."""
    if merged_dataset_path is None:
        merged_dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'merged_dataset.csv')
    if not os.path.exists(merged_dataset_path):
        print("Merged dataset not found:", merged_dataset_path)
        return None
    if not os.path.exists(MODEL_PATH) or force:
        print("Training new model because model not present or force=True")
        return train_and_save(csv_files=[merged_dataset_path])
    # compare mtimes
    model_mtime = os.path.getmtime(MODEL_PATH)
    data_mtime = os.path.getmtime(merged_dataset_path)
    if data_mtime > model_mtime:
        print("Merged dataset is newer than existing model — retraining...")
        return train_and_save(csv_files=[merged_dataset_path])
    print("No retraining needed. Model is up-to-date.")
    return MODEL_PATH

if __name__ == "__main__":
    # CLI: if args provided, treat them as CSV files; else try to process datasets and train
    if len(sys.argv) > 1:
        files = sys.argv[1:]
        train_and_save(csv_files=files)
    else:
        train_and_save(demo=True)
