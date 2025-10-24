"""Model validation helpers for IntelliSniff."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

@dataclass
class ValidationReport:
    task: str
    model_path: str
    metrics: Dict[str, float]
    evaluated_at: float
    dataset: Optional[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "task": self.task,
            "model_path": self.model_path,
            "metrics": self.metrics,
            "evaluated_at": self.evaluated_at,
            "dataset": self.dataset,
        }


def _load_dataset(dataset_path: Path, label_column: Optional[str] = None) -> tuple[pd.DataFrame, pd.Series]:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    if dataset_path.suffix.lower() in {".parquet", ".pq"}:
        df = pd.read_parquet(dataset_path)
    else:
        df = pd.read_csv(dataset_path)
    if label_column and label_column in df.columns:
        label_col = label_column
    else:
        for candidate in ("label", "target", "y", "class"):
            if candidate in df.columns:
                label_col = candidate
                break
        else:
            raise ValueError("Dataset must contain a label/target column")
    y = df[label_col]
    X = df.drop(columns=[label_col])
    return X, y


def evaluate_model(model_path: str, dataset_path: str, task: str, label_column: Optional[str] = None) -> ValidationReport:
    model_file = Path(model_path)
    dataset_file = Path(dataset_path)
    model_obj = joblib.load(model_file)

    model = model_obj.get("model") if isinstance(model_obj, dict) else model_obj
    feature_names = None
    for key in ("features", "feature_names", "columns"):
        if isinstance(model_obj, dict) and key in model_obj:
            feature_names = list(model_obj[key])
            break
    X, y = _load_dataset(dataset_file, label_column)

    if feature_names:
        X_eval = X[feature_names]
    else:
        X_eval = X.select_dtypes(include=[float, int])
    preds = model.predict(X_eval)
    metrics = {
        "precision": float(precision_score(y, preds, average="weighted", zero_division=0)),
        "recall": float(recall_score(y, preds, average="weighted", zero_division=0)),
        "f1": float(f1_score(y, preds, average="weighted", zero_division=0)),
        "accuracy": float(accuracy_score(y, preds)),
    }
    # Drift-resilience proxy: variation of predictions on shuffled data
    shuffled = X_eval.sample(frac=1.0, random_state=42)
    shuffled_preds = model.predict(shuffled)
    drift_resilience = 1.0 - float(np.mean(preds != shuffled_preds))
    metrics["drift_resilience"] = drift_resilience
    return ValidationReport(
        task=task,
        model_path=str(model_file),
        metrics=metrics,
        evaluated_at=time.time(),
        dataset=str(dataset_file),
    )


def compare_models(current: Mapping[str, float], candidate: Mapping[str, float],
                   min_improvement: float = 0.01) -> bool:
    """Return True if candidate metrics are good enough to replace current."""
    if not current:
        return True
    current_f1 = float(current.get("f1", 0.0))
    candidate_f1 = float(candidate.get("f1", 0.0))
    if candidate_f1 >= current_f1 + min_improvement:
        return True
    if candidate_f1 >= current_f1 and candidate.get("drift_resilience", 0.0) >= current.get("drift_resilience", 0.0):
        return True
    # allow small degradation if other metrics improved significantly
    improvements = 0
    degradations = 0
    for key in ("precision", "recall", "drift_resilience"):
        cand = float(candidate.get(key, 0.0))
        cur = float(current.get(key, 0.0))
        if cand >= cur + min_improvement:
            improvements += 1
        elif cand + min_improvement < cur:
            degradations += 1
    if degradations == 0 and improvements:
        return True
    return False


def save_report(report: ValidationReport, metrics_path: str) -> None:
    metrics_file = Path(metrics_path)
    if metrics_file.exists():
        data = json.loads(metrics_file.read_text(encoding="utf-8"))
    else:
        data = {}
    task_section = data.setdefault(report.task, {})
    task_section[Path(report.model_path).name] = {
        **report.metrics,
        "evaluated_at": report.evaluated_at,
        "dataset": report.dataset,
    }
    metrics_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
