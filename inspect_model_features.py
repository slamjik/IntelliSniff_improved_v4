from pathlib import Path
import joblib
from pprint import pprint

bundle_path = Path("data/model.joblib")
bundle = joblib.load(bundle_path)

print("=== TOP-LEVEL KEYS ===")
print(bundle.keys())

features = bundle.get("features")
print("\n=== FEATURES ===")
pprint(features)
print("\nКоличество фичей:", len(features) if features is not None else "None")
