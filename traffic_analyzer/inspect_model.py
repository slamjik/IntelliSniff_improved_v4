# tools/inspect_model.py
import joblib
import sys
from pathlib import Path
from pprint import pprint

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("C:/Users/Olega/PycharmProjects/IntelliSniff_improved_v4/datasets/model.joblib")
print("Loading:", path)
obj = joblib.load(path)

print("TYPE:", type(obj))
# Частые варианты: sklearn Pipeline, estimator (Classifier), dict containing {'model':..., 'features': [...]}
if isinstance(obj, dict):
    print("Keys in joblib dict:")
    pprint(list(obj.keys()))
    if "model" in obj:
        clf = obj["model"]
        print("Inner model type:", type(clf))
    else:
        clf = next((v for v in obj.values() if hasattr(v, "predict")), None)
    if "features" in obj:
        print("Declared features (len={}):".format(len(obj["features"])))
        pprint(obj["features"][:200])
else:
    clf = obj

# Try to print feature names known to sklearn models/pipelines
try:
    if hasattr(clf, "feature_names_in_"):
        print("feature_names_in_ (len={}):".format(len(clf.feature_names_in_)))
        pprint(list(clf.feature_names_in_)[:200])
    if hasattr(clf, "named_steps"):
        print("Pipeline steps:", list(clf.named_steps.keys()))
    if hasattr(clf, "get_params"):
        print("Model params keys snippet:", list(clf.get_params().keys())[:40])
except Exception as e:
    print("Ошибка при извлечении метаданных модели:", e)
