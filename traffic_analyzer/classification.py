import os, joblib, numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import Dict
DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
MODEL_PATH = os.path.join(DATA_DIR, 'model.joblib')

def train_demo_model(path=MODEL_PATH):
    rng = np.random.RandomState(42)
    X = []
    y = []
    for i in range(300):
        X.append([rng.normal(1.0,0.3), rng.normal(40,12), rng.normal(1500,400)]); y.append(0) # web
    for i in range(300):
        X.append([rng.normal(5.0,1.2), rng.normal(220,60), rng.normal(25000,5000)]); y.append(1) # vpn
    for i in range(300):
        X.append([rng.normal(0.4,0.08), rng.normal(8,3), rng.normal(400,80)]); y.append(2) # voip
    X = np.array(X); y = np.array(y)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X,y)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(clf, path)
    return path

def load_model(path=MODEL_PATH):
    if os.path.exists(path):
        return joblib.load(path)
    return None

def predict_from_features(features: Dict, model):
    v = [features.get('duration',0.0), features.get('packets',0), features.get('bytes',0)]
    if model is None:
        return {'label':'unknown','score':0.0}
    lab = int(model.predict([v])[0])
    proba = float(model.predict_proba([v])[0].max())
    labels = {0:'web',1:'vpn',2:'voip'}
    return {'label':labels.get(lab,'unknown'),'score':proba}
