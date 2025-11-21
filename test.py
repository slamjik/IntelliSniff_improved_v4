import base64
from fastapi.testclient import TestClient

# Импортируем API приложение
from traffic_analyzer.api import app

client = TestClient(app)

# --- Basic auth ---
username = "admin"
password = "changeme"

token = base64.b64encode(f"{username}:{password}".encode()).decode()
HEADERS = {
    "Authorization": f"Basic {token}"
}

def test_versions():
    print("=== TEST /get_versions ===")
    r = client.get("/get_versions?task=attack", headers=HEADERS)
    print(r.status_code)
    print(r.text)

def test_model_status():
    print("\n=== TEST /model_status ===")
    r = client.get("/model_status", headers=HEADERS)
    print(r.status_code)
    print(r.text)

def run_all():
    test_versions()
    test_model_status()

if __name__ == "__main__":
    run_all()
