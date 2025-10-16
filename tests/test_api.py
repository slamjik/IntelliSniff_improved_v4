
from fastapi.testclient import TestClient
from traffic_analyzer.api import app

def test_health():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
