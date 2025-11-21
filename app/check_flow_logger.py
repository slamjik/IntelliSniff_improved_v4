from traffic_analyzer.flow_logger import save_flow, get_recent_flows
import time

# 1. Создаём тестовый поток
flow = {
    "ts": int(time.time() * 1000),
    "iface": "eth0",
    "src": "10.0.0.1",
    "dst": "8.8.8.8",
    "sport": 12345,
    "dport": 53,
    "proto": "UDP",
    "packets": 5,
    "bytes": 300,
    "label": "attack",
    "label_name": "TEST_ATTACK",
    "score": 0.77,
    "summary": {"test": True},
}

print("Saving flow...")
flow_id = save_flow(flow)
print("Saved flow ID:", flow_id)

print("\nLast flows:")
flows = get_recent_flows(5)
for f in flows:
    print(f)
