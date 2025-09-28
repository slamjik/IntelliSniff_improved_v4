# TrafficAnalyzer — full prototype

This is an expanded version of TrafficAnalyzer with more production-oriented features:
- Async packet capture with scapy AsyncSniffer (start/stop reliably)
- Optional NFStream integration (if nfstream is installed) for DPI
- Storage: ClickHouse (optional via CLICKHOUSE_HOST) or SQLite fallback
- FastAPI REST API + WebSocket for live push to dashboard
- Dashboard built with Chart.js
- PDF and CSV report generation (reportlab)
- Dockerfile and docker-compose.yml (includes ClickHouse service)
- Model training and persistence with scikit-learn
- Health checks and graceful shutdown

Quick start (local):
1. Create venv and install requirements:
   python -m venv venv
   source venv/bin/activate   # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
2. Train model:
   python -m traffic_analyzer.train_model
3. Run API:
   uvicorn traffic_analyzer.api:app --reload --port 8000
4. Open dashboard: http://127.0.0.1:8000/dashboard

Notes:
- For live capture on Windows install Npcap and run as admin. On Linux ensure libpcap.
- To enable ClickHouse, run clickhouse and set environment variables (docker-compose provided).


## Security & Auth
Use HTTP Basic auth for protected endpoints. Default credentials: admin / changeme. Set TA_USER and TA_PASS env vars in production.

## NFStream
To enable NFStream DPI install `nfstream` and ensure native nDPI dependencies are available. The application will detect and use NFStream automatically if present.
