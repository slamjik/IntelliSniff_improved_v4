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

### What is new in this iteration?

- Полностью переработанный веб-интерфейс на русском языке: карточки показателей, фильтр по меткам,
  всплывающие подсказки, мгновенный поиск по таблице и удобный экран входа вместо всплывающих `prompt`.
- Живая аналитика: диаграммы по распределению меток, интенсивности трафика и топу направлений
  автоматически обновляются через WebSocket.
- Расширенный REST API (`/health`, `/status`, `/interfaces`, `/flows/recent`) для интеграции, а также
  структурированные ответы с метаданными потоков (скорость, длительность, хосты TLS/DNS/HTTP).
- Улучшенная обработка потоков: исправлена загрузка модели, добавлены расширенные признаки, корректное
  завершение потоков при остановке захвата и более информативные записи в хранилище.

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



## Быстрый старт (русский)
1. Создайте виртуальное окружение и установите зависимости:
```
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows PowerShell
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
2. Запустить обучение демонстрационной модели:
```
python -m traffic_analyzer.train_model
```
3. Запустить API:
```
uvicorn traffic_analyzer.api:app --reload --port 8000
```
4. Перейти в браузере на: `http://127.0.0.1:8000/dashboard` (будет запрошена HTTP Basic авторизация).

По умолчанию логин/пароль: `admin` / `changeme`. **Замените TA_USER и TA_PASS в окружении на безопасные значения перед развёртыванием.**


## Обучение объединённой модели

1. Скачайте CSV-файлы CICIDS2017, CICIDS2018 и ISCX VPN и поместите их в папку `datasets/` в корне проекта (можно вложенные папки).
2. Запустите подготовку данных:
```
python -m traffic_analyzer.dataset_preprocessor
```
3. Обучите модель (она сохранится в `traffic_analyzer/data/model.joblib`):
```
python -m traffic_analyzer.train_model
```
4. Чтобы принудительно переобучить модель, выполните:
```
python -m traffic_analyzer.train_model --force
```
