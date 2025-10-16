# IntelliSniff / TrafficAnalyzer – обзор кода

## Общая картина
Проект реализует полноценный прототип системы анализа сетевого трафика: FastAPI-бекенд, веб-панель на Chart.js, хранение в SQLite и заготовки для обучения модели. Архитектура разделена по слоям (сбор, потоковая обработка, классификация, отчёты), что облегчает расширение.

## Сильные стороны
- Асинхронный цикл брокера и WebSocket-поток позволяют строить живой дашборд без опроса. 【F:traffic_analyzer/api.py†L23-L55】
- Поддержка NFStream оформлена как опциональный модуль с graceful fallback на Scapy. 【F:traffic_analyzer/capture.py†L57-L110】
- Предобработчик датасетов умеет автоматически находить и унифицировать CSV/Parquet-файлы, балансирует классы и логирует прогресс. 【F:traffic_analyzer/dataset_preprocessor.py†L15-L111】

## Критические замечания
1. **Отсутствует эндпоинт `/health`**. Юнит-тесты и, вероятно, внешние проверки ожидают его наличие, но в `traffic_analyzer.api` роут не объявлен, из-за чего тесты `tests/test_api.py` и `tests/test_api_health.py` гарантированно падают. 【F:traffic_analyzer/api.py†L12-L118】【F:tests/test_api.py†L5-L9】【F:tests/test_api_health.py†L4-L8】
2. **Классификация потоков ломается на числовых протоколах.** В `streaming.handle_packet` значение `proto` берётся из словаря пакета и без проверок вызывается `.upper()`. Scapy отдаёт `int`, поэтому возникает `AttributeError`, поток не попадает в модель и дашборд. 【F:traffic_analyzer/streaming.py†L65-L92】【F:traffic_analyzer/capture.py†L28-L55】
3. **Натренированная модель не используется.** `train_model` сохраняет артефакт в `traffic_analyzer/data/model.joblib`, а `classification.load_model` ищет файл в `data/model.joblib` (на уровень выше). В рабочей среде загрузка всегда провалится, и система обучит демо-модель вместо реальной. 【F:traffic_analyzer/train_model.py†L7-L54】【F:traffic_analyzer/classification.py†L8-L74】
4. **Фичи модели не согласованы.** Продакшн-тренер использует признаки `duration/packets/bytes/sport/dport/proto`, а рантайм-классификатор ожидает набор `duration/packets/bytes/pkts_per_s/bytes_per_s/avg_pkt_size`. Даже если путь исправить, такой артефакт выдаст некорректные предсказания. 【F:traffic_analyzer/train_model.py†L41-L74】【F:traffic_analyzer/classification.py†L12-L119】

## Важные замечания
- `capture.start_capture` принимает `flow_timeout`, но никогда не передаёт его в `init_streaming`, поэтому настройка не работает. 【F:traffic_analyzer/capture.py†L88-L131】【F:traffic_analyzer/streaming.py†L41-L63】
- Модуль отчётов работает с `csv.writer`/`canvas`, предполагая, что `storage.recent` возвращает последовательности, но фактически получает словари; в итоге в CSV попадут только имена колонок, а PDF вызовет `KeyError`. Стоит перейти на `DictWriter`/итерировать по ключам. 【F:traffic_analyzer/reports.py†L1-L34】【F:traffic_analyzer/storage.py†L1-L49】
- CLI-команда `train_model` в `traffic_analyzer.cli` вызывает несуществующий `main`, поэтому запустить обучение через CLI нельзя. 【F:traffic_analyzer/cli.py†L1-L18】【F:traffic_analyzer/train_model.py†L96-L102】
- Веб-клиент хранит Basic-токен в памяти браузера и собирает его через `prompt` при каждом обновлении. Для публичного развёртывания стоит заменить на форму входа с TLS и `localStorage`/`sessionStorage`. 【F:web/templates/dashboard_full.html†L18-L108】

## Рекомендации по развитию
1. Добавить `/health` с проверками зависимостей (модель, подключение к БД, поток брокера) и покрыть тестом на happy-path и failure.
2. Нормализовать поле протокола (`str(proto).upper()`), а также логировать исходный пакет при ошибке, чтобы проще было отлаживать NFStream/Scapy кейсы.
3. Выбрать единую схему признаков: либо дообучить модель на расширенных фичах (добавив расчёт в `Flow.features`/`extract_features_from_flow`), либо оставить только базовые и обновить `FEATURE_NAMES`.
4. Привести пути модели к одному каталогу (например, `traffic_analyzer/data/`) и добавить smoke-тест на загрузку.
5. Исправить экспорт отчётов: пользоваться `csv.DictWriter`, приводить числовые значения и корректно форматировать строки для PDF.
6. Расширить CLI, чтобы команды `start_capture`/`stop_capture` корректно завершали поток и возвращали exit-code, а `train_model` принимала пути к датасетам.

