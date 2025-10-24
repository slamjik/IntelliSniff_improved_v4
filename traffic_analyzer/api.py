"""Основной REST/WebSocket API для IntelliSniff."""
import asyncio
import csv
import io
import json
import os
import threading
from typing import Optional, Set

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import capture, event_bus, storage
from .ml_runtime import get_auto_updater, get_drift_detector, get_model_manager, get_predictor
from .auth import get_current_username


class StartCaptureRequest(BaseModel):
    iface: Optional[str] = Field(default=None, description="Сетевой интерфейс для захвата")
    bpf: Optional[str] = Field(default=None, description="BPF-фильтр (например, tcp port 80)")
    flow_timeout: float = Field(
        default=30.0,
        ge=1.0,
        le=600.0,
        description="Таймаут сворачивания потоков в секундах",
    )
    use_nfstream: bool = Field(default=False, description="Включить глубокий анализ NFStream")


class TrainRequest(BaseModel):
    demo: bool = Field(default=True, description="Использовать демонстрационный датасет")

class PredictRequest(BaseModel):
    task: str = Field(default='attack', description='ML task (attack/vpn/anomaly)')
    features: dict = Field(default_factory=dict)
    metadata: Optional[dict] = Field(default=None, description='Optional context information')


class SwitchModelRequest(BaseModel):
    task: str = Field(default='attack')
    version: str = Field(..., description='Version identifier from registry.json')


class ValidationRequest(BaseModel):
    task: str = Field(default='attack')
    version: str = Field(..., description='Filename of the candidate model in ml/models')
    dataset: Optional[str] = Field(default=None, description='Optional path to dataset for validation')


class AutoUpdateToggleRequest(BaseModel):
    enabled: bool = Field(default=True)


app = FastAPI(
    title="IntelliSniff — Анализатор трафика",
    description="Веб-интерфейс для мониторинга, анализа и отчётности по сетевым потокам",
)

model_manager = get_model_manager()
predictor = get_predictor()
drift_detector = get_drift_detector()
auto_updater = get_auto_updater()

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "..", "web", "templates")
)
static_dir = os.path.join(os.path.dirname(__file__), "..", "web", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# WebSocket clients set
_ws_clients_lock = threading.Lock()
_ws_clients: Set[WebSocket] = set()


async def _broker_loop():
    q = event_bus.get_queue()
    loop = asyncio.get_event_loop()
    while True:
        # blocking get in threadpool to avoid blocking event loop
        item = await loop.run_in_executor(None, q.get)
        try:
            topic, payload = item
        except Exception:
            continue
        # prepare JSONable payload
        msg = {"topic": topic, "data": payload}
        # broadcast to clients
        to_remove = []
        with _ws_clients_lock:
            clients = list(_ws_clients)
        for ws in clients:
            try:
                await ws.send_json(msg)
            except Exception:
                # mark for removal
                to_remove.append(ws)
        if to_remove:
            with _ws_clients_lock:
                for w in to_remove:
                    if w in _ws_clients:
                        _ws_clients.remove(w)


@app.on_event("startup")
async def startup_event():
    # start broker loop task
    asyncio.create_task(_broker_loop())


@app.get("/health")
def health() -> dict:
    """Простая проверка готовности сервиса."""
    return {"status": "ok"}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard_full.html", {"request": request})


@app.post("/start_capture")
def api_start(req: StartCaptureRequest, user: str = Depends(get_current_username)):
    capture.start_capture(
        iface=req.iface,
        bpf=req.bpf,
        flow_timeout=req.flow_timeout,
        use_nfstream=req.use_nfstream,
    )
    return {"status": "started", "details": capture.get_status()}


@app.post("/stop_capture")
def api_stop(user: str = Depends(get_current_username)):
    capture.stop_capture()
    return {"status": "stopped", "details": capture.get_status()}


@app.post("/train_model")
def api_train(
    background_tasks: BackgroundTasks,
    payload: TrainRequest,
    user: str = Depends(get_current_username),
):
    def _train():
        try:
            from . import train_model

            if payload.demo:
                train_model.train_demo_model()
            else:
                train_model.train_from_dataset()
        except Exception as e:
            print("Training failed:", e)

    background_tasks.add_task(_train)
    return {"status": "training_started", "demo": payload.demo}


@app.get("/status")
def api_status(user: str = Depends(get_current_username)):
    return capture.get_status()

@app.post('/predict')
def api_predict(payload: PredictRequest, user: str = Depends(get_current_username)):
    return predictor.predict(payload.features, task=payload.task, metadata=payload.metadata)


@app.post('/switch_model')
def api_switch_model(payload: SwitchModelRequest, user: str = Depends(get_current_username)):
    info = model_manager.switch_model(payload.task, payload.version)
    return info


@app.get('/get_versions')
def api_get_versions(task: str = Query('attack'), user: str = Depends(get_current_username)):
    return {'task': task, 'versions': model_manager.get_versions(task)}


@app.get('/model_status')
def api_model_status(user: str = Depends(get_current_username)):
    data = {}
    for task in model_manager.list_tasks():
        info = model_manager.get_active_model_info(task)
        data[task] = info.to_dict() if info else None
    return data


@app.get('/drift_status')
def api_drift_status(user: str = Depends(get_current_username)):
    return drift_detector.get_status()


@app.get('/ml/predictions')
def api_ml_predictions(limit: int = Query(50, ge=1, le=500), user: str = Depends(get_current_username)):
    data = predictor.get_buffer()
    return {'items': list(reversed(data[-limit:]))}


@app.post('/trigger_validation')
def api_trigger_validation(payload: ValidationRequest, user: str = Depends(get_current_username)):
    return auto_updater.validate_and_maybe_activate(payload.task, payload.version, payload.dataset)


@app.post('/auto_update_toggle')
def api_toggle_auto_update(payload: AutoUpdateToggleRequest, user: str = Depends(get_current_username)):
    auto_updater.toggle(payload.enabled)
    return {'enabled': auto_updater.enabled}


@app.get('/quality_metrics')
def api_quality_metrics(user: str = Depends(get_current_username)):
    summary = {}
    for task in model_manager.list_tasks():
        versions = model_manager.get_versions(task)
        summary[task] = versions
    return summary


@app.get('/auto_update_status')
def api_auto_update_status(user: str = Depends(get_current_username)):
    return {'enabled': auto_updater.enabled}


@app.get("/interfaces")
def api_interfaces(user: str = Depends(get_current_username)):
    status = capture.get_status()
    return {
        "interfaces": status.get("interfaces", []),
        "nfstream_available": status.get("nfstream_available"),
        "running": status.get("running"),
    }


def _parse_summary(summary_value):
    if isinstance(summary_value, (dict, list)):
        return summary_value
    if not summary_value:
        return {}
    if isinstance(summary_value, str):
        try:
            return json.loads(summary_value)
        except json.JSONDecodeError:
            # попытка распарсить строковое представление dict от Python
            try:
                return json.loads(summary_value.replace("'", '"'))
            except Exception:
                return {"raw": summary_value}
    return {"raw": str(summary_value)}


@app.get("/flows/recent")
def api_recent_flows(
    limit: int = Query(100, ge=1, le=1000),
    user: str = Depends(get_current_username),
):
    rows = storage.recent(limit=limit)
    for row in rows:
        row["summary"] = _parse_summary(row.get("summary"))
        # нормализуем ts в миллисекундах
        if row.get("ts") and row["ts"] < 10_000_000_000:
            row["ts"] = int(row["ts"] * 1000)
    return {"items": rows, "count": len(rows)}


@app.get("/report/csv")
def report_csv(user: str = Depends(get_current_username)):
    rows = storage.recent(limit=500)
    buf = io.StringIO()
    writer = csv.writer(buf)
    if rows:
        writer.writerow(list(rows[0].keys()))
        for r in rows:
            writer.writerow([r.get(k) for k in rows[0].keys()])
    else:
        writer.writerow(
            [
                "ts",
                "iface",
                "src",
                "dst",
                "sport",
                "dport",
                "proto",
                "packets",
                "bytes",
                "label",
                "score",
                "summary",
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ta_report.csv"},
    )


@app.get("/report/pdf")
def report_pdf(user: str = Depends(get_current_username)):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        return JSONResponse({"error": "reportlab not installed"}, status_code=501)
    rows = storage.recent(limit=200)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica", 10)
    y = 750
    c.drawString(50, y + 20, "Traffic Analyzer - recent flows report")
    for r in rows:
        line = (
            f"{r.get('ts')} {r.get('src')}:{r.get('sport')} -> {r.get('dst')}:{r.get('dport')} "
            f"label={r.get('label')} score={r.get('score')}"
        )
        c.drawString(50, y, line[:100])
        y -= 12
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=ta_report.pdf"},
    )


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    with _ws_clients_lock:
        _ws_clients.add(ws)
    try:
        while True:
            # keep connection open; client may send pings
            await ws.receive_text()
    except WebSocketDisconnect:
        with _ws_clients_lock:
            if ws in _ws_clients:
                _ws_clients.remove(ws)
