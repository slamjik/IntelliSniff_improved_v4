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


app = FastAPI(
    title="IntelliSniff — Анализатор трафика",
    description="Веб-интерфейс для мониторинга, анализа и отчётности по сетевым потокам",
)


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

            train_model.train_and_save(demo=payload.demo)
        except Exception as e:
            print("Training failed:", e)

    background_tasks.add_task(_train)
    return {"status": "training_started", "demo": payload.demo}


@app.get("/status")
def api_status(user: str = Depends(get_current_username)):
    return capture.get_status()


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
