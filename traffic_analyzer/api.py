
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import io, csv, os, time, threading, asyncio
from typing import Set

from . import capture, streaming, storage, event_bus
from .auth import get_current_username

app = FastAPI(title="Traffic Analyzer")

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), '..', 'web', 'templates'))
static_dir = os.path.join(os.path.dirname(__file__), '..', 'web', 'static')
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

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(get_current_username)):
    return templates.TemplateResponse("dashboard_full.html", {"request": request})

@app.post("/start_capture")
def api_start(iface: str = None, bpf: str = None, flow_timeout: float = 30.0, use_nfstream: bool = False, user: str = Depends(get_current_username)):
    capture.start_capture(iface=iface, bpf=bpf, flow_timeout=flow_timeout, use_nfstream=use_nfstream)
    return {"status": "started", "iface": iface, "bpf": bpf, "use_nfstream": use_nfstream}

@app.post("/stop_capture")
def api_stop(user: str = Depends(get_current_username)):
    capture.stop_capture()
    return {"status": "stopped"}

@app.post("/train_model")
def api_train(background_tasks: BackgroundTasks, demo: bool = True, user: str = Depends(get_current_username)):
    def _train():
        try:
            from . import train_model
            train_model.train_and_save(demo=demo)
        except Exception as e:
            print("Training failed:", e)
    background_tasks.add_task(_train)
    return {"status":"training_started", "demo": demo}

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
        writer.writerow(['ts','iface','src','dst','sport','dport','proto','packets','bytes','label','score','summary'])
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv", headers={"Content-Disposition":"attachment; filename=ta_report.csv"})

@app.get("/report/pdf")
def report_pdf(user: str = Depends(get_current_username)):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        return JSONResponse({"error":"reportlab not installed"}, status_code=501)
    rows = storage.recent(limit=200)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica", 10)
    y = 750
    c.drawString(50, y+20, "Traffic Analyzer - recent flows report")
    for r in rows:
        line = f"{r.get('ts')} {r.get('src')}:{r.get('sport')} -> {r.get('dst')}:{r.get('dport')} label={r.get('label')} score={r.get('score')}"
        c.drawString(50, y, line[:100])
        y -= 12
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    buf.seek(0)
    return StreamingResponse(buf, media_type="application/pdf", headers={"Content-Disposition":"attachment; filename=ta_report.pdf"})

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
