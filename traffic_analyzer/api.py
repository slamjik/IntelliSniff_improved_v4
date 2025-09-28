import os, logging, tempfile, time, asyncio
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse, FileResponse
import uvicorn
from . import capture, streaming, storage, reports, classification, event_bus, auth
from .storage import storage as storage_instance
log = logging.getLogger('ta.api')
app = FastAPI(title='Traffic Analyzer full prototype')
clients = set()

async def event_consumer_task():
    loop = asyncio.get_event_loop()
    q = event_bus.get_queue()
    while True:
        # blocking get in threadpool to not block the event loop
        event = await loop.run_in_executor(None, q.get)
        # dispatch to clients
        to_remove = []
        for ws in list(clients):
            try:
                await ws.send_json(event)
            except Exception:
                to_remove.append(ws)
        for ws in to_remove:
            clients.discard(ws)

@app.on_event('startup')
async def startup():
    logging.basicConfig(level=logging.INFO)
    streaming.init_streaming()
    # start background consumer
    asyncio.create_task(event_consumer_task())
    log.info('API startup complete (event consumer started)')

@app.get('/health')
async def health():
    return {'status':'ok', 'model_loaded': streaming._model is not None}

@app.post('/start_capture')
async def start_capture(iface: str = None, user: str = Depends(auth.get_current_username)):
    capture.start_capture(iface=iface)
    return {'result':'started'}

@app.post('/stop_capture')
async def stop_capture(user: str = Depends(auth.get_current_username)):
    capture.stop_capture()
    return {'result':'stop_requested'}

@app.get('/stats')
async def stats(limit: int = 100):
    rows = storage_instance.recent(limit=limit)
    return {'rows': rows}

@app.post('/upload_pcap')
async def upload_pcap(file: UploadFile = File(...), background_tasks: BackgroundTasks = None, user: str = Depends(auth.get_current_username)):
    tmp = os.path.join(tempfile.gettempdir(), file.filename)
    with open(tmp, 'wb') as f:
        f.write(await file.read())
    from pcap_import.import_pcap import import_and_process
    if background_tasks:
        background_tasks.add_task(import_and_process, tmp)
        return {'result':'accepted'}
    else:
        import_and_process(tmp)
        return {'result':'processed'}

@app.post('/train_model')
async def train_model(user: str = Depends(auth.get_current_username)):
    p = classification.train_demo_model()
    # reload model
    streaming.init_streaming()
    return {'result':'trained', 'path': p}

@app.get('/report/csv')
async def report_csv(user: str = Depends(auth.get_current_username)):
    p = reports.export_csv(limit=1000)
    return FileResponse(p, filename=os.path.basename(p))

@app.get('/report/pdf')
async def report_pdf(user: str = Depends(auth.get_current_username)):
    p = reports.export_pdf(limit=500)
    return FileResponse(p, filename=os.path.basename(p))

@app.get('/dashboard', response_class=HTMLResponse)
async def dashboard(user: str = Depends(auth.get_current_username)):
    html = open(os.path.join(os.path.dirname(__file__),'..','web','templates','dashboard_full.html'),'r',encoding='utf-8').read()
    return HTMLResponse(content=html)

@app.websocket('/ws/live')
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            data = await ws.receive_text()
            # echo behavior or simple ping
            await ws.send_text('pong:' + data)
    except WebSocketDisconnect:
        clients.remove(ws)

if __name__ == '__main__':
    uvicorn.run('traffic_analyzer.api:app', host='0.0.0.0', port=8000, reload=True)
