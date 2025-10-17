import os
from .storage import storage
import csv, time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'reports')
def export_csv(path=None, limit=1000):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = path or os.path.join(OUT_DIR, f'flows_{int(time.time())}.csv')
    rows = storage.recent(limit=limit)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ts','src','dst','proto','packets','bytes','label','label_name','score'])
        for r in rows:
            w.writerow([
                r.get('ts'),
                r.get('src'),
                r.get('dst'),
                r.get('proto'),
                r.get('packets'),
                r.get('bytes'),
                r.get('label'),
                r.get('label_name'),
                r.get('score'),
            ])
    return path

def export_pdf(path=None, limit=500):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = path or os.path.join(OUT_DIR, f'flows_{int(time.time())}.pdf')
    rows = storage.recent(limit=limit)
    c = canvas.Canvas(path, pagesize=letter)
    w, h = letter
    y = h - 40
    c.setFont('Helvetica-Bold', 14)
    c.drawString(40, y, 'Traffic Analyzer - Flows Report')
    y -= 30
    c.setFont('Helvetica', 10)
    for r in rows:
        line = (
            f"{r.get('ts')} {r.get('src')}->{r.get('dst')} proto={r.get('proto')} "
            f"pkts={r.get('packets')} bytes={r.get('bytes')} "
            f"label={r.get('label_name') or r.get('label')}"
        )
        c.drawString(40, y, line[:120])
        y -= 12
        if y < 40:
            c.showPage()
            y = h - 40
    c.save()
    return path
