import json, os
import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import matplotlib.pyplot as plt

class Exporter:
    def export_csv(self, rows, path):
        df = pd.DataFrame(rows)
        df.to_csv(path, index=False)
        return True

    def export_json(self, rows, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        return True

    def export_pdf_summary(self, summary: dict, path: str):
        c = canvas.Canvas(path, pagesize=A4)
        w, h = A4
        y = h - 50
        c.setFont('Helvetica-Bold', 14)
        c.drawString(40, y, 'IntelliSniff — Отчёт')
        y -= 30
        c.setFont('Helvetica', 10)
        for k, v in summary.items():
            c.drawString(40, y, f'{k}: {v}')
            y -= 14
            if y < 80:
                c.showPage()
                y = h - 50
        c.showPage(); c.save()
        return True

    def plot_protocol_pie(self, counts: dict, path_png: str):
        if not counts:
            return False
        labels = list(counts.keys())
        sizes = list(counts.values())
        fig, ax = plt.subplots(figsize=(6,4))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%')
        fig.savefig(path_png, bbox_inches='tight')
        return True
