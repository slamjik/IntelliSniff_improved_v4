import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel, QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QSplitter, QFileDialog, QMessageBox, QCheckBox, QTableView, QGroupBox

# --- Applied minimalist stylesheet loader (auto-added) ---
def apply_minimal_style(app):
    try:
        here = os.path.dirname(__file__)
        qss_path = os.path.join(here, "style.qss")
        if os.path.exists(qss_path):
            with open(qss_path, "r", encoding="utf-8") as f:
                app.setStyleSheet(f.read())
    except Exception:
        pass
# -------------------------------------------------------
from PySide6.QtCore import Qt, QTimer
from .models import PacketTableModel
from time import strftime, localtime
import os
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel, QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QSplitter, QFileDialog, QMessageBox, QCheckBox, QTableView, QGroupBox, QAbstractItemView


try:
    # matplotlib Qt backend for embedding
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    import matplotlib.pyplot as plt
    HAS_MPL = True
except Exception:
    HAS_MPL = False

class StatsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        if HAS_MPL:
            self.fig, self.ax = plt.subplots(figsize=(4,3))
            self.canvas = FigureCanvas(self.fig)
            self.layout.addWidget(self.canvas)
        else:
            self.layout.addWidget(QLabel('matplotlib не установлен — статистика недоступна'))

    def plot_proto_counts(self, counts):
        if not HAS_MPL:
            return
        self.ax.clear()
        labels = list(counts.keys())
        sizes = list(counts.values())
        if not sizes:
            self.ax.text(0.5, 0.5, 'Нет данных', ha='center')
        else:
            self.ax.pie(sizes, labels=labels, autopct='%1.1f%%')
        self.canvas.draw()

class IntelliSniffApp:
    def __init__(self, capture, classifier, detections, exporter):
        self.capture = capture
        self.classifier = classifier
        self.detections = detections
        self.exporter = exporter
        self.qtapp = QApplication(sys.argv)
        try:
            apply_minimal_style(self.qtapp)
        except Exception:
            pass

        # dark theme (basic)
        self.qtapp.setStyleSheet("""
        QWidget { background: #121212; color: #e0e0e0; font-family: Segoe UI, Arial; }
        QLineEdit, QTextEdit, QTableView { background: #1e1e1e; color: #e0e0e0; }
        QPushButton { background: #2d2d2d; border: 1px solid #3a3a3a; padding: 6px; }
        QPushButton:hover { background: #3a3a3a; }
        QLabel { color: #d0d0d0 }
        """)

        self.window = QMainWindow()
        self.window.setWindowTitle('IntelliSniff — Интеллектуальный анализатор трафика')
        self.window.resize(1400, 900)
        self._build_ui()

        self.timer = QTimer()
        self.timer.setInterval(150)
        self.timer.timeout.connect(self._drain)
        self.timer.start()
        self._max_rows = 300000

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)

        # controls
        ctrl = QHBoxLayout()
        self.if_list = QListWidget()
        self.if_list.setSelectionMode(QAbstractItemView.MultiSelection)
        try:
            for i in self.capture.list_ifaces():
                it = QListWidgetItem(i); it.setCheckState(Qt.Unchecked); self.if_list.addItem(it)
        except Exception:
            pass
        ctrl.addWidget(QLabel('Интерфейсы:'))
        ctrl.addWidget(self.if_list)
        self.bpf = QLineEdit(); self.bpf.setPlaceholderText('BPF фильтр (опционально)')
        ctrl.addWidget(self.bpf)
        self.chk_write = QCheckBox('Записывать PCAP')
        ctrl.addWidget(self.chk_write)
        btn_pcap = QPushButton('Выбрать PCAP...'); btn_pcap.clicked.connect(self._choose_pcap)
        ctrl.addWidget(btn_pcap)
        self.chk_pyshark = QCheckBox('Использовать pyshark (если доступен)')
        ctrl.addWidget(self.chk_pyshark)
        btn_start = QPushButton('Запустить'); btn_start.clicked.connect(self._start_capture)
        ctrl.addWidget(btn_start)
        btn_stop = QPushButton('Остановить'); btn_stop.clicked.connect(self._stop_capture)
        ctrl.addWidget(btn_stop)
        root.addLayout(ctrl)

        # main area split
        main_split = QSplitter(Qt.Horizontal)
        left = QWidget(); left_l = QVBoxLayout(left)
        self.table_model = PacketTableModel()
        self.table = QTableView(); self.table.setModel(self.table_model)
        left_l.addWidget(self.table)
        main_split.addWidget(left)

        right = QWidget(); right_l = QVBoxLayout(right)
        # details box
        box = QGroupBox('Детали пакета')
        box_layout = QVBoxLayout(box)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        box_layout.addWidget(self.detail)
        right_l.addWidget(box)
        # stats widget
        self.stats = StatsWidget()
        right_l.addWidget(self.stats)
        main_split.addWidget(right)

        root.addWidget(main_split)

        # bottom toolbar
        bottom = QHBoxLayout()
        btn_csv = QPushButton('Экспорт CSV'); btn_csv.clicked.connect(self._export_csv)
        btn_json = QPushButton('Экспорт JSON'); btn_json.clicked.connect(self._export_json)
        btn_pdf = QPushButton('Экспорт PDF (сводка)'); btn_pdf.clicked.connect(self._export_pdf)
        bottom.addWidget(btn_csv); bottom.addWidget(btn_json); bottom.addWidget(btn_pdf)
        self.lbl_status = QLabel('Статус: Готов')
        bottom.addStretch(1); bottom.addWidget(self.lbl_status)
        root.addLayout(bottom)

        self.window.setCentralWidget(central)

    def _choose_pcap(self):
        fname, _ = QFileDialog.getSaveFileName(self.window, 'Сохранить PCAP', 'capture.pcap', 'PCAP Files (*.pcap)')
        if fname:
            self._pcap_path = fname
            self.lbl_status.setText(f'PCAP: {fname}')

    def _selected_ifaces(self):
        out = []
        for i in range(self.if_list.count()):
            it = self.if_list.item(i)
            if it.checkState() == Qt.Checked:
                out.append(it.text())
        return out

    def _start_capture(self):
        ifaces = self._selected_ifaces() or None
        pcap = getattr(self, '_pcap_path', None) if self.chk_write.isChecked() else None
        bpf = self.bpf.text().strip() or None
        use_pyshark = self.chk_pyshark.isChecked()
        try:
            self.capture.start(ifaces, write_pcap=pcap, bpf=bpf, use_pyshark=use_pyshark)
            self.lbl_status.setText('Статус: Захват запущен')
        except PermissionError:
            QMessageBox.critical(self.window, 'Ошибка', 'Нет прав для захвата. Запустите от имени администратора и установите Npcap.')
        except Exception as e:
            QMessageBox.critical(self.window, 'Ошибка', str(e))

    def _stop_capture(self):
        self.capture.stop()
        self.lbl_status.setText('Статус: Остановлен')

    def _drain(self):
        cnt = 0
        proto_counts = {}
        while True:
            pv = self.capture.pull_packet()
            if pv is None:
                break
            cnt += 1
            self.table_model.append([strftime('%H:%M:%S', localtime(pv.ts)), pv.iface, pv.src, pv.dst, pv.proto, pv.sport, pv.dport, pv.length, pv.classification, pv.summary])
            try:
                self.detections.feed(pv)
            except Exception:
                pass
            proto_counts[pv.proto] = proto_counts.get(pv.proto, 0) + 1
            if self.table_model.rowCount() > self._max_rows:
                self.table_model.trim_front(1000)
            try:
                if pv.scapy_pkt is not None:
                    self.detail.setPlainText(pv.scapy_pkt.show(dump=True))
                else:
                    self.detail.setPlainText(pv.summary or '')
            except Exception:
                self.detail.setPlainText(pv.summary or '')

        alerts = self.detections.pull()
        if alerts:
            self.lbl_status.setText(' | '.join(alerts[-2:]))
        if cnt:
            self.table.scrollToBottom()
            # update stats
            self.stats.plot_proto_counts(proto_counts)

    def _export_csv(self):
        fname, _ = QFileDialog.getSaveFileName(self.window, 'Экспорт CSV', 'report.csv', 'CSV Files (*.csv)')
        if not fname: return
        rows = self.table_model.as_dicts()
        ok = self.exporter.export_csv(rows, fname)
        QMessageBox.information(self.window, 'Экспорт', 'CSV сохранён' if ok else 'Ошибка при экспорте')

    def _export_json(self):
        fname, _ = QFileDialog.getSaveFileName(self.window, 'Экспорт JSON', 'report.json', 'JSON Files (*.json)')
        if not fname: return
        rows = self.table_model.as_dicts()
        ok = self.exporter.export_json(rows, fname)
        QMessageBox.information(self.window, 'Экспорт', 'JSON сохранён' if ok else 'Ошибка при экспорте')

    def _export_pdf(self):
        fname, _ = QFileDialog.getSaveFileName(self.window, 'Экспорт PDF', 'summary.pdf', 'PDF Files (*.pdf)')
        if not fname: return
        rows = self.table_model.as_dicts()
        proto_counts = {}
        for r in rows:
            k = r.get('l4') or 'OTHER'
            proto_counts[k] = proto_counts.get(k, 0) + 1
        summary = {'Всего пакетов': len(rows), 'Протоколы': str(proto_counts)}
        ok = self.exporter.export_pdf_summary(summary, fname)
        QMessageBox.information(self.window, 'Экспорт', 'PDF сохранён' if ok else 'Ошибка при экспорте')

    def run(self):
        self.window.show()
        self.qtapp.exec()