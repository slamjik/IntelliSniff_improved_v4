import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTextEdit

class IntelliSniffUI(QMainWindow):
    def __init__(self, capture_manager, analyzer):
        super().__init__()
        self.capture_manager = capture_manager
        self.analyzer = analyzer
        self.setWindowTitle("IntelliSniff — MVP")
        self.resize(1280, 720)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        btn_start = QPushButton("Start Capture")
        btn_start.clicked.connect(self.start_capture)

        layout = QVBoxLayout()
        layout.addWidget(btn_start)
        layout.addWidget(self.output)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def start_capture(self):
        self.output.append("Starting capture... (simulation)")

def run_app(capture_manager, analyzer):
    app = QApplication(sys.argv)
    window = IntelliSniffUI(capture_manager, analyzer)
    window.show()
    app.exec()
