from .ui.app import IntelliSniffApp
from .core.dpi_rules import DPIRules
from .core.classifier import Classifier
from .core.capture import CaptureManager
from .core.detections import Detections
from .io.exporters import Exporter

def main():
    rules = DPIRules()
    classifier = Classifier(rules)
    capture = CaptureManager(classifier)
    detections = Detections()
    exporter = Exporter()
    app = IntelliSniffApp(capture, classifier, detections, exporter)
    app.run()

if __name__ == '__main__':
    main()
