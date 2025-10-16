
import time
from traffic_analyzer import capture

def test_start_stop_capture():
    # start capture in fallback mode (no nfstream) - should not raise
    capture.start_capture(iface=None, bpf=None, flow_timeout=1, use_nfstream=False)
    time.sleep(0.5)
    capture.stop_capture()
    assert True
