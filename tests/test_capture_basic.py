
import time
from types import SimpleNamespace

from traffic_analyzer import capture

def test_start_stop_capture():
    # start capture in fallback mode (no nfstream) - should not raise
    capture.start_capture(iface=None, bpf=None, flow_timeout=1, use_nfstream=False)
    time.sleep(0.5)
    capture.stop_capture()
    assert True


def test_start_capture_nfstream_sanitizes_iface(monkeypatch):
    packets = []
    called = {}

    monkeypatch.setattr(capture, "NFSTREAM_AVAILABLE", True)
    monkeypatch.setattr(capture, "list_ifaces", lambda: ["All interfaces", "eth0 (10.0.0.1)"])

    def fake_make_streamer(interface=None, **kwargs):
        called['interface'] = interface

        class Dummy:
            def stop(self_inner):
                called['stopped'] = True

        return Dummy()

    def fake_iterate(streamer):
        yield SimpleNamespace(
            timestamp=time.time(),
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            bytes=150,
            packets=1,
            tls_sni=None,
            http_host=None,
            dns_qry_name=None,
            application_name=None,
        )

    def fake_handle_packet(pkt):
        packets.append(pkt)

    monkeypatch.setattr(capture, "make_streamer", fake_make_streamer)
    monkeypatch.setattr(capture, "iterate_flows_from_streamer", fake_iterate)
    monkeypatch.setattr(capture, "handle_packet", fake_handle_packet)

    capture.start_capture(iface="eth0 (10.0.0.1)", use_nfstream=True, flow_timeout=0.1)
    time.sleep(0.2)
    capture.stop_capture()

    assert called.get('interface') == "eth0"
    assert packets and packets[0]['iface'] == "eth0"
