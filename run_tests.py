"""Quick test runner for classifier (no pytest required).
Run: python run_tests.py
"""
from intellinsniff.core.classifier import Classifier
def assert_eq(a,b,msg=None):
    if a!=b:
        raise AssertionError(f"Assertion failed: {a} != {b} -- {msg}")

def test_vpn_detection():
    c = Classifier()
    pkt = {'proto':'udp','dport':1194,'payload':b'\x01\x02\x03'}
    tags,score,info = c.classify_packet(pkt)
    print('vpn test ->', tags, score, info)
    assert 'vpn' in tags, "VPN port not detected"
    assert score > 0.4, "Low score for vpn"

def test_tls_web_detection():
    c = Classifier()
    pkt = {'proto':'tcp','dport':443,'tls_sni':'example.com','layers':['ip','tcp','tls'],'payload':b'GET'}
    tags,score,info = c.classify_packet(pkt)
    print('tls test ->', tags, score, info)
    assert 'web' in tags or 'tls' in tags, "TLS/web not detected"

def test_entropy_detection():
    c = Classifier()
    pkt = {'proto':'udp','dport':12345,'payload':bytes([i%256 for i in range(1024)])}  # low entropy-ish
    tags,score,info = c.classify_packet(pkt)
    print('entropy test ->', tags, score, info)

if __name__ == '__main__':
    test_vpn_detection()
    test_tls_web_detection()
    test_entropy_detection()
    print('All tests ran (simple smoke tests).')
