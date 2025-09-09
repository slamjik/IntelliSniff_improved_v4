"""Improved Classifier
- Rule-based ensemble for traffic classification: ports, protocols, TLS SNI, DNS, known VPN ports, encapsulation.
- Provides confidence score [0..1] and tags like: 'vpn','web','streaming','p2p','dns','mail','unknown'.
- Extensible: loads signatures from assets/traffic_signatures.yaml (if present).
"""
from typing import Dict, Any, List, Tuple
import os, math

try:
    import yaml
except Exception:
    yaml = None

DEFAULT_SIGNATURES = {
    'vpn_ports': [1194, 51820, 500, 4500, 1701, 1723],  # openvpn, wireguard, ipsec, l2tp, pptp
    'tls_indicators': ['.com', '.org', '.net'],  # fallback indicators in hostnames
    'streaming_ports': [554, 1935, 1755],  # rtsp, rtmp
    'mail_ports': [25, 465, 587, 110, 995, 143, 993],
    'dns_ports': [53, 5353]
}

def load_signatures(path: str = None) -> Dict[str,Any]:
    if path is None:
        here = os.path.dirname(__file__)
        path = os.path.join(here, "..", "assets", "traffic_signatures.yaml")
    try:
        if yaml is None:
            return DEFAULT_SIGNATURES.copy()
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or DEFAULT_SIGNATURES.copy()
    except Exception:
        return DEFAULT_SIGNATURES.copy()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    cnt = Counter(data)
    import math
    ent = 0.0
    for v in cnt.values():
        p = v/len(data)
        ent -= p * math.log2(p)
    # normalize by max entropy for byte alphabet
    max_ent = 8.0
    return ent/max_ent

class Classifier:
    def __init__(self, rules=None):
        # rules can be DPIRules or signatures loaded elsewhere; we accept a dict
        self.signatures = load_signatures() if rules is None else (rules if isinstance(rules, dict) else load_signatures())
        # allow additional tunables
        self.vpn_ports = set(self.signatures.get('vpn_ports', []))
        self.stream_ports = set(self.signatures.get('streaming_ports', []))
        self.mail_ports = set(self.signatures.get('mail_ports', []))
        self.dns_ports = set(self.signatures.get('dns_ports', []))
        self.tls_indicators = self.signatures.get('tls_indicators', [])

    def classify_packet(self, pkt: Dict[str,Any]) -> Tuple[List[str], float, Dict[str,Any]]:
        """Classify a single packet.
        pkt is expected to be a dict with possible keys:
            'proto' - protocol string
            'sport','dport' - source/dest ports (int)
            'src','dst' - ip strings
            'payload' - bytes (optional)
            'layers' - list of layer names (optional)
            'http_host' - hostname from HTTP Host header (optional)
            'tls_sni' - SNI string from TLS (optional)
            'dns_query' - domain string from DNS query (optional)
        Returns (tags, confidence, reasons)
        """
        tags = []
        reasons = {}
        score = 0.0

        proto = (pkt.get('proto') or '').lower()
        sport = pkt.get('sport')
        dport = pkt.get('dport')
        tls_sni = pkt.get('tls_sni') or ''
        http_host = pkt.get('http_host') or ''
        dns_q = pkt.get('dns_query') or ''
        layers = pkt.get('layers') or []
        payload = pkt.get('payload') or b''

        # Heuristic 1: VPN by ports or encapsulation
        if dport in self.vpn_ports or sport in self.vpn_ports:
            tags.append('vpn')
            reasons['vpn_port'] = True
            score += 0.45

        # Heuristic 2: ESP / IPsec in layers
        if any(l.lower() in ('esp','isakmp','ipsec') for l in layers):
            tags.append('vpn')
            reasons['encapsulation'] = 'esp/ipsec'
            score += 0.40

        # Heuristic 3: WireGuard detection by common port and payload entropy pattern (short handshake)
        if dport == 51820 or sport == 51820:
            tags.append('vpn')
            reasons['wg_port'] = True
            score += 0.40

        # Heuristic 4: DNS traffic
        if dport in self.dns_ports or sport in self.dns_ports or dns_q:
            tags.append('dns')
            reasons['dns'] = dns_q or True
            score += 0.2

        # Heuristic 5: streaming / media ports
        if dport in self.stream_ports or sport in self.stream_ports:
            tags.append('streaming')
            reasons['stream_port'] = True
            score += 0.25

        # Heuristic 6: mail
        if dport in self.mail_ports or sport in self.mail_ports:
            tags.append('mail')
            reasons['mail_port'] = True
            score += 0.25

        # Heuristic 7: HTTP / TLS host matching — if host is present it's likely web traffic
        host = tls_sni or http_host or dns_q
        if host:
            # basic heuristic: known TLD / dot presence implies web-like traffic
            if any(ind in host.lower() for ind in self.tls_indicators) or '.' in host:
                tags.append('web')
                reasons['host'] = host
                score += 0.35

        # Heuristic 8: payload entropy high -> possible encrypted tunnel / VPN
        try:
            ent = entropy(payload if isinstance(payload, (bytes,bytearray)) else str(payload).encode('utf-8',errors='ignore'))
            reasons['entropy'] = ent
            if ent > 0.85:
                # encrypted-looking
                tags.append('encrypted')
                score += 0.25
                # if not yet tagged vpn, this is supportive evidence
                if 'vpn' not in tags:
                    score += 0.15
        except Exception:
            pass

        # Heuristic 9: TLS handshake presence -> web or encrypted app
        if any('tls' in l.lower() or 'ssl' in l.lower() for l in layers):
            tags.append('tls')
            score += 0.15

        # Normalize score to max 1.0
        if score > 1.0:
            score = 1.0

        # Post-processing: deduplicate tags and compute confidence adjustments
        tags = list(dict.fromkeys(tags))

        # If both dns and web present -> web preferred
        if 'dns' in tags and 'web' in tags:
            # keep both but boost web confidence
            score = min(1.0, score + 0.05)

        # Compute human-readable label
        label = self._compose_label(tags, score)

        reasons['base_score'] = score
        return tags, float(round(score,3)), {'label': label, 'reasons': reasons}

    def _compose_label(self, tags, score):
        if not tags:
            return 'unknown'
        # prefer vpn if present
        priority = ['vpn','web','streaming','p2p','mail','dns','encrypted','tls']
        for p in priority:
            if p in tags:
                return f'{p} (score={score:.2f})'
        return f'{tags[0]} (score={score:.2f})'

    # Utility: classify many packets
    def classify_batch(self, pkts: List[Dict[str,Any]]) -> List[Tuple[List[str], float, Dict[str,Any]]]:
        return [self.classify_packet(p) for p in pkts]

if __name__ == '__main__':  # quick smoke test when run standalone
    c = Classifier()
    # simple synthetic packet
    pkt = {'proto':'udp','dport':51820,'src':'10.0.0.2','dst':'8.8.8.8','payload':b'\x01\x02\x03\x04'}
    print(c.classify_packet(pkt))
