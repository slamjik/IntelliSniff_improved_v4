import yaml
from pathlib import Path

DEFAULT = {
    'vpn': {'udp_ports': [1194, 51820], 'ip_proto': {50: 'esp', 47: 'gre'}, 'ike_ports': [500,4500]},
    'apps': {'video': [1935, 554, 3478], 'games': [27015, 3074]}
}

class DPIRules:
    def __init__(self, path: Path=None):
        self.path = path
        self.rules = DEFAULT
        if path and path.exists():
            try:
                self.rules = yaml.safe_load(path.read_text(encoding='utf-8')) or DEFAULT
            except Exception:
                self.rules = DEFAULT
