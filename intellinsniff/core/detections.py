from collections import deque

class Detections:
    def __init__(self, window=500):
        self.recent = deque(maxlen=window)
        self.alerts = []

    def feed(self, pview):
        self.recent.append(pview)
        dns_count = sum(1 for x in self.recent if x.classification and 'dns' in x.classification)
        if dns_count > 200 and ('Высокая интенсивность DNS — проверьте туннелирование/ботнет' not in self.alerts):
            self.alerts.append('Высокая интенсивность DNS — проверьте туннелирование/ботнет')
        tls_small = sum(1 for x in self.recent if x.classification and ('tls' in x.classification) and x.length < 200)
        if tls_small > 300 and ('Много маленьких TLS пакетов — возможен beaconing/канал C2' not in self.alerts):
            self.alerts.append('Много маленьких TLS пакетов — возможен beaconing/канал C2')

    def pull(self):
        out = list(self.alerts)
        self.alerts.clear()
        return out
