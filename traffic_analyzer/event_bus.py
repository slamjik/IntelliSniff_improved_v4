# traffic_analyzer/event_bus.py
import queue
_q = queue.Queue()

def publish(topic, obj):
    _q.put((topic, obj))

def get_queue():
    return _q
