import queue
_q = queue.Queue()
def publish(event: dict):
    """Publish a serializable event to the internal queue."""
    try:
        _q.put(event, block=False)
    except Exception:
        # fallback blocking
        _q.put(event)
def get_queue():
    return _q
