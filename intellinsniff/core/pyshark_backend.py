import asyncio
import threading

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False

class PySharkCapture:
    def __init__(self, iface=None, bpf=None, callback=None):
        if not HAS_PYSHARK:
            raise RuntimeError("pyshark is not installed")
        self.iface = iface
        self.bpf = bpf
        self.callback = callback
        self._stop_event = threading.Event()
        self._thread = None
        self.live = None

    async def _capture_async(self):
        self.live = pyshark.LiveCapture(
            interface=self.iface if self.iface else None,
            bpf_filter=self.bpf,
            use_json=True,
            include_raw=True
        )
        try:
            async for pkt in self.live.sniff_continuously(packet_count=None):
                if self._stop_event.is_set():
                    break
                parsed = {'layers': {}, 'raw': bytes(pkt.get_raw_packet()) if hasattr(pkt, 'get_raw_packet') else None}
                for layer in pkt.layers:
                    if hasattr(layer, 'items') and callable(getattr(layer, 'items')):
                        parsed['layers'][layer.layer_name] = dict(layer.items())
                    else:
                        parsed['layers'][layer.layer_name] = getattr(layer, '__dict__', {})
                if self.callback:
                    self.callback(parsed)
        except Exception as e:
            print(f"[PyShark] Capture async error: {e}")

    def _run_capture(self):
        # Создаём отдельный event loop в потоке
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._capture_async())
        loop.close()

    def start(self):
        if self._thread and self._thread.is_alive():
            print("[PyShark] Capture already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_capture, daemon=True)
        self._thread.start()
        print(f"[PyShark] Capture thread started on iface={self.iface}, bpf={self.bpf}")

    def stop(self):
        self._stop_event.set()
        if self.live:
            try:
                self.live.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=1)
        print("[PyShark] Capture stopped")
