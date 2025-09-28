import logging, threading, os
from scapy.all import AsyncSniffer
from .streaming import handle_packet, init_streaming
log = logging.getLogger('ta.capture')
_sniffer = None

def start_capture(iface=None, bpf=None):
    global _sniffer
    if _sniffer and _sniffer.running:
        log.info('Sniffer already running')
        return
    init_streaming()
    _sniffer = AsyncSniffer(iface=iface, prn=handle_packet, filter=bpf, store=False)
    _sniffer.start()
    log.info('AsyncSniffer started on %s', iface or 'default')

def stop_capture(timeout=2):
    global _sniffer
    if not _sniffer:
        return
    try:
        _sniffer.stop()
        log.info('Sniffer stopped')
    except Exception as e:
        log.exception('Error stopping sniffer: %s', e)
