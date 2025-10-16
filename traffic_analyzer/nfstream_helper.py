"""
Helper for optional NFStream integration.
If nfstream is installed, this module exposes helper functions to create an NFStreamer
and iterate flows. If not installed, functions are no-op and provide graceful fallback.
"""
import logging
log = logging.getLogger("ta.nfstream_helper")
try:
    from nfstream import NFStreamer, NFPlugin
    NFSTREAM_AVAILABLE = True
except Exception:
    NFSTREAM_AVAILABLE = False

def make_streamer(interface=None, pcap=None, timeout=60, **kwargs):
    """Create an NFStreamer if available.
    Params: interface (str) or pcap (str) - source
    Returns NFStreamer instance or None
    """
    if not NFSTREAM_AVAILABLE:
        log.debug("NFStream not available in environment.")
        return None
    params = dict()
    if interface:
        params['interface'] = interface
    if pcap:
        params['input_file'] = pcap
    params.update(kwargs)
    # keep defaults safe
    try:
        streamer = NFStreamer(**params)
        return streamer
    except Exception as e:
        log.exception("Failed to create NFStreamer: %s", e)
        return None

def iterate_flows_from_streamer(streamer):
    """Yield flows from an NFStreamer object (if available)."""
    if not NFSTREAM_AVAILABLE or streamer is None:
        return
    try:
        for flow in streamer:
            yield flow
    except GeneratorExit:
        return
    except Exception:
        log.exception("Error iterating flows from NFStreamer")
        return
