"""
Helper for optional NFStream integration.
If nfstream is installed, this module exposes helper functions to create an NFStreamer
and iterate flows. If not installed, functions are no-op and provide graceful fallback.
"""
import inspect
import logging

log = logging.getLogger("ta.nfstream_helper")
try:
    from nfstream import NFStreamer, NFPlugin
    NFSTREAM_AVAILABLE = True
    try:
        _NFSTREAMER_PARAMS = set(inspect.signature(NFStreamer.__init__).parameters)
    except Exception:  # pragma: no cover - very defensive
        _NFSTREAMER_PARAMS = set()
except Exception:  # pragma: no cover - runtime optional dependency
    NFSTREAM_AVAILABLE = False
    _NFSTREAMER_PARAMS = set()


def _supports_param(param_name: str) -> bool:
    """Check whether current NFStreamer version accepts a keyword."""
    if not _NFSTREAMER_PARAMS:
        return True
    return param_name in _NFSTREAMER_PARAMS


def make_streamer(interface=None, pcap=None, timeout=60, **kwargs):
    """Create an NFStreamer if available.
    Params: interface (str) or pcap (str) - source
    Returns NFStreamer instance or None
    """
    if not NFSTREAM_AVAILABLE:
        log.debug("NFStream not available in environment.")
        return None
    params = dict()
    source = None
    if interface:
        if _supports_param("interface"):
            params["interface"] = interface
        elif _supports_param("device"):
            params["device"] = interface
        else:
            source = interface
    if pcap:
        if _supports_param("input_file"):
            params['input_file'] = pcap
        else:
            source = pcap
    if source and _supports_param("source"):
        params["source"] = source
    elif source:
        log.warning(
            "NFStreamer interface compatibility fallback used for source=%s", source
        )
        params["source"] = source
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
