from __future__ import annotations
import logging
import threading
import time
from typing import Any, Dict, Optional

from app.session_logger import finish_session, log_action, start_session

log = logging.getLogger("ta.session_bridge")

_LOCK = threading.RLock()
CURRENT_CAPTURE_SESSION: Optional[int] = None
SESSION_START_TS: Optional[float] = None
FLOW_COUNTER = 0
ATTACK_COUNTER = 0
TOTAL_BYTES = 0
TOTAL_PACKETS = 0


def _safe_log_action(name: str, payload: Optional[Dict[str, Any]] = None, *, session_id: Optional[int] = None) -> None:
    sid = session_id or CURRENT_CAPTURE_SESSION
    if not sid:
        return
    try:
        log_action(sid, name, payload=payload)
    except Exception:  # noqa: BLE001 - logging must not break pipeline
        log.warning("Session logging failed for %s", name, exc_info=True)


def _compute_metrics() -> Dict[str, Any]:
    duration = None
    if SESSION_START_TS is not None:
        duration = max(0.0, time.time() - SESSION_START_TS)
    return {
        "duration_seconds": duration,
        "flows_processed": FLOW_COUNTER,
        "attacks_detected": ATTACK_COUNTER,
        "total_bytes": TOTAL_BYTES,
        "total_packets": TOTAL_PACKETS,
        "avg_packets_per_flow": (TOTAL_PACKETS / FLOW_COUNTER) if FLOW_COUNTER else 0.0,
        "avg_bytes_per_flow": (TOTAL_BYTES / FLOW_COUNTER) if FLOW_COUNTER else 0.0,
    }


def start_capture_session(user: str = "system", details: Optional[Dict[str, Any]] = None) -> Optional[int]:
    global CURRENT_CAPTURE_SESSION, SESSION_START_TS, FLOW_COUNTER, ATTACK_COUNTER, TOTAL_BYTES, TOTAL_PACKETS
    with _LOCK:
        if CURRENT_CAPTURE_SESSION:
            _finish_session_locked("forced_stop", {"reason": "restart"})
        FLOW_COUNTER = 0
        ATTACK_COUNTER = 0
        TOTAL_BYTES = 0
        TOTAL_PACKETS = 0
        SESSION_START_TS = time.time()
        try:
            CURRENT_CAPTURE_SESSION = start_session(user, details=details)
            _safe_log_action("capture_started", payload=details, session_id=CURRENT_CAPTURE_SESSION)
        except Exception:  # noqa: BLE001 - logging must not break pipeline
            log.warning("Failed to start capture session", exc_info=True)
            CURRENT_CAPTURE_SESSION = None
            SESSION_START_TS = None
        return CURRENT_CAPTURE_SESSION


def _finish_session_locked(result: str, extra_details: Optional[Dict[str, Any]] = None) -> None:
    global CURRENT_CAPTURE_SESSION, SESSION_START_TS
    sid = CURRENT_CAPTURE_SESSION
    if not sid:
        return
    details = _compute_metrics()
    if extra_details:
        details.update(extra_details)
    try:
        finish_session(sid, result, details)
    except Exception:  # noqa: BLE001 - logging must not break pipeline
        log.warning("Failed to finish session", exc_info=True)
    CURRENT_CAPTURE_SESSION = None
    SESSION_START_TS = None


def finish_capture_session(result: str = "success", extra_details: Optional[Dict[str, Any]] = None) -> None:
    with _LOCK:
        _safe_log_action("capture_stopped", payload=_compute_metrics())
        _finish_session_locked(result, extra_details)


def log_capture_event(name: str, payload: Optional[Dict[str, Any]] = None) -> None:
    with _LOCK:
        _safe_log_action(name, payload)


def record_flow_emission(key, flow, res: Optional[Dict[str, Any]]) -> None:
    global FLOW_COUNTER, ATTACK_COUNTER, TOTAL_BYTES, TOTAL_PACKETS
    res = res or {}
    with _LOCK:
        FLOW_COUNTER += 1
        TOTAL_BYTES += int(getattr(flow, "bytes", 0) or 0)
        TOTAL_PACKETS += int(getattr(flow, "packets", 0) or 0)
        label = res.get("label")
        if label and str(label).lower() not in {"benign", "normal", "none", "ok"}:
            ATTACK_COUNTER += 1
        payload = {
            "src": getattr(key, "src", None),
            "dst": getattr(key, "dst", None),
            "proto": getattr(key, "proto", None),
            "packets": getattr(flow, "packets", None),
            "bytes": getattr(flow, "bytes", None),
            "label": res.get("label"),
            "score": res.get("confidence"),
        }
    _safe_log_action("flow_emitted", payload)


def log_streaming_stopped() -> None:
    metrics = _compute_metrics()
    _safe_log_action("streaming_stopped", metrics)


def get_current_session_id() -> Optional[int]:
    with _LOCK:
        return CURRENT_CAPTURE_SESSION

