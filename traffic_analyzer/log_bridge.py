"""
log_bridge.py — мост между streaming.py и PostgreSQL.

Выполняет:
  ✔ создание SessionLog при старте стриминга
  ✔ логирование flow_emit → ActionLog
  ✔ логирование ml_prediction → ActionLog
  ✔ логирование ошибок стриминга
  ✔ завершение сессии при остановке

Работает полностью event-driven через event_bus.
"""

from __future__ import annotations
from typing import Optional, Dict, Any
import traceback
import time

# ——— Импорт инфраструктуры ————————————————————————————————
from .event_bus import subscribe
from app.session_logger import start_session, log_action, finish_session


# Глобальный ID PostgreSQL-сессии
_pg_session_id: Optional[int] = None


# ——————————————————————————————————————————————————————————————
#    ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ——————————————————————————————————————————————————————————————

def _safe_log_action(action: str, payload: Dict[str, Any]):
    """
    Безопасный логгер действий — не ломает стриминг,
    даже если PostgreSQL временно недоступен.
    """
    global _pg_session_id
    if not _pg_session_id:
        return

    try:
        log_action(_pg_session_id, action, payload)
    except Exception as e:
        print(f"[log_bridge] ERROR writing action '{action}': {e}")
        print(traceback.format_exc())


# ——————————————————————————————————————————————————————————————
#    ОБРАБОТЧИКИ СОБЫТИЙ
# ——————————————————————————————————————————————————————————————

def handle_flow_event(flow: Dict[str, Any]):
    """
    Событие от streaming._emit_flow
    """
    _safe_log_action("flow_emit", {
        "src": flow.get("src"),
        "dst": flow.get("dst"),
        "proto": flow.get("proto"),
        "sport": flow.get("sport"),
        "dport": flow.get("dport"),
        "label": flow.get("label"),
        "score": flow.get("score"),
        "packets": flow.get("packets"),
        "bytes": flow.get("bytes"),
        "duration_ms": flow.get("duration_ms"),
        "iface": flow.get("iface"),
    })


def handle_prediction_event(result: Dict[str, Any]):
    """
    Событие от ML-модели.
    """
    _safe_log_action("ml_prediction", {
        "label": result.get("label"),
        "confidence": result.get("confidence"),
        "version": result.get("version"),
        "task": result.get("task"),
        "drift": result.get("drift"),
    })


def handle_stream_error(payload: Dict[str, Any]):
    """
    Общий обработчик ошибок стриминга + модели.
    """
    _safe_log_action("error", {
        "error": payload.get("error") or "unknown",
        "traceback": payload.get("traceback"),
        "time": time.time()
    })


# ——————————————————————————————————————————————————————————————
#    ИНИЦИАЛИЗАЦИЯ МОСТА
# ——————————————————————————————————————————————————————————————

def init_log_bridge() -> int:
    """
    Создаём PostgreSQL-сессию и подписываемся на события стриминга.
    """

    global _pg_session_id

    if _pg_session_id is not None:
        print("[log_bridge] WARNING: bridge already initialized")
        return _pg_session_id

    # Создаём новую сессию в PostgreSQL
    _pg_session_id = start_session("streaming_engine")

    print(f"[log_bridge] PostgreSQL session STARTED → ID={_pg_session_id}")

    # Подписываемся на события event_bus
    subscribe("flow", handle_flow_event)
    subscribe("ml_prediction", handle_prediction_event)
    subscribe("stream_error", handle_stream_error)

    print("[log_bridge] Subscribed to events: flow, ml_prediction, stream_error")

    return _pg_session_id


# ——————————————————————————————————————————————————————————————
#    ЗАВЕРШЕНИЕ МОСТА
# ——————————————————————————————————————————————————————————————

def stop_log_bridge(result: str = "success"):
    """
    Завершает PostgreSQL-сессию.
    """
    global _pg_session_id
    if not _pg_session_id:
        print("[log_bridge] No session to stop.")
        return

    try:
        finish_session(
            _pg_session_id,
            result=result,
            details={"type": "streaming_shutdown"}
        )
        print(f"[log_bridge] PostgreSQL session FINISHED → ID={_pg_session_id}")
    except Exception as e:
        print(f"[log_bridge] ERROR finishing session: {e}")
        print(traceback.format_exc())

    _pg_session_id = None
