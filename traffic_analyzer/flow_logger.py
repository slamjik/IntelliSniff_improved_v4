"""
flow_logger.py — боевой логгер сетевых потоков в PostgreSQL.

❯ Назначение
    - Принимать готовый словарь flow_dict из streaming.py
    - Конвертировать поля в корректные типы
    - Записывать в таблицу flows (модель app.models.Flow)
    - Делать простую авто-чистку (retention), чтобы БД не пухла бесконечно
    - Давать удобный API для чтения последних потоков

❯ Ожидаемый формат входного flow_dict:
    {
        'ts': <int ms>,
        'iface': 'eth0',
        'src': '10.0.0.1',
        'dst': '8.8.8.8',
        'sport': 12345,
        'dport': 53,
        'proto': 'UDP',
        'packets': 42,
        'bytes': 2048,
        'label': 'attack',
        'label_name': 'DDoS',
        'score': 0.97,
        'summary': {... любой JSON ...}
    }

❯ Использование из streaming.py:
    from traffic_analyzer.flow_logger import save_flow

    ...
    flow_dict = {
        ...  # как сейчас формируешь в _emit_flow()
    }
    save_flow(flow_dict)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, desc, or_, select
from sqlalchemy.exc import SQLAlchemyError

# Важно: импортируем твои готовые объекты
from app.db import SessionLocal
from app.models import Flow

log = logging.getLogger("ta.flow_logger")


# =====================================================================
#   Вспомогательные конвертеры
# =====================================================================

def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return str(value)
    return str(value)


def _as_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if callable(value):
        try:
            return _as_int(value(), default)
        except Exception:
            return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value:  # NaN
            return default
        return int(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", errors="ignore")
        except Exception:
            return default
    try:
        return int(str(value).strip())
    except Exception:
        try:
            return int(float(str(value).strip()))
        except Exception:
            return default


def _as_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if callable(value):
        try:
            return _as_float(value(), default)
        except Exception:
            return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", errors="ignore")
        except Exception:
            return default
    try:
        return float(str(value).strip())
    except Exception:
        return default


def _to_utc_datetime_from_ms(value: Any) -> datetime:
    """Convert milliseconds (or datetime) to timezone-aware datetime in UTC."""

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    ts_ms = _as_int(value, default=int(time.time() * 1000))
    return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)


# =====================================================================
#   Класс логгера
# =====================================================================

class FlowLogger:
    """
    Потокобезопасный логгер сетевых флоу в PostgreSQL.

    Используется как синглтон: flow_logger = FlowLogger()
    И далее:
        flow_logger.save_flow(flow_dict)
        flow_logger.get_recent_flows(limit=100)
    """

    def __init__(
            self,
            max_age_hours: Optional[float] = 24.0,
            max_rows: int = 50_000,
    ):
        """
        :param max_age_hours: сколько часов хранить записи (None — не ограничивать по времени)
        :param max_rows: максимум строк в таблице (0 или None — без ограничения)
        """
        self._lock = threading.Lock()
        self._max_age_hours = max_age_hours
        self._max_rows = max_rows

    # -----------------------------------------------------------------
    #   Внутренний retention (чистка старых записей)
    # -----------------------------------------------------------------
    def _cleanup(self, db_session) -> None:
        """
        Чистим старые записи:
          - старше max_age_hours
          - оставляем только max_rows последних
        """
        # === 1) Чистим по возрасту ===
        if self._max_age_hours is not None:

            cutoff_dt = datetime.now(timezone.utc) - timedelta(hours=float(self._max_age_hours))

            db_session.execute(delete(Flow).where(Flow.ts < cutoff_dt))

        # === 2) Чистим по количеству ===
        if self._max_rows and self._max_rows > 0:
            subq = (
                select(Flow.id)
                .order_by(desc(Flow.id))
                .offset(self._max_rows)
                .limit(1)
            )
            oldest_to_keep_id = db_session.execute(subq).scalar()


            if oldest_to_keep_id:
                db_session.execute(
                    delete(Flow).where(Flow.id < oldest_to_keep_id)
                )

    # -----------------------------------------------------------------
    #   Публичный API: запись
    # -----------------------------------------------------------------
    def save_flow(self, flow: Dict[str, Any]) -> int:
        """
        Записать один флоу в таблицу flows.

        Возвращает ID созданной строки (или 0 при ошибке).
        """
        with self._lock:
            db = SessionLocal()
            try:
                ts_dt = _to_utc_datetime_from_ms(flow.get("ts"))

                row = Flow(
                    ts=ts_dt,
                    iface=_as_text(flow.get("iface")),
                    src=_as_text(flow.get("src")),
                    dst=_as_text(flow.get("dst")),
                    sport=_as_int(flow.get("sport")),
                    dport=_as_int(flow.get("dport")),
                    proto=_as_text(flow.get("proto")) or "",
                    packets=_as_int(flow.get("packets")),
                    bytes=_as_int(flow.get("bytes")),
                    label=_as_text(flow.get("label")) or "unknown",
                    label_name=_as_text(flow.get("label_name"))
                               or _as_text(flow.get("label"))
                               or "unknown",
                    score=_as_float(flow.get("score")),
                    # summary может быть dict/list/str — JSONB всё съест
                    summary=flow.get("summary"),
                )

                db.add(row)

                # авто-чистка (по желанию можно отключить, выставив max_age_hours=None и max_rows=0)
                self._cleanup(db)

                db.commit()
                db.refresh(row)

                log.debug(
                    "FlowLogger: saved flow id=%s %s:%s -> %s:%s [%s] label=%s score=%.3f",
                    row.id,
                    row.src,
                    row.sport,
                    row.dst,
                    row.dport,
                    row.proto,
                    row.label,
                    row.score if row.score is not None else 0.0,
                )
                return row.id

            except SQLAlchemyError as e:
                db.rollback()
                log.error("FlowLogger: DB error while saving flow: %s", e)
                return 0
            finally:
                db.close()

    # -----------------------------------------------------------------
    #   Публичный API: чтение
    # -----------------------------------------------------------------
    def get_recent_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Вернуть последние N флоу (по времени ts, по убыванию) в виде словарей.
        Удобно для CLI, отладки, веб-интерфейса.
        """
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        limit = max(1, min(limit, 1000))

        db = SessionLocal()
        try:
            q = (
                select(Flow)
                .order_by(desc(Flow.ts))
                .limit(limit)
            )
            rows = db.execute(q).scalars().all()

            result: List[Dict[str, Any]] = []
            for r in rows:
                result.append(
                    {
                        "id": r.id,
                        "ts": r.ts,
                        "iface": r.iface,
                        "src": r.src,
                        "dst": r.dst,
                        "sport": r.sport,
                        "dport": r.dport,
                        "proto": r.proto,
                        "packets": r.packets,
                        "bytes": r.bytes,
                        "label": r.label,
                        "label_name": r.label_name,
                        "score": r.score,
                        "summary": r.summary,
                    }
                )
            return result
        finally:
            db.close()

    def get_last_attack_flows(
            self,
            limit: int = 50,
            min_score: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """
        Пример полезного метода: последние "подозрительные" флоу с label='attack'
        и score >= min_score.
        """
        try:
            limit = int(limit)
        except Exception:
            limit = 50
        limit = max(1, min(limit, 1000))

        db = SessionLocal()
        try:
            q = (
                select(Flow)
                .where(Flow.label == "attack")
                .where(or_(Flow.score.is_(None), Flow.score >= min_score))
                .order_by(desc(Flow.ts))
                .limit(limit)
            )
            rows = db.execute(q).scalars().all()

            result: List[Dict[str, Any]] = []
            for r in rows:
                result.append(
                    {
                        "id": r.id,
                        "ts": r.ts,
                        "src": r.src,
                        "dst": r.dst,
                        "sport": r.sport,
                        "dport": r.dport,
                        "proto": r.proto,
                        "packets": r.packets,
                        "bytes": r.bytes,
                        "label": r.label,
                        "score": r.score,
                        "summary": r.summary,
                    }
                )
            return result
        finally:
            db.close()


# =====================================================================
#   Глобальный инстанс + удобные функции
# =====================================================================

_flow_logger = FlowLogger()


def save_flow(flow: Dict[str, Any]) -> int:
    """
    Удобный глобальный помощник: записать флоу.
    Используй в streaming.py:  save_flow(flow_dict)
    """
    return _flow_logger.save_flow(flow)


def get_recent_flows(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Вернуть последние N потоков (dict-ами).
    Удобно использовать из отдельного view-скрипта.
    """
    return _flow_logger.get_recent_flows(limit=limit)


def get_last_attack_flows(limit: int = 50, min_score: float = 0.5) -> List[Dict[str, Any]]:
    """
    Вернуть последние "атаки" (label='attack') с порогом уверенности.
    """
    return _flow_logger.get_last_attack_flows(limit=limit, min_score=min_score)
