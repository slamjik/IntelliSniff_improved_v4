"""Database logger for captured flows.

Ensures ML metadata is preserved and duration fields are always present so UI and
analytics remain consistent.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, desc, or_, select
from sqlalchemy.exc import SQLAlchemyError

from app.db import SessionLocal
from app.models import Flow

log = logging.getLogger("ta.flow_logger")


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
    try:
        if callable(value):
            return _as_int(value(), default)
        if value is None:
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
            value = value.decode("utf-8", errors="ignore")
        return int(str(value).strip())
    except Exception:
        try:
            return int(float(str(value).strip()))
        except Exception:
            return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if callable(value):
            return _as_float(value(), default)
        if value is None:
            return default
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)):
            if value != value:
                return default
            return float(value)
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="ignore")
        return float(str(value).strip())
    except Exception:
        return default


def _as_json(value: Any) -> Any:
    """Safely coerce incoming value to JSON-serializable object."""

    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            # leave raw string so JSONB accepts it but do not fail
            return value
    return value


def _as_dict(value: Any) -> Dict[str, Any]:
    parsed = _as_json(value)
    return parsed if isinstance(parsed, dict) else {}


def _to_utc_datetime_from_ms(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    ts_ms = _as_int(value, default=int(time.time() * 1000))
    return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)


class FlowLogger:
    def __init__(self, max_age_hours: Optional[float] = 24.0, max_rows: int = 50_000):
        self._lock = threading.Lock()
        self._max_age_hours = max_age_hours
        self._max_rows = max_rows

    # ------------------------------------------------------------------
    def _cleanup(self, db_session) -> None:
        if self._max_age_hours is not None:
            cutoff_dt = datetime.now(timezone.utc) - timedelta(hours=float(self._max_age_hours))
            db_session.execute(delete(Flow).where(Flow.ts < cutoff_dt))

        if self._max_rows and self._max_rows > 0:
            subq = select(Flow.id).order_by(desc(Flow.id)).offset(self._max_rows).limit(1)
            oldest_to_keep_id = db_session.execute(subq).scalar()
            if oldest_to_keep_id:
                db_session.execute(delete(Flow).where(Flow.id < oldest_to_keep_id))

    # ------------------------------------------------------------------
    def save_flow(self, flow: Dict[str, Any]) -> int:
        with self._lock:
            db = SessionLocal()
            try:
                ts_dt = _to_utc_datetime_from_ms(flow.get("ts"))
                duration_sec = _as_float(flow.get("duration"))
                if duration_sec == 0:
                    duration_sec = _as_float(flow.get("flow_duration"))

                base_summary = _as_dict(flow.get("summary"))
                row = Flow(
                    ts=ts_dt,
                    iface=_as_text(flow.get("iface")) or "-",
                    src=_as_text(flow.get("src")) or "",
                    dst=_as_text(flow.get("dst")) or "",
                    sport=_as_int(flow.get("sport")),
                    dport=_as_int(flow.get("dport")),
                    proto=_as_text(flow.get("proto")) or _as_text(flow.get("protocol")),
                    packets=_as_int(flow.get("packets")),
                    bytes=_as_int(flow.get("bytes")),
                    label=_as_text(flow.get("label")) or "unknown",
                    label_name=_as_text(flow.get("label_name")) or _as_text(flow.get("label")) or "unknown",
                    score=_as_float(flow.get("score")),
                    task_attack=_as_text(flow.get("task_attack")),
                    attack_confidence=_as_float(flow.get("attack_confidence")),
                    attack_version=_as_text(flow.get("attack_version")),
                    attack_explanation=_as_json(flow.get("attack_explanation")),
                    task_vpn=_as_text(flow.get("task_vpn")),
                    vpn_confidence=_as_float(flow.get("vpn_confidence")),
                    vpn_version=_as_text(flow.get("vpn_version")),
                    vpn_explanation=_as_json(flow.get("vpn_explanation")),
                    task_anomaly=_as_text(flow.get("task_anomaly")),
                    anomaly_confidence=_as_float(flow.get("anomaly_confidence")),
                    anomaly_version=_as_text(flow.get("anomaly_version")),
                    anomaly_explanation=_as_json(flow.get("anomaly_explanation")),
                    summary={
                        **base_summary,
                        "duration": duration_sec,
                        "flow_duration": duration_sec,
                    },
                )

                db.add(row)
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
            except SQLAlchemyError:
                db.rollback()
                log.exception("FlowLogger: DB error while saving flow")
                return 0
            finally:
                db.close()

    # ------------------------------------------------------------------
    def get_recent_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            limit = max(1, min(int(limit), 1000))
        except Exception:
            limit = 100

        db = SessionLocal()
        try:
            q = select(Flow).order_by(desc(Flow.ts)).limit(limit)
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
                        "task_attack": r.task_attack,
                        "attack_confidence": r.attack_confidence,
                        "attack_version": r.attack_version,
                        "attack_explanation": r.attack_explanation,
                        "task_vpn": r.task_vpn,
                        "vpn_confidence": r.vpn_confidence,
                        "vpn_version": r.vpn_version,
                        "vpn_explanation": r.vpn_explanation,
                        "task_anomaly": r.task_anomaly,
                        "anomaly_confidence": r.anomaly_confidence,
                        "anomaly_version": r.anomaly_version,
                        "anomaly_explanation": r.anomaly_explanation,
                        "summary": r.summary,
                    }
                )
            return result
        finally:
            db.close()

    def get_last_attack_flows(self, limit: int = 50, min_score: float = 0.5) -> List[Dict[str, Any]]:
        try:
            limit = max(1, min(int(limit), 1000))
        except Exception:
            limit = 50

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


_flow_logger = FlowLogger()


def save_flow(flow: Dict[str, Any]) -> int:
    return _flow_logger.save_flow(flow)


def get_recent_flows(limit: int = 100) -> List[Dict[str, Any]]:
    return _flow_logger.get_recent_flows(limit=limit)


def get_last_attack_flows(limit: int = 50, min_score: float = 0.5) -> List[Dict[str, Any]]:
    return _flow_logger.get_last_attack_flows(limit=limit, min_score=min_score)
