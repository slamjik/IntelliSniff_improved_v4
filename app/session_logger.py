"""Utilities for logging task sessions in PostgreSQL."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .db import session_scope
from .models import ActionLog, SessionLog


class SessionLoggerError(RuntimeError):
    """Raised when an error occurs during session logging operations."""


def _normalize_details(details: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if details is None:
        return None
    if not isinstance(details, dict):
        raise SessionLoggerError("details must be a dictionary or None")
    return details


def start_session(user: str, *, details: Optional[Dict[str, Any]] = None) -> int:
    """Create a new session entry and return its identifier."""
    if not user:
        raise SessionLoggerError("user must be provided")

    session_details = _normalize_details(details)

    try:
        with session_scope() as db:
            session = SessionLog(user=user, details=session_details)
            db.add(session)
            db.flush()  # populate session.id without committing yet
            session_id = session.id
        return session_id
    except SQLAlchemyError as exc:
        raise SessionLoggerError(f"Failed to start session: {exc}") from exc


def log_action(
    session_id: int,
    name: str,
    *,
    payload: Optional[Dict[str, Any]] = None,
    db: Optional[Session] = None,
) -> None:
    """Record an action that occurred within a session."""
    if not name:
        raise SessionLoggerError("Action name must be provided")

    action_payload = _normalize_details(payload)
    if session_id <= 0:
        raise SessionLoggerError("session_id must be a positive integer")

    def _persist(session: Session) -> None:
        session.add(
            ActionLog(session_id=session_id, name=name, payload=action_payload)
        )

    try:
        if db is not None:
            _persist(db)
        else:
            with session_scope() as scoped_session:
                _persist(scoped_session)
    except SQLAlchemyError as exc:
        raise SessionLoggerError(f"Failed to log action: {exc}") from exc


def finish_session(
    session_id: int,
    result: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Mark a session as finished."""
    if session_id <= 0:
        raise SessionLoggerError("session_id must be a positive integer")

    if not result:
        raise SessionLoggerError("result must be provided")

    session_details = _normalize_details(details)

    try:
        with session_scope() as db:
            session = db.get(SessionLog, session_id)
            if session is None:
                raise SessionLoggerError(f"Session with id={session_id} not found")
            session.finished_at = datetime.now(timezone.utc)
            session.result = result
            session.details = session_details
    except SQLAlchemyError as exc:
        raise SessionLoggerError(f"Failed to finish session: {exc}") from exc


def cleanup_sessions(*, older_than_days: int = 30) -> int:
    """Delete finished sessions older than the specified amount of days."""
    if older_than_days <= 0:
        raise SessionLoggerError("older_than_days must be positive")

    threshold = datetime.now(timezone.utc) - timedelta(days=older_than_days)

    try:
        with session_scope() as db:
            deleted = (
                db.query(SessionLog)
                .filter(SessionLog.finished_at.isnot(None))
                .filter(SessionLog.finished_at < threshold)
                .delete(synchronize_session=False)
            )
            return deleted
    except SQLAlchemyError as exc:
        raise SessionLoggerError(f"Failed to cleanup sessions: {exc}") from exc


def list_recent_sessions(limit: int = 50) -> Iterable[SessionLog]:
    """Fetch a limited number of the most recent sessions for inspection."""
    if limit <= 0:
        raise SessionLoggerError("limit must be positive")

    try:
        with session_scope() as db:
            return (
                db.query(SessionLog)
                .order_by(SessionLog.started_at.desc())
                .limit(limit)
                .all()
            )
    except SQLAlchemyError as exc:
        raise SessionLoggerError(f"Failed to list sessions: {exc}") from exc
