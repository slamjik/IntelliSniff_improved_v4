from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, or_

from app.db import session_scope
from app.models import ActionLog, Flow, SessionLog
from traffic_analyzer.auth import get_current_username

router = APIRouter(tags=["logs"])


def _parse_dt(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except Exception:
        return None


def _session_dict(obj: SessionLog) -> Dict[str, Any]:
    return {
        "id": obj.id,
        "user": obj.user,
        "started_at": obj.started_at,
        "finished_at": obj.finished_at,
        "result": obj.result,
        "details": obj.details or {},
    }


def _action_dict(obj: ActionLog) -> Dict[str, Any]:
    return {
        "id": obj.id,
        "session_id": obj.session_id,
        "name": obj.name,
        "created_at": obj.created_at,
        "payload": obj.payload or {},
    }


def _flow_dict(obj: Flow) -> Dict[str, Any]:
    return {
        "id": obj.id,
        "ts": obj.ts,
        "src": obj.src,
        "dst": obj.dst,
        "sport": obj.sport,
        "dport": obj.dport,
        "proto": obj.proto,
        "packets": obj.packets,
        "bytes": obj.bytes,
        "label": obj.label,
        "score": obj.score,
        "summary": obj.summary or {},
    }


def _apply_time_filter(query, column, date_from: Optional[dt.datetime], date_to: Optional[dt.datetime]):
    if date_from:
        query = query.filter(column >= date_from)
    if date_to:
        query = query.filter(column <= date_to)
    return query


def _apply_search_filter(query, column, search: Optional[str]):
    if search:
        pattern = f"%{search}%"
        query = query.filter(cast(column, String).ilike(pattern))
    return query


@router.get("/sessions")
def api_sessions(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    user_filter: Optional[str] = Query(None, alias="user"),
    search: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_username),
):
    dt_from = _parse_dt(date_from)
    dt_to = _parse_dt(date_to)

    with session_scope() as db:
        q = db.query(SessionLog)
        q = _apply_time_filter(q, SessionLog.started_at, dt_from, dt_to)
        if user_filter:
            q = q.filter(SessionLog.user == user_filter)
        q = _apply_search_filter(q, SessionLog.details, search)
        sessions = q.order_by(SessionLog.started_at.desc()).limit(limit).all()
        return {"items": [_session_dict(s) for s in sessions]}


@router.get("/actions")
def api_actions(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    user_filter: Optional[str] = Query(None, alias="user"),
    event_type: Optional[str] = Query(None, alias="event_type"),
    search: Optional[str] = Query(None),
    limit: int = Query(400, ge=1, le=2000),
    user: str = Depends(get_current_username),
):
    dt_from = _parse_dt(date_from)
    dt_to = _parse_dt(date_to)

    with session_scope() as db:
        q = db.query(ActionLog).join(SessionLog, SessionLog.id == ActionLog.session_id)
        q = _apply_time_filter(q, ActionLog.created_at, dt_from, dt_to)
        if user_filter:
            q = q.filter(SessionLog.user == user_filter)
        if event_type:
            q = q.filter(ActionLog.name == event_type)
        if search:
            pattern = f"%{search}%"
            q = q.filter(
                or_(
                    cast(ActionLog.payload, String).ilike(pattern),
                    cast(ActionLog.name, String).ilike(pattern),
                )
            )
        actions = q.order_by(ActionLog.created_at.desc()).limit(limit).all()
        return {"items": [_action_dict(a) for a in actions]}


@router.get("/full")
def api_full(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    user_filter: Optional[str] = Query(None, alias="user"),
    event_type: Optional[str] = Query(None, alias="event_type"),
    search: Optional[str] = Query(None),
    limit: int = Query(400, ge=1, le=2000),
    user: str = Depends(get_current_username),
):
    dt_from = _parse_dt(date_from)
    dt_to = _parse_dt(date_to)

    with session_scope() as db:
        sessions_q = db.query(SessionLog)
        sessions_q = _apply_time_filter(sessions_q, SessionLog.started_at, dt_from, dt_to)
        if user_filter:
            sessions_q = sessions_q.filter(SessionLog.user == user_filter)
        sessions = (
            sessions_q.order_by(SessionLog.started_at.desc()).limit(limit).all()
        )

        actions_q = db.query(ActionLog, SessionLog.user).join(SessionLog, SessionLog.id == ActionLog.session_id)
        actions_q = _apply_time_filter(actions_q, ActionLog.created_at, dt_from, dt_to)
        if user_filter:
            actions_q = actions_q.filter(SessionLog.user == user_filter)
        if event_type:
            actions_q = actions_q.filter(ActionLog.name == event_type)
        if search:
            pattern = f"%{search}%"
            actions_q = actions_q.filter(
                or_(
                    cast(ActionLog.payload, String).ilike(pattern),
                    cast(ActionLog.name, String).ilike(pattern),
                )
            )
        actions = actions_q.all()

    events: List[Dict[str, Any]] = []

    for session in sessions:
        events.append(
            {
                "time": session.started_at,
                "type": "session_started",
                "user": session.user,
                "session_id": session.id,
                "payload": session.details or {},
            }
        )
        if session.finished_at:
            events.append(
                {
                    "time": session.finished_at,
                    "type": "session_finished",
                    "user": session.user,
                    "session_id": session.id,
                    "payload": {
                        "result": session.result,
                        **(session.details or {}),
                    },
                }
            )

    for action, user_name in actions:
        events.append(
            {
                "time": action.created_at,
                "type": action.name,
                "user": user_name,
                "session_id": action.session_id,
                "payload": action.payload or {},
            }
        )

    if event_type:
        events = [e for e in events if e["type"] == event_type]
    if search:
        lowered = search.lower()
        events = [
            e
            for e in events
            if lowered in str(e.get("payload", "")).lower()
            or lowered in str(e.get("user", "")).lower()
            or lowered in str(e.get("type", "")).lower()
        ]

    events.sort(key=lambda x: x["time"] or dt.datetime.min.replace(tzinfo=dt.timezone.utc), reverse=True)
    return {"items": events[:limit], "count": len(events)}


@router.get("/session/{session_id}")
def api_session_details(
    session_id: int,
    limit_flows: int = Query(10, ge=1, le=200),
    user: str = Depends(get_current_username),
):
    with session_scope() as db:
        session_obj = db.get(SessionLog, session_id)
        if session_obj is None:
            raise HTTPException(status_code=404, detail="Session not found")

        actions = (
            db.query(ActionLog)
            .filter(ActionLog.session_id == session_id)
            .order_by(ActionLog.created_at.desc())
            .all()
        )

        flow_query = db.query(Flow).order_by(Flow.ts.desc())
        if session_obj.started_at:
            flow_query = flow_query.filter(Flow.ts >= session_obj.started_at)
        if session_obj.finished_at:
            flow_query = flow_query.filter(Flow.ts <= session_obj.finished_at)
        flows = flow_query.limit(limit_flows).all()

        return {
            "session": _session_dict(session_obj),
            "actions": [_action_dict(a) for a in actions],
            "flows": [_flow_dict(f) for f in flows],
        }


@router.get("/users")
def api_users(user: str = Depends(get_current_username)):
    with session_scope() as db:
        names = db.query(SessionLog.user).group_by(SessionLog.user).all()
    return {"items": [row[0] for row in names if row[0]]}
