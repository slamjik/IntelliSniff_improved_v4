"""Database models for Traffic Analyzer."""

from __future__ import annotations

from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Float,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


# ============================================================
# Base
# ============================================================

class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ============================================================
# Session Logging Models (sessions + actions)
# ============================================================

class SessionLog(Base):
    """
    Represents a high-level execution session.
    Example:
        - запуск задачи
        - ML анализ
        - фоновая обработка
    """

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user: Mapped[str] = mapped_column(String(64), nullable=False)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )

    result: Mapped[Optional[str]] = mapped_column(Text())
    details: Mapped[Optional[dict]] = mapped_column(JSONB)

    # Relation: one session → many actions
    actions: Mapped[List["ActionLog"]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ActionLog.created_at",
    )


class ActionLog(Base):
    """
    Represents an action performed inside a session.
    Example:
        - load_data
        - analyze
        - ping
    """

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    payload: Mapped[Optional[dict]] = mapped_column(JSONB)

    # Back reference to SessionLog
    session: Mapped[SessionLog] = relationship(back_populates="actions")


# ============================================================
# Flow Model (PostgreSQL version of old SQLite storage)
# ============================================================

class Flow(Base):
    """
    Represents a network flow stored in PostgreSQL.
    This replaces the old SQLite table "flows".
    """

    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # timestamp of the flow
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    iface: Mapped[Optional[str]] = mapped_column(String(128))

    # IPs and ports
    src: Mapped[str] = mapped_column(String(128), nullable=False)
    dst: Mapped[str] = mapped_column(String(128), nullable=False)
    sport: Mapped[Optional[int]] = mapped_column(Integer)
    dport: Mapped[Optional[int]] = mapped_column(Integer)

    proto: Mapped[Optional[str]] = mapped_column(String(32))

    packets: Mapped[Optional[int]] = mapped_column(Integer)
    bytes: Mapped[Optional[int]] = mapped_column(Integer)

    # ML fields
    label: Mapped[Optional[str]] = mapped_column(String(64))
    label_name: Mapped[Optional[str]] = mapped_column(String(64))
    score: Mapped[Optional[float]] = mapped_column(Float)

    # JSON summary
    summary: Mapped[Optional[dict]] = mapped_column(JSONB)
