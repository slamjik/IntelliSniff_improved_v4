"""Database models for session logging."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base class for all ORM models."""


class SessionLog(Base):
    """Represents a high-level execution session."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result: Mapped[Optional[str]] = mapped_column(Text())
    details: Mapped[Optional[dict]] = mapped_column(JSONB)

    actions: Mapped[list["ActionLog"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True
    )


class ActionLog(Base):
    """Represents a detailed action recorded within a session."""

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    payload: Mapped[Optional[dict]] = mapped_column(JSONB)

    session: Mapped[SessionLog] = relationship(back_populates="actions")
