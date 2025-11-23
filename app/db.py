"""Database configuration and session utilities."""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    connect_args=connect_args,
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,  # ← ФИКС
    future=True
)


def ensure_flow_schema() -> None:
    """Ensure the ``flows`` table matches the ORM definition.

    This is a lightweight runtime safeguard for deployments where Alembic
    migrations haven't been executed yet. Missing columns are added with the
    correct types so the API can query without crashing.
    """

    from app.models import Flow  # imported lazily to avoid circular imports

    bind = engine
    inspector = sa.inspect(bind)

    json_type = (
        sa.dialects.postgresql.JSONB(astext_type=sa.Text())
        if bind.dialect.name == "postgresql"
        else sa.JSON()
    )

    expected_columns = [
        sa.Column("task_attack", sa.String(length=32), nullable=True),
        sa.Column("attack_confidence", sa.Float(), nullable=True),
        sa.Column("attack_version", sa.String(length=32), nullable=True),
        sa.Column("attack_explanation", json_type, nullable=True),
        sa.Column("task_vpn", sa.String(length=32), nullable=True),
        sa.Column("vpn_confidence", sa.Float(), nullable=True),
        sa.Column("vpn_version", sa.String(length=32), nullable=True),
        sa.Column("vpn_explanation", json_type, nullable=True),
        sa.Column("task_anomaly", sa.String(length=32), nullable=True),
        sa.Column("anomaly_confidence", sa.Float(), nullable=True),
        sa.Column("anomaly_version", sa.String(length=32), nullable=True),
        sa.Column("anomaly_explanation", json_type, nullable=True),
        sa.Column("summary", json_type, nullable=True),
    ]

    with bind.begin() as connection:
        if not inspector.has_table("flows"):
            Flow.__table__.create(bind=connection, checkfirst=True)
            return

        existing = {col["name"] for col in inspector.get_columns("flows")}
        for col in expected_columns:
            if col.name not in existing:
                connection.execute(sa.schema.AddColumn("flows", col.copy()))



def get_db() -> Generator[Session, None, None]:
    """Yield a database session, ensuring it is closed afterwards."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Provide a transactional scope for database operations."""
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.close()
