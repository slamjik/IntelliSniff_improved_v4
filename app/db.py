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
    """Ensure the ``flows`` table matches the ORM definition (SQLAlchemy 2.x safe)."""

    from app.models import Base, Flow  # imported lazily to avoid circular imports

    bind = engine
    inspector = sa.inspect(bind)
    dialect_name = bind.dialect.name

    def _render_sql_type(col_type: sa.types.TypeEngine) -> str:
        if isinstance(col_type, (sa.JSON, sa.dialects.postgresql.JSONB)):
            return "JSONB" if dialect_name == "postgresql" else "JSON"
        if isinstance(col_type, sa.Float):
            return "DOUBLE PRECISION"
        if isinstance(col_type, sa.Integer):
            return "INTEGER"
        if isinstance(col_type, (sa.String, sa.Text)):
            return "TEXT"
        if isinstance(col_type, sa.DateTime):
            if dialect_name == "postgresql":
                return "TIMESTAMP WITH TIME ZONE" if getattr(col_type, "timezone", False) else "TIMESTAMP WITHOUT TIME ZONE"
            return "TIMESTAMP"
        # Fallback to dialect compilation for any unexpected type
        return col_type.compile(dialect=bind.dialect)

    # Create the table entirely if it does not yet exist
    if not inspector.has_table("flows"):
        Base.metadata.create_all(bind=bind, tables=[Flow.__table__])
        return

    existing = {col["name"] for col in inspector.get_columns("flows")}
    missing_columns = [col for col in Flow.__table__.columns if col.name not in existing]

    if not missing_columns:
        return

    with bind.begin() as connection:
        for col in missing_columns:
            sql_type = _render_sql_type(col.type)
            ddl = f'ALTER TABLE flows ADD COLUMN "{col.name}" {sql_type}'
            connection.execute(sa.text(ddl))




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
