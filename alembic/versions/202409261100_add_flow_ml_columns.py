"""Add ML detail columns to flows table"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "202409261100"
down_revision = "202407171200"
branch_labels = None
depends_on = None


def _json_type(bind):
    if bind.dialect.name == "postgresql":
        return postgresql.JSONB(astext_type=sa.Text())
    return sa.JSON()


def _existing_columns(inspector, table_name: str) -> set[str]:
    try:
        return {col["name"] for col in inspector.get_columns(table_name)}
    except sa.exc.NoSuchTableError:
        return set()


def _add_column_if_missing(columns: set[str], name: str, column: sa.Column) -> None:
    if name not in columns:
        op.add_column("flows", column)


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    json_type = _json_type(bind)

    if not insp.has_table("flows"):
        op.create_table(
            "flows",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
            sa.Column("iface", sa.String(length=128), nullable=True),
            sa.Column("src", sa.String(length=128), nullable=False),
            sa.Column("dst", sa.String(length=128), nullable=False),
            sa.Column("sport", sa.Integer(), nullable=True),
            sa.Column("dport", sa.Integer(), nullable=True),
            sa.Column("proto", sa.String(length=32), nullable=True),
            sa.Column("packets", sa.Integer(), nullable=True),
            sa.Column("bytes", sa.Integer(), nullable=True),
            sa.Column("label", sa.String(length=64), nullable=True),
            sa.Column("label_name", sa.String(length=64), nullable=True),
            sa.Column("score", sa.Float(), nullable=True),
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
        )
        op.create_index("ix_flows_ts", "flows", ["ts"])
        op.create_index("ix_flows_id", "flows", ["id"])
        return

    columns = _existing_columns(insp, "flows")

    _add_column_if_missing(columns, "task_attack", sa.Column("task_attack", sa.String(length=32), nullable=True))
    _add_column_if_missing(columns, "attack_confidence", sa.Column("attack_confidence", sa.Float(), nullable=True))
    _add_column_if_missing(columns, "attack_version", sa.Column("attack_version", sa.String(length=32), nullable=True))
    _add_column_if_missing(columns, "attack_explanation", sa.Column("attack_explanation", json_type, nullable=True))

    _add_column_if_missing(columns, "task_vpn", sa.Column("task_vpn", sa.String(length=32), nullable=True))
    _add_column_if_missing(columns, "vpn_confidence", sa.Column("vpn_confidence", sa.Float(), nullable=True))
    _add_column_if_missing(columns, "vpn_version", sa.Column("vpn_version", sa.String(length=32), nullable=True))
    _add_column_if_missing(columns, "vpn_explanation", sa.Column("vpn_explanation", json_type, nullable=True))

    _add_column_if_missing(columns, "task_anomaly", sa.Column("task_anomaly", sa.String(length=32), nullable=True))
    _add_column_if_missing(columns, "anomaly_confidence", sa.Column("anomaly_confidence", sa.Float(), nullable=True))
    _add_column_if_missing(columns, "anomaly_version", sa.Column("anomaly_version", sa.String(length=32), nullable=True))
    _add_column_if_missing(columns, "anomaly_explanation", sa.Column("anomaly_explanation", json_type, nullable=True))

    if "summary" not in columns:
        op.add_column("flows", sa.Column("summary", json_type, nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("flows"):
        return

    columns = _existing_columns(insp, "flows")
    for name in [
        "anomaly_explanation",
        "anomaly_version",
        "anomaly_confidence",
        "task_anomaly",
        "vpn_explanation",
        "vpn_version",
        "vpn_confidence",
        "task_vpn",
        "attack_explanation",
        "attack_version",
        "attack_confidence",
        "task_attack",
    ]:
        if name in columns:
            op.drop_column("flows", name)

    # summary column left intact to preserve data
