"""Create or align flows table with widened string columns"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "202407171200"
down_revision = "202311071421"
branch_labels = None
depends_on = None


def _json_type(bind):
    if bind.dialect.name == "postgresql":
        return postgresql.JSONB(astext_type=sa.Text())
    return sa.JSON()


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
            sa.Column("summary", json_type, nullable=True),
        )
        op.create_index("ix_flows_ts", "flows", ["ts"])
        op.create_index("ix_flows_id", "flows", ["id"])
        return

    # Existing table: widen columns to match ORM expectations
    op.alter_column(
        "flows",
        "iface",
        type_=sa.String(length=128),
        existing_nullable=True,
    )
    op.alter_column(
        "flows",
        "src",
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    op.alter_column(
        "flows",
        "dst",
        type_=sa.String(length=128),
        existing_nullable=False,
    )
    op.alter_column(
        "flows",
        "proto",
        type_=sa.String(length=32),
        existing_nullable=True,
    )
    op.alter_column(
        "flows",
        "label",
        type_=sa.String(length=64),
        existing_nullable=True,
    )
    op.alter_column(
        "flows",
        "label_name",
        type_=sa.String(length=64),
        existing_nullable=True,
    )
    op.alter_column(
        "flows",
        "summary",
        type_=json_type,
        existing_nullable=True,
    )



def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("flows"):
        return

    # Revert lengths to conservative defaults
    try:
        op.alter_column("flows", "iface", type_=sa.String(length=32), existing_nullable=True)
        op.alter_column("flows", "src", type_=sa.String(length=64), existing_nullable=False)
        op.alter_column("flows", "dst", type_=sa.String(length=64), existing_nullable=False)
        op.alter_column("flows", "proto", type_=sa.String(length=16), existing_nullable=True)
        op.alter_column("flows", "label", type_=sa.String(length=32), existing_nullable=True)
        op.alter_column("flows", "label_name", type_=sa.String(length=32), existing_nullable=True)
    except Exception:
        # Schema may already be at previous size or database may not support shrinking
        pass

    try:
        op.drop_index("ix_flows_ts", table_name="flows")
        op.drop_index("ix_flows_id", table_name="flows")
    except Exception:
        pass

    try:
        op.drop_table("flows")
    except Exception:
        pass
