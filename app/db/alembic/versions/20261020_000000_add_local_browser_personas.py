"""Local account browser ownership and OAuth route association."""

import sqlalchemy as sa
from alembic import op

revision = "20261020_000000_add_local_browser_personas"
down_revision = "20260914_000000_add_orca_terminal_handle"


def upgrade() -> None:
    op.create_table(
        "browser_personas",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id", ondelete="SET NULL"), unique=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("route_mode", sa.String(), nullable=False),
        sa.Column("route_fingerprint", sa.String(), nullable=False),
        sa.Column("enrollment_pool_id", sa.String()),
        sa.Column("relay_port", sa.Integer(), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "browser_oauth_flows",
        sa.Column("flow_id", sa.String(), primary_key=True),
        sa.Column("persona_id", sa.String(), sa.ForeignKey("browser_personas.id"), nullable=False),
        sa.Column("route_fingerprint", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("browser_oauth_flows")
    op.drop_table("browser_personas")
