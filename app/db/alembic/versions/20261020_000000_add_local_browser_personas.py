"""Local account browser ownership and OAuth route association."""

import sqlalchemy as sa
from alembic import op

revision = "20261020_000000_add_local_browser_personas"
down_revision = "20260914_000000_add_orca_terminal_handle"


def _ensure_table(name: str, *columns: sa.Column) -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(name):
        op.create_table(name, *columns)
        return
    # Legacy bootstrap and ledger recovery replay revisions over existing
    # tables. Preserve their rows, but reject an incompatible ownership schema.
    actual = {column["name"]: column for column in inspector.get_columns(name)}
    for column in columns:
        found = actual.get(column.name)
        if found is None or not isinstance(found["type"], type(column.type)) or found["nullable"] != column.nullable:
            raise RuntimeError(f"Incompatible existing {name}.{column.name}")
    primary = set(inspector.get_pk_constraint(name)["constrained_columns"])
    if primary != {column.name for column in columns if column.primary_key}:
        raise RuntimeError(f"Incompatible primary key on {name}")
    unique = {tuple(item["column_names"]) for item in inspector.get_unique_constraints(name)}
    foreign = {
        (
            tuple(item["constrained_columns"]),
            item["referred_table"],
            tuple(item["referred_columns"]),
            item["options"].get("ondelete"),
        )
        for item in inspector.get_foreign_keys(name)
    }
    for column in columns:
        if column.unique and (column.name,) not in unique:
            raise RuntimeError(f"Missing unique constraint on {name}.{column.name}")
        for key in column.foreign_keys:
            table, target = key.target_fullname.split(".")
            if ((column.name,), table, (target,), key.ondelete) not in foreign:
                raise RuntimeError(f"Missing foreign key on {name}.{column.name}")


def upgrade() -> None:
    _ensure_table(
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
    _ensure_table(
        "browser_oauth_flows",
        sa.Column("flow_id", sa.String(), primary_key=True),
        sa.Column("persona_id", sa.String(), sa.ForeignKey("browser_personas.id"), nullable=False),
        sa.Column("route_fingerprint", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("browser_oauth_flows")
    op.drop_table("browser_personas")
