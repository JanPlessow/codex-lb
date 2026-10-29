"""add orca terminal handle to request logs"""

import sqlalchemy as sa
from alembic import op

revision = "20260914_000000_add_orca_terminal_handle"
down_revision = "20260816_000000_add_model_source_embeddings"


def upgrade():
    bind = op.get_bind()
    cols = {c["name"] for c in sa.inspect(bind).get_columns("request_logs")}
    if "orca_terminal_handle" not in cols:
        op.add_column("request_logs", sa.Column("orca_terminal_handle", sa.String(), nullable=True))


def downgrade():
    op.drop_column("request_logs", "orca_terminal_handle")
