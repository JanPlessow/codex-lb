"""Join the deployed local-feature and shared main histories."""

revision = "20261029_000000_merge_local_feature_history"
down_revision = (
    "20260918_000000_merge_scim_and_overflow_heads",
    "20261020_000000_add_local_browser_personas",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
