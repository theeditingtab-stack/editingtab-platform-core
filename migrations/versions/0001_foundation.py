"""Empty foundation baseline: only Alembic's revision bookkeeping is created.

No domain tables belong to CORE-002. Never edit this baseline after deployment;
add new revisions when domain modeling is authorized.
"""

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
