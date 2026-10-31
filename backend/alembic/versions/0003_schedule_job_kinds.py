"""allow AI and EPSS job kinds in schedules

Revision ID: 0003_schedule_job_kinds
Revises: e13eaf85ab32
Create Date: 2026-10-31 08:10:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003_schedule_job_kinds"
down_revision: str | None = "e13eaf85ab32"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD = "('SCAN','SYNC_OSV','SYNC_NVD','SYNC_KEV')"
_NEW = (
    "('SCAN','SYNC_OSV','SYNC_NVD','SYNC_KEV','SYNC_EPSS',"
    "'AI_RISK','AI_INVESTIGATE','AI_REMEDIATE','AI_VERIFY')"
)
# Pass the bare name: the metadata naming convention prefixes ck_<table>_.
CONSTRAINT = "schedule_kind"


def upgrade() -> None:
    op.drop_constraint(CONSTRAINT, "schedules", type_="check")
    op.create_check_constraint(CONSTRAINT, "schedules", f"kind IN {_NEW}")


def downgrade() -> None:
    op.execute("DELETE FROM schedules WHERE kind NOT IN " + _OLD)
    op.drop_constraint(CONSTRAINT, "schedules", type_="check")
    op.create_check_constraint(CONSTRAINT, "schedules", f"kind IN {_OLD}")
