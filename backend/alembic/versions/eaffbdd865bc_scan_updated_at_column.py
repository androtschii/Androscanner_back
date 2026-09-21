"""scan updated_at column

Revision ID: eaffbdd865bc
Revises: c7f2a91d5e3b
Create Date: 2026-09-21

Добавляет scans.updated_at — момент последней смены статуса. created_at
сам по себе показывает только когда скан поставили в очередь, а не сколько
он шёл; без второй метки времени нельзя посчитать длительность для CSV
и карточки скана.

Обычный add_column, без enum — ловушка с ALTER TYPE здесь не нужна,
autogenerate тут ведёт себя одинаково на обеих базах.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "eaffbdd865bc"
down_revision: Union[str, Sequence[str], None] = "c7f2a91d5e3b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "updated_at")
