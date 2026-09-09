"""scan cancellation

Revision ID: e435d66f0277
Revises: 8b04a5792219
Create Date: 2026-09-09

Добавляет:
  * scans.celery_task_id — чтобы задачу можно было отозвать
  * значение 'cancelled' в enum статусов

ВАЖНО про enum и PostgreSQL. Autogenerate предложил здесь alter_column
с новым типом Enum. На SQLite это безобидно — там enum хранится как
VARCHAR. На PostgreSQL enum это ОТДЕЛЬНЫЙ ТИП, и такой alter_column
упал бы: нельзя привести колонку к типу, в котором ещё нет нужного
значения. Правильный путь — ALTER TYPE ... ADD VALUE.

Автоматика этой разницы не видит, поэтому миграция написана вручную
и разветвлена по диалекту.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e435d66f0277"
down_revision: Union[str, Sequence[str], None] = "8b04a5792219"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("celery_task_id", sa.String(length=64), nullable=True))

    if op.get_bind().dialect.name == "postgresql":
        # PostgreSQL 12+ разрешает это внутри транзакции.
        # IF NOT EXISTS — чтобы повторный прогон не падал.
        op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'cancelled'")
    # На SQLite статус хранится как VARCHAR — новое значение принимается
    # без изменения схемы, делать здесь нечего.


def downgrade() -> None:
    op.drop_column("scans", "celery_task_id")

    # Убрать значение из enum PostgreSQL штатными средствами нельзя:
    # пришлось бы пересоздавать тип и переписывать колонку. Для отката
    # это несоразмерно, тем более что лишнее значение никому не мешает.
    # Сканы, помеченные 'cancelled', при откате останутся с ним —
    # это осознанный компромисс, а не упущение.
