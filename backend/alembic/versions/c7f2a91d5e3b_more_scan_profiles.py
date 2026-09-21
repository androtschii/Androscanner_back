"""more scan profiles

Revision ID: c7f2a91d5e3b
Revises: ac4849b571d7
Create Date: 2026-09-21

Добавляет шесть новых значений в enum ScanProfile: ping, top1000, version,
udp, vuln, aggressive. Было 3 профиля (discovery/quick/full), стало 9 —
по образцу шаблонов сканирования Nessus.

ВАЖНО про enum и PostgreSQL — та же ловушка, что и в миграции 'scan
cancellation'. Autogenerate предложил бы alter_column с новым типом Enum:
на SQLite это безобидно (enum там VARCHAR), на PostgreSQL enum — отдельный
тип, и такой alter_column упал бы, потому что колонка ссылается на значения,
которых в новом типе ещё нет. Правильный путь — ALTER TYPE ... ADD VALUE
для каждого нового значения, что и делает эта миграция вручную.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "c7f2a91d5e3b"
down_revision: Union[str, Sequence[str], None] = "ac4849b571d7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NEW_VALUES = ["ping", "top1000", "version", "udp", "vuln", "aggressive"]


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        # ALTER TYPE ... ADD VALUE нельзя выполнить внутри одной транзакции
        # с несколькими значениями за раз в старых версиях PostgreSQL,
        # поэтому — по одному оператору. IF NOT EXISTS — чтобы повторный
        # прогон не падал.
        for value in NEW_VALUES:
            op.execute(f"ALTER TYPE scanprofile ADD VALUE IF NOT EXISTS '{value}'")
    # На SQLite профиль хранится как VARCHAR — новые значения принимаются
    # без изменения схемы, делать здесь нечего.


def downgrade() -> None:
    # Убрать значения из enum PostgreSQL штатными средствами нельзя: пришлось
    # бы пересоздавать тип и переписывать колонку. Несоразмерно для отката,
    # тем более что лишние значения никому не мешают, пока на них нет ссылок.
    pass
