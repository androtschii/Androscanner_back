"""unique canonical cidr in allowed scopes

Revision ID: ac4849b571d7
Revises: e435d66f0277
Create Date: 2026-09-11

Приводит cidr к каноническому виду и запрещает дубликаты.

Зачем: 192.168.1.77/24 и 192.168.1.0/24 — одна и та же сеть, но хранились
как разные строки, и одну сеть можно было добавить сколько угодно раз.
Последствие проверялось: админ удаляет запись, считая, что отозвал доступ,
а оставшийся дубликат продолжает его разрешать. Для инструмента, чья
главная защита — белый список, «отзыв не отзывает» недопустимо.

Миграция сначала канонизирует значения и схлопывает дубликаты (оставляя
запись с наименьшим id), и только потом ставит уникальный индекс —
иначе индекс не создался бы на существующих данных.
"""

import ipaddress
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "ac4849b571d7"
down_revision: Union[str, Sequence[str], None] = "e435d66f0277"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT id, cidr FROM allowed_scopes ORDER BY id")
    ).fetchall()

    seen: dict[str, int] = {}
    for row_id, cidr in rows:
        try:
            canonical = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            # Мусорное значение: канонизировать нечего, удаляем —
            # проверка scope его всё равно никогда не пропустит
            bind.execute(
                sa.text("DELETE FROM allowed_scopes WHERE id = :id"), {"id": row_id}
            )
            continue

        if canonical in seen:
            # Дубликат: оставляем запись с меньшим id, эту убираем
            bind.execute(
                sa.text("DELETE FROM allowed_scopes WHERE id = :id"), {"id": row_id}
            )
            continue

        seen[canonical] = row_id
        if canonical != cidr:
            bind.execute(
                sa.text("UPDATE allowed_scopes SET cidr = :c WHERE id = :id"),
                {"c": canonical, "id": row_id},
            )

    op.create_index(
        "ix_allowed_scopes_cidr", "allowed_scopes", ["cidr"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_allowed_scopes_cidr", table_name="allowed_scopes")
    # Канонизацию не откатываем: исходные написания не сохранялись,
    # да и вернуть 192.168.1.0/24 обратно в 192.168.1.77/24 было бы
    # ухудшением, а не откатом.
