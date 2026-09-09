"""Типы колонок, одинаково ведущие себя на SQLite и PostgreSQL."""

from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    """Текущее время в UTC, с зоной. Единая точка — чтобы никто случайно
    не записал наивное время через datetime.now()."""
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """DateTime, который ВСЕГДА возвращает время с зоной UTC.

    Зачем: SQLite не хранит tzinfo. Записав время с зоной, на чтении
    получаешь наивное — и оно уходит в JSON как «2026-09-04T11:21:25»,
    без суффикса. PostgreSQL с timestamptz вернёт «...+00:00».

    Браузерный `new Date()` трактует эти строки по-разному: без зоны —
    как локальное время, с зоной — как UTC. То есть один и тот же скан
    показывал бы разное время в зависимости от того, какая под ним база.
    На UTC+3 расхождение — три часа.

    Тип приводит значение к UTC на записи и навешивает зону на чтении,
    поэтому поведение одинаково на обеих базах. Схему это не меняет:
    под капотом та же колонка DateTime(timezone=True), миграция не нужна.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            # Наивное время считаем UTC: весь код пишет через utcnow()
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
