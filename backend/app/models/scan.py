import enum
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.database import Base
from app.models.types import UTCDateTime, utcnow


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"  # отменён пользователем


class ScanProfile(str, enum.Enum):
    discovery = "discovery"   # только живые хосты
    quick = "quick"           # top-ports
    full = "full"             # полный скан


class AllowedScope(Base):
    """Разрешённые для сканирования диапазоны. Только свои сети!"""
    __tablename__ = "allowed_scopes"

    id: Mapped[int] = mapped_column(primary_key=True)
    # unique: дубликаты одной сети опасны — удалив одну запись, админ
    # решил бы, что отозвал доступ, а вторая продолжала бы его разрешать.
    # Значение всегда канонизировано (192.168.1.77/24 -> 192.168.1.0/24),
    # иначе уникальность по строке ничего бы не гарантировала.
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(128))
    profile: Mapped[ScanProfile] = mapped_column(Enum(ScanProfile), default=ScanProfile.quick)
    # Индекс: список сканов всегда сортируется по дате, аналитика фильтрует по статусу
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.queued, index=True
    )
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # Идентификатор задачи Celery — нужен, чтобы её можно было отозвать.
    # Пусто, когда скан выполняется через BackgroundTasks (dev на Windows).
    celery_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON с результатом
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# Пределы длины полей журнала. Держим рядом с валидатором, чтобы
# обрезка и объявление колонки не разъехались.
ACTION_MAX = 128
DETAIL_MAX = 512


class AuditLog(Base):
    """Кто / что / когда. Видят только админы, записи не удаляются."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    # Индексы под два запроса: журнал сортируется по дате,
    # а лимит попыток входа ищет по (action, detail, created_at)
    action: Mapped[str] = mapped_column(String(ACTION_MAX), index=True)
    detail: Mapped[str] = mapped_column(String(DETAIL_MAX), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    @validates("action", "detail")
    def _truncate(self, key: str, value: str | None) -> str | None:
        """Обрезает слишком длинное значение вместо падения.

        Зачем: в detail попадает логин из формы входа, а он ничем
        не ограничен — прислать можно хоть 5000 символов. SQLite длину
        VARCHAR(n) не проверяет и сохранит как есть; PostgreSQL выдаст
        StringDataRightTruncation, и попытка входа обернётся 500.

        Валидатор на модели, а не проверка в каждом месте записи:
        иначе рано или поздно появится новый вызов AuditLog(...),
        где обрезать забудут.
        """
        if value is None:
            return value
        limit = ACTION_MAX if key == "action" else DETAIL_MAX
        if len(value) > limit:
            # Многоточие показывает, что значение урезано, а не такое короткое
            return value[: limit - 1] + "…"
        return value
