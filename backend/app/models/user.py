import enum
from datetime import datetime

from sqlalchemy import Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.types import UTCDateTime, utcnow


class Role(str, enum.Enum):
    """Три роли с разными привилегиями."""
    admin = "admin"      # всё: пользователи, scope, запуск/удаление сканов, логи
    analyst = "analyst"  # запуск сканов, просмотр, отчёты
    viewer = "viewer"    # только чтение


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow
    )
