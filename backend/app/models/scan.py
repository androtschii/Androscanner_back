import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class ScanProfile(str, enum.Enum):
    discovery = "discovery"   # только живые хосты
    quick = "quick"           # top-ports
    full = "full"             # полный скан


class AllowedScope(Base):
    """Разрешённые для сканирования диапазоны. Только свои сети!"""
    __tablename__ = "allowed_scopes"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64))  # напр. 192.168.1.0/24
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(128))
    profile: Mapped[ScanProfile] = mapped_column(Enum(ScanProfile), default=ScanProfile.quick)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    result: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON с результатом
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class AuditLog(Base):
    """Кто / что / когда. Видят только админы, рядовые не удаляют."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    detail: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
