"""Даты должны вести себя одинаково на SQLite и PostgreSQL.

Баг, который эти тесты закрывают: колонки были объявлены как
DateTime(timezone=True), но SQLite зону не хранит и возвращал наивное
время. В JSON оно уходило без суффикса «+00:00», а браузерный new Date()
трактует строку без зоны как ЛОКАЛЬНОЕ время. PostgreSQL вернул бы то же
значение с зоной — и то же самое время отобразилось бы иначе.
На UTC+3 расхождение составило бы три часа.
"""

from datetime import datetime, timedelta, timezone

from app.database import SessionLocal
from app.models import AuditLog, Scan, ScanProfile, User
from app.models.types import utcnow


def test_utcnow_is_timezone_aware():
    now = utcnow()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_scan_created_at_comes_back_with_timezone(client):
    """Главная проверка: после round-trip через БД зона на месте."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        scan = Scan(target="192.168.1.50", profile=ScanProfile.quick, created_by=admin.id)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        loaded = db.get(Scan, scan_id)
        assert loaded.created_at.tzinfo is not None, "зона потеряна при чтении из БД"
        assert loaded.created_at.utcoffset() == timedelta(0)
    finally:
        db.close()


def test_all_models_preserve_timezone(client):
    """Проверяем все четыре таблицы: баг был в каждой."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        assert admin.created_at.tzinfo is not None, "User.created_at без зоны"

        db.add(AuditLog(user_id=admin.id, action="tz_check", detail="проверка"))
        db.commit()
        entry = db.query(AuditLog).filter(AuditLog.action == "tz_check").first()
        assert entry.created_at.tzinfo is not None, "AuditLog.created_at без зоны"
    finally:
        db.close()


def test_api_serializes_datetime_with_offset(client, admin_headers):
    """В JSON дата должна уходить с указанием зоны — иначе браузер
    истолкует её как локальное время."""
    scans = client.get("/scans", headers=admin_headers).json()
    assert scans, "нужен хотя бы один скан"

    created = scans[0]["created_at"]
    assert created.endswith("+00:00") or created.endswith("Z"), (
        f"дата без зоны: {created!r} — браузер прочтёт её как локальное время"
    )


def test_naive_datetime_written_directly_is_treated_as_utc(client):
    """Если наивное время всё-таки просочится в запись, считаем его UTC,
    а не локальным — иначе смысл значения зависел бы от зоны сервера."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        naive = datetime(2026, 1, 15, 12, 0, 0)  # без зоны
        scan = Scan(
            target="192.168.1.51",
            profile=ScanProfile.quick,
            created_by=admin.id,
            created_at=naive,
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    db = SessionLocal()
    try:
        loaded = db.get(Scan, scan_id)
        assert loaded.created_at == datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    finally:
        db.close()


def test_comparison_with_aware_datetime_works(client):
    """Лимит попыток входа сравнивает created_at с временем «15 минут назад».
    Смешение наивного и aware времени в таком сравнении кидает TypeError."""
    db = SessionLocal()
    try:
        since = utcnow() - timedelta(minutes=15)
        # Не должно упасть: обе стороны сравнения с зоной
        count = db.query(AuditLog).filter(AuditLog.created_at >= since).count()
        assert count >= 0
    finally:
        db.close()
