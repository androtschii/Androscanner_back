"""Тесты постановки и выполнения задач сканирования.

Redis здесь не нужен: диспетчер проверяется моками, а тело задачи —
напрямую, с замоканным nmap.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.database import SessionLocal
from app.models import AllowedScope, Scan, ScanProfile, ScanStatus, User
from app.scanner import ScannerError
from app.tasks.runner import dispatch_scan, execute_scan


@pytest.fixture
def scan_id(client):
    """Создаёт скан прямо в БД и отдаёт его id."""
    db = SessionLocal()
    try:
        if not db.query(AllowedScope).filter(AllowedScope.cidr == "192.168.1.0/24").first():
            db.add(AllowedScope(cidr="192.168.1.0/24", description="test"))
            db.commit()
        admin = db.query(User).filter(User.username == "admin").first()
        scan = Scan(target="192.168.1.10", profile=ScanProfile.quick, created_by=admin.id)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan.id
    finally:
        db.close()


def _reload(scan_id: int) -> Scan:
    db = SessionLocal()
    try:
        return db.get(Scan, scan_id)
    finally:
        db.close()


# ── диспетчер ──


def test_dispatch_uses_background_tasks_when_celery_disabled():
    bg = MagicMock()
    with patch("app.tasks.runner.settings") as cfg:
        cfg.use_celery = False
        dispatch_scan(42, bg)
    bg.add_task.assert_called_once_with(execute_scan, 42)


def test_dispatch_uses_celery_when_enabled():
    bg = MagicMock()
    with patch("app.tasks.runner.settings") as cfg:
        cfg.use_celery = True
        with patch("app.tasks.runner.run_scan") as task:
            dispatch_scan(42, bg)
    task.delay.assert_called_once_with(42)
    bg.add_task.assert_not_called()


# ── тело задачи ──


def test_execute_scan_marks_done_and_stores_result(scan_id):
    payload = {"profile": "quick", "hosts": [], "stats": {"hosts_up": 0}}
    with patch("app.tasks.runner.run_nmap_scan", return_value=payload):
        execute_scan(scan_id)

    scan = _reload(scan_id)
    assert scan.status == ScanStatus.done
    assert json.loads(scan.result)["profile"] == "quick"


def test_execute_scan_marks_failed_on_scanner_error(scan_id):
    with patch("app.tasks.runner.run_nmap_scan", side_effect=ScannerError("нет прав")):
        execute_scan(scan_id)

    scan = _reload(scan_id)
    assert scan.status == ScanStatus.failed
    assert json.loads(scan.result)["error"] == "нет прав"


def test_execute_scan_marks_failed_when_scope_rejects(scan_id):
    """Движок отбил цель по allowed-scope — скан должен стать failed, а не зависнуть."""
    with patch(
        "app.tasks.runner.run_nmap_scan",
        side_effect=HTTPException(status_code=403, detail="Цель вне разрешённого диапазона"),
    ):
        execute_scan(scan_id)

    scan = _reload(scan_id)
    assert scan.status == ScanStatus.failed
    assert "вне разрешённого" in json.loads(scan.result)["error"]


def test_execute_scan_never_leaves_scan_running(scan_id):
    """Даже неожиданная ошибка не должна оставить скан в running навсегда."""
    with patch("app.tasks.runner.run_nmap_scan", side_effect=RuntimeError("что-то пошло не так")):
        execute_scan(scan_id)

    scan = _reload(scan_id)
    assert scan.status == ScanStatus.failed
    assert "Непредвиденная ошибка" in json.loads(scan.result)["error"]


def test_execute_scan_ignores_missing_scan():
    """Скан удалили, пока задача ждала в очереди — не должно падать."""
    execute_scan(999999)
