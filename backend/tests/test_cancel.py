"""Тесты отмены скана."""

import json
from unittest.mock import patch

from app.database import SessionLocal
from app.models import Scan, ScanProfile, ScanStatus, User
from app.tasks.runner import execute_scan


def _make_scan(status=ScanStatus.queued, owner="admin", task_id=None):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == owner).first()
        scan = Scan(
            target="192.168.1.60",
            profile=ScanProfile.quick,
            status=status,
            created_by=user.id,
            celery_task_id=task_id,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan.id
    finally:
        db.close()


def _status(scan_id):
    db = SessionLocal()
    try:
        return db.get(Scan, scan_id).status
    finally:
        db.close()


# ── базовое поведение ──


def test_queued_scan_can_be_cancelled(client, admin_headers):
    scan_id = _make_scan(ScanStatus.queued)
    r = client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"


def test_running_scan_can_be_cancelled(client, admin_headers):
    scan_id = _make_scan(ScanStatus.running)
    r = client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)
    assert r.status_code == 200
    assert _status(scan_id) == ScanStatus.cancelled


def test_cancel_is_recorded_in_audit(client, admin_headers):
    scan_id = _make_scan(ScanStatus.queued)
    client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)

    audit = client.get("/audit?action=cancel_scan", headers=admin_headers).json()["items"]
    assert any(e["detail"] == str(scan_id) for e in audit)


def test_cancel_404_for_missing_scan(client, admin_headers):
    assert client.post("/scans/999999/cancel", headers=admin_headers).status_code == 404


# ── уже завершённые ──


def test_finished_scan_cannot_be_cancelled(client, admin_headers):
    """Отменять готовый скан бессмысленно — 409, а не тихое согласие."""
    scan_id = _make_scan(ScanStatus.done)
    r = client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)
    assert r.status_code == 409
    assert "уже завершён" in r.json()["detail"]
    assert _status(scan_id) == ScanStatus.done


def test_failed_scan_cannot_be_cancelled(client, admin_headers):
    scan_id = _make_scan(ScanStatus.failed)
    assert client.post(f"/scans/{scan_id}/cancel", headers=admin_headers).status_code == 409


def test_double_cancel_rejected(client, admin_headers):
    scan_id = _make_scan(ScanStatus.queued)
    assert client.post(f"/scans/{scan_id}/cancel", headers=admin_headers).status_code == 200
    assert client.post(f"/scans/{scan_id}/cancel", headers=admin_headers).status_code == 409


# ── права ──


def test_viewer_cannot_cancel_others_scan(client, viewer_headers):
    scan_id = _make_scan(ScanStatus.queued, owner="admin")
    r = client.post(f"/scans/{scan_id}/cancel", headers=viewer_headers)
    assert r.status_code == 403
    assert _status(scan_id) == ScanStatus.queued


def test_admin_can_cancel_any_scan(client, admin_headers, viewer_headers):
    """У админа право на чужие сканы есть — он и удалять их может."""
    scan_id = _make_scan(ScanStatus.queued, owner="test_viewer")
    assert client.post(f"/scans/{scan_id}/cancel", headers=admin_headers).status_code == 200


# ── отзыв задачи Celery ──


def test_celery_task_is_revoked_when_present(client, admin_headers):
    scan_id = _make_scan(ScanStatus.running, task_id="task-abc-123")

    with patch("app.api.scans.revoke_scan_task") as revoke:
        client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)

    revoke.assert_called_once_with("task-abc-123")


def test_no_revoke_attempt_without_task_id(client, admin_headers):
    """В режиме BackgroundTasks отзывать нечего — задача проверит статус сама."""
    scan_id = _make_scan(ScanStatus.queued, task_id=None)

    with patch("app.api.scans.revoke_scan_task") as revoke:
        client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)

    revoke.assert_not_called()


def test_cancel_succeeds_even_if_broker_unreachable(client, admin_headers):
    """Недоступный брокер не должен мешать пометить скан отменённым."""
    scan_id = _make_scan(ScanStatus.running, task_id="task-xyz")

    with patch("app.api.scans.revoke_scan_task", return_value=False):
        r = client.post(f"/scans/{scan_id}/cancel", headers=admin_headers)

    assert r.status_code == 200
    assert _status(scan_id) == ScanStatus.cancelled


# ── взаимодействие задачи с отменой ──


def test_cancelled_scan_is_not_executed(client):
    """Скан отменили, пока задача ждала в очереди — сканировать не должны.
    Без этой проверки отмена «queued» ничего бы не давала."""
    scan_id = _make_scan(ScanStatus.cancelled)

    with patch("app.tasks.runner.run_nmap_scan") as scan_fn:
        execute_scan(scan_id)

    scan_fn.assert_not_called()
    assert _status(scan_id) == ScanStatus.cancelled


def test_cancel_during_run_keeps_cancelled_status(client, admin_headers):
    """Отмена во время скана: результат сохраняем — работа уже сделана, —
    но статус не перебиваем на done."""
    scan_id = _make_scan(ScanStatus.queued)

    def scan_and_cancel(*_args, **_kwargs):
        # Имитируем отмену, случившуюся пока nmap работал
        db = SessionLocal()
        try:
            db.get(Scan, scan_id).status = ScanStatus.cancelled
            db.commit()
        finally:
            db.close()
        return {"profile": "quick", "hosts": [], "stats": {"hosts_up": 0}}

    with patch("app.tasks.runner.run_nmap_scan", side_effect=scan_and_cancel):
        execute_scan(scan_id)

    assert _status(scan_id) == ScanStatus.cancelled

    db = SessionLocal()
    try:
        # результат всё же записан: выбрасывать проделанную работу незачем
        assert json.loads(db.get(Scan, scan_id).result)["profile"] == "quick"
    finally:
        db.close()


def test_normal_scan_still_completes(client):
    """Контроль: обычный скан по-прежнему доходит до done."""
    scan_id = _make_scan(ScanStatus.queued)

    with patch(
        "app.tasks.runner.run_nmap_scan",
        return_value={"profile": "quick", "hosts": [], "stats": {}},
    ):
        execute_scan(scan_id)

    assert _status(scan_id) == ScanStatus.done


# ── гонка при постановке в очередь ──


def test_task_id_saved_before_queueing(client):
    """Раньше delay() публиковал задачу, и только потом id сохранялся в базу.
    В этом промежутке воркер уже мог взять задачу, а запрос на отмену —
    увидеть celery_task_id = None и ничего не отозвать: скан помечался
    отменённым, а nmap продолжал работать."""
    from unittest.mock import MagicMock, patch

    from app.tasks import runner

    scan_id = _make_scan(ScanStatus.queued)
    order = []

    def remember_queueing(*_args, **_kwargs):
        db = SessionLocal()
        try:
            # В момент постановки в очередь id уже обязан быть в базе
            order.append(db.get(Scan, scan_id).celery_task_id)
        finally:
            db.close()

    with patch.object(runner.settings, "use_celery", True):
        with patch.object(runner.run_scan, "apply_async", side_effect=remember_queueing):
            runner.dispatch_scan(scan_id, MagicMock())

    assert order and order[0] is not None, "id задачи ещё не был записан в момент постановки"


def test_dispatched_task_id_matches_stored(client):
    """Сгенерированный id должен совпасть с тем, под которым задача ушла."""
    from unittest.mock import MagicMock, patch

    from app.tasks import runner

    scan_id = _make_scan(ScanStatus.queued)
    captured = {}

    def capture(*_args, **kwargs):
        captured["task_id"] = kwargs.get("task_id")

    with patch.object(runner.settings, "use_celery", True):
        with patch.object(runner.run_scan, "apply_async", side_effect=capture):
            runner.dispatch_scan(scan_id, MagicMock())

    db = SessionLocal()
    try:
        assert db.get(Scan, scan_id).celery_task_id == captured["task_id"]
    finally:
        db.close()


def test_background_mode_does_not_set_task_id(client):
    """В режиме BackgroundTasks отзывать нечего — id не нужен."""
    from unittest.mock import MagicMock, patch

    from app.tasks import runner

    scan_id = _make_scan(ScanStatus.queued)
    bg = MagicMock()

    with patch.object(runner.settings, "use_celery", False):
        runner.dispatch_scan(scan_id, bg)

    bg.add_task.assert_called_once()
    db = SessionLocal()
    try:
        assert db.get(Scan, scan_id).celery_task_id is None
    finally:
        db.close()
