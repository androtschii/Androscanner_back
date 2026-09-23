"""Автоматическое обнаружение аномалий: скан сравнивается с предыдущим
завершённым сканом той же цели, и если появилось что-то новое —
уведомление в Telegram (app/tasks/runner.py::_check_anomalies) и
доступный на чтение diff (GET /scans/{id}/changes).
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.database import SessionLocal
from app.models import AllowedScope, Scan, ScanProfile, ScanStatus, User
from app.tasks.runner import execute_scan


def _host(ip, ports=()):
    return {
        "ip": ip,
        "hostnames": [],
        "state": "up",
        "mac": None,
        "vendor": None,
        "os": [],
        "ports": [
            {"port": p, "protocol": "tcp", "state": "open", "service": "http"} for p in ports
        ],
    }


def _result(hosts):
    return {"profile": "quick", "hosts": hosts, "stats": {"hosts_up": len(hosts)}}


_next_host = iter(range(10, 250))


@pytest.fixture
def target_with_prior_scan():
    """Готовит allowed-scope и уже завершённый скан цели за час до «сейчас»,
    чтобы новый скан гарантированно оказался позже по created_at.

    Каждый вызов берёт свой IP (192.168.9.X) — иначе несколько тестов,
    использующих эту фикстуру, оставляли бы в общей тестовой БД сканы
    одной и той же цели, и «предыдущий скан» для одного теста мог бы
    случайно найтись из совсем другого теста.
    """
    ip = f"192.168.9.{next(_next_host)}"
    db = SessionLocal()
    try:
        if not db.query(AllowedScope).filter(AllowedScope.cidr == "192.168.9.0/24").first():
            db.add(AllowedScope(cidr="192.168.9.0/24", description="test"))
            db.commit()
        admin = db.query(User).filter(User.username == "admin").first()

        previous = Scan(
            target=ip,
            profile=ScanProfile.quick,
            status=ScanStatus.done,
            created_by=admin.id,
            created_at=datetime.now(timezone.utc) - timedelta(hours=1),
            result=json.dumps(_result([_host(ip, ports=[22])]), ensure_ascii=False),
        )
        db.add(previous)

        current = Scan(target=ip, profile=ScanProfile.quick, created_by=admin.id)
        db.add(current)
        db.commit()
        db.refresh(current)
        return current.id
    finally:
        db.close()


def _reload(scan_id):
    db = SessionLocal()
    try:
        return db.get(Scan, scan_id)
    finally:
        db.close()


# ── уведомление ──


def test_notifies_on_new_host(target_with_prior_scan):
    ip = _reload(target_with_prior_scan).target
    new_result = _result([_host(ip, ports=[22]), _host("192.168.9.250")])
    with patch("app.tasks.runner.run_nmap_scan", return_value=new_result):
        with patch("app.tasks.runner.notify_anomaly_detected") as notify:
            execute_scan(target_with_prior_scan)

    notify.assert_called_once()
    summary = notify.call_args[0][1]
    assert summary["hosts_added"] == 1


def test_notifies_on_new_open_port(target_with_prior_scan):
    ip = _reload(target_with_prior_scan).target
    new_result = _result([_host(ip, ports=[22, 80])])
    with patch("app.tasks.runner.run_nmap_scan", return_value=new_result):
        with patch("app.tasks.runner.notify_anomaly_detected") as notify:
            execute_scan(target_with_prior_scan)

    notify.assert_called_once()
    summary = notify.call_args[0][1]
    assert summary["ports_opened"] == 1


def test_silent_when_nothing_changed(target_with_prior_scan):
    ip = _reload(target_with_prior_scan).target
    same_result = _result([_host(ip, ports=[22])])
    with patch("app.tasks.runner.run_nmap_scan", return_value=same_result):
        with patch("app.tasks.runner.notify_anomaly_detected") as notify:
            execute_scan(target_with_prior_scan)

    notify.assert_not_called()


def test_silent_when_only_things_closed(target_with_prior_scan):
    """Закрывшийся порт — не аномалия: поверхность атаки не выросла."""
    ip = _reload(target_with_prior_scan).target
    smaller_result = _result([_host(ip, ports=[])])
    with patch("app.tasks.runner.run_nmap_scan", return_value=smaller_result):
        with patch("app.tasks.runner.notify_anomaly_detected") as notify:
            execute_scan(target_with_prior_scan)

    notify.assert_not_called()


def test_silent_on_first_scan_of_a_target():
    db = SessionLocal()
    try:
        if not db.query(AllowedScope).filter(AllowedScope.cidr == "192.168.9.0/24").first():
            db.add(AllowedScope(cidr="192.168.9.0/24", description="test"))
            db.commit()
        admin = db.query(User).filter(User.username == "admin").first()
        scan = Scan(target="192.168.9.253", profile=ScanProfile.quick, created_by=admin.id)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    result = _result([_host("192.168.9.253", ports=[22])])
    with patch("app.tasks.runner.run_nmap_scan", return_value=result):
        with patch("app.tasks.runner.notify_anomaly_detected") as notify:
            execute_scan(scan_id)

    notify.assert_not_called()


# ── GET /scans/{id}/changes ──


def test_changes_endpoint_returns_diff(client, admin_headers, target_with_prior_scan):
    ip = _reload(target_with_prior_scan).target
    new_result = _result([_host(ip, ports=[22, 80])])
    with patch("app.tasks.runner.run_nmap_scan", return_value=new_result):
        with patch("app.tasks.runner.notify_anomaly_detected"):
            execute_scan(target_with_prior_scan)

    r = client.get(f"/scans/{target_with_prior_scan}/changes", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body is not None
    assert body["summary"]["ports_opened"] == 1


def test_changes_endpoint_null_on_first_scan(client, admin_headers):
    db = SessionLocal()
    try:
        if not db.query(AllowedScope).filter(AllowedScope.cidr == "192.168.9.0/24").first():
            db.add(AllowedScope(cidr="192.168.9.0/24", description="test"))
            db.commit()
        admin = db.query(User).filter(User.username == "admin").first()
        scan = Scan(
            target="192.168.9.254",
            profile=ScanProfile.quick,
            status=ScanStatus.done,
            created_by=admin.id,
            result=json.dumps(_result([_host("192.168.9.254")]), ensure_ascii=False),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    finally:
        db.close()

    r = client.get(f"/scans/{scan_id}/changes", headers=admin_headers)
    assert r.status_code == 200
    assert r.json() is None


def test_changes_endpoint_null_while_pending(client, admin_headers, target_with_prior_scan):
    r = client.get(f"/scans/{target_with_prior_scan}/changes", headers=admin_headers)
    assert r.status_code == 200
    assert r.json() is None


def test_changes_endpoint_404_for_missing_scan(client, admin_headers):
    r = client.get("/scans/999999/changes", headers=admin_headers)
    assert r.status_code == 404
