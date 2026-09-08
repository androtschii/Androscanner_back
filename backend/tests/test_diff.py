"""Тесты сравнения сканов."""

import json

from app.analytics import diff_results
from app.database import SessionLocal
from app.models import Scan, ScanProfile, ScanStatus, User


def _port(port, state="open", service="ssh", product="", version=""):
    return {"port": port, "protocol": "tcp", "state": state, "service": service,
            "product": product, "version": version, "cpe": []}


def _result(hosts):
    return {
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "profile": "quick",
        "arguments": "-sT",
        "hosts": [{"ip": ip, "hostnames": [], "state": "up", "mac": None,
                   "vendor": None, "os": [], "ports": ports} for ip, ports in hosts.items()],
        "stats": {"hosts_total": len(hosts), "hosts_up": len(hosts), "open_ports": 0},
    }


# ── чистая логика ──


def test_detects_new_host():
    d = diff_results(
        _result({"10.0.0.1": [_port(22)]}),
        _result({"10.0.0.1": [_port(22)], "10.0.0.2": [_port(80, service="http")]}),
    )
    assert d["summary"]["hosts_added"] == 1
    assert d["hosts_added"][0]["ip"] == "10.0.0.2"
    # порты нового хоста считаются как вновь открытые
    assert d["summary"]["ports_opened"] == 1


def test_detects_disappeared_host():
    d = diff_results(
        _result({"10.0.0.1": [_port(22)], "10.0.0.2": [_port(80)]}),
        _result({"10.0.0.1": [_port(22)]}),
    )
    assert d["summary"]["hosts_removed"] == 1
    assert d["hosts_removed"][0]["ip"] == "10.0.0.2"
    assert d["summary"]["ports_closed"] == 1


def test_detects_newly_opened_port():
    d = diff_results(
        _result({"10.0.0.1": [_port(22)]}),
        _result({"10.0.0.1": [_port(22), _port(3389, service="ms-wbt-server")]}),
    )
    change = d["host_changes"][0]
    assert change["ip"] == "10.0.0.1"
    assert change["ports_opened"] == [{"port": 3389, "protocol": "tcp", "service": "ms-wbt-server"}]
    assert change["ports_closed"] == []


def test_detects_closed_port():
    d = diff_results(
        _result({"10.0.0.1": [_port(22), _port(23, service="telnet")]}),
        _result({"10.0.0.1": [_port(22)]}),
    )
    assert d["host_changes"][0]["ports_closed"] == [
        {"port": 23, "protocol": "tcp", "service": "telnet"}
    ]


def test_port_that_became_closed_counts_as_closed():
    """Порт остался в выдаче, но сменил состояние на closed — это закрытие."""
    d = diff_results(
        _result({"10.0.0.1": [_port(22)]}),
        _result({"10.0.0.1": [_port(22, state="closed")]}),
    )
    assert d["summary"]["ports_closed"] == 1


def test_detects_service_version_change():
    d = diff_results(
        _result({"10.0.0.1": [_port(22, product="OpenSSH", version="8.4")]}),
        _result({"10.0.0.1": [_port(22, product="OpenSSH", version="9.6")]}),
    )
    changed = d["host_changes"][0]["services_changed"][0]
    assert changed["before"] == "ssh OpenSSH 8.4"
    assert changed["after"] == "ssh OpenSSH 9.6"


def test_identical_scans_produce_no_changes():
    same = _result({"10.0.0.1": [_port(22), _port(80, service="http")]})
    d = diff_results(same, same)
    assert d["host_changes"] == []
    assert d["summary"] == {"hosts_added": 0, "hosts_removed": 0, "ports_opened": 0,
                            "ports_closed": 0, "hosts_changed": 0}


# ── эндпоинт ──


def _add_done_scan(hosts, target="10.0.0.0/24"):
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        scan = Scan(target=target, profile=ScanProfile.quick, status=ScanStatus.done,
                    created_by=admin.id, result=json.dumps(_result(hosts), ensure_ascii=False))
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan.id
    finally:
        db.close()


def test_diff_endpoint_returns_changes(client, admin_headers):
    a = _add_done_scan({"10.0.0.1": [_port(22)]})
    b = _add_done_scan({"10.0.0.1": [_port(22), _port(443, service="https")]})

    r = client.get(f"/analytics/diff?base={a}&compare={b}", headers=admin_headers)
    assert r.status_code == 200
    d = r.json()
    assert d["base"]["id"] == a
    assert d["compare"]["id"] == b
    assert d["summary"]["ports_opened"] == 1


def test_diff_rejects_same_scan(client, admin_headers):
    a = _add_done_scan({"10.0.0.1": [_port(22)]})
    r = client.get(f"/analytics/diff?base={a}&compare={a}", headers=admin_headers)
    assert r.status_code == 400


def test_diff_rejects_unfinished_scan(client, admin_headers):
    done = _add_done_scan({"10.0.0.1": [_port(22)]})

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        pending = Scan(target="10.0.0.5", profile=ScanProfile.quick,
                       status=ScanStatus.queued, created_by=admin.id)
        db.add(pending)
        db.commit()
        db.refresh(pending)
        pending_id = pending.id
    finally:
        db.close()

    r = client.get(f"/analytics/diff?base={done}&compare={pending_id}", headers=admin_headers)
    assert r.status_code == 400
    assert "не завершён" in r.json()["detail"]


def test_diff_404_for_missing_scan(client, admin_headers):
    a = _add_done_scan({"10.0.0.1": [_port(22)]})
    r = client.get(f"/analytics/diff?base={a}&compare=999999", headers=admin_headers)
    assert r.status_code == 404


def test_diff_available_to_viewer(client, viewer_headers):
    a = _add_done_scan({"10.0.0.1": [_port(22)]})
    b = _add_done_scan({"10.0.0.1": [_port(80, service="http")]})
    r = client.get(f"/analytics/diff?base={a}&compare={b}", headers=viewer_headers)
    assert r.status_code == 200
