"""Тесты сводной аналитики."""

import json

from app.database import SessionLocal
from app.models import Scan, ScanProfile, ScanStatus, User


def _add_scan(target, status, result=None, profile=ScanProfile.quick):
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        scan = Scan(
            target=target,
            profile=profile,
            status=status,
            created_by=admin.id,
            result=json.dumps(result, ensure_ascii=False) if result else None,
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()


def _result(ip, ports):
    return {
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "profile": "quick",
        "arguments": "-sT",
        "hosts": [{"ip": ip, "hostnames": [], "state": "up", "mac": None,
                   "vendor": None, "os": [], "ports": ports}],
        "stats": {"hosts_total": 1, "hosts_up": 1, "open_ports": len(ports)},
    }


def _port(port, state="open", service="ssh"):
    return {"port": port, "protocol": "tcp", "state": state,
            "service": service, "product": "", "version": "", "cpe": []}


def test_summary_available_to_viewer(client, viewer_headers):
    """Аналитику смотрят все роли, включая наблюдателя."""
    r = client.get("/analytics/summary", headers=viewer_headers)
    assert r.status_code == 200


def test_summary_counts_hosts_and_ports(client, admin_headers):
    _add_scan("192.168.1.10", ScanStatus.done, _result("192.168.1.10", [_port(22), _port(80, service="http")]))
    _add_scan("192.168.1.11", ScanStatus.done, _result("192.168.1.11", [_port(22)]))

    d = client.get("/analytics/summary", headers=admin_headers).json()

    assert d["hosts_unique"] >= 2
    assert d["open_ports_total"] >= 3
    services = {s["name"]: s["count"] for s in d["top_services"]}
    assert services["ssh"] >= 2
    assert services["http"] >= 1


def test_summary_ignores_closed_ports(client, admin_headers):
    before = client.get("/analytics/summary", headers=admin_headers).json()["open_ports_total"]
    _add_scan("192.168.1.20", ScanStatus.done, _result("192.168.1.20", [_port(443, state="closed")]))
    after = client.get("/analytics/summary", headers=admin_headers).json()["open_ports_total"]
    assert after == before


def test_summary_skips_failed_and_broken_results(client, admin_headers):
    """Провалившийся скан и битый JSON не должны ломать сводку."""
    _add_scan("192.168.1.30", ScanStatus.failed, {"error": "нет прав"})

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        db.add(Scan(target="192.168.1.31", profile=ScanProfile.quick,
                    status=ScanStatus.done, created_by=admin.id, result="{не json"))
        db.commit()
    finally:
        db.close()

    r = client.get("/analytics/summary", headers=admin_headers)
    assert r.status_code == 200


def test_summary_groups_by_status_and_profile(client, admin_headers):
    d = client.get("/analytics/summary", headers=admin_headers).json()
    assert d["scans_total"] > 0
    assert sum(s["count"] for s in d["scans_by_status"]) == d["scans_total"]
    assert sum(p["count"] for p in d["scans_by_profile"]) == d["scans_total"]


def test_scan_list_omits_result(client, admin_headers):
    """Список сканов не должен таскать полные результаты — они весят килобайты."""
    scans = client.get("/scans", headers=admin_headers).json()
    assert scans, "нужен хотя бы один скан"
    assert "result" not in scans[0]


def test_scan_detail_includes_result(client, admin_headers):
    scans = client.get("/scans", headers=admin_headers).json()
    detail = client.get(f"/scans/{scans[0]['id']}", headers=admin_headers).json()
    assert "result" in detail
