"""Тесты сводной карты сети."""

import json

from app.analytics import build_network_map
from app.database import SessionLocal
from app.models import AllowedScope, Scan, ScanProfile, ScanStatus, User


def _host(ip, ports=(), mac=None, vendor=None, os_name=None, hostnames=()):
    return {
        "ip": ip,
        "hostnames": list(hostnames),
        "state": "up",
        "mac": mac,
        "vendor": vendor,
        "os": [{"name": os_name, "accuracy": 95}] if os_name else [],
        "ports": [
            {"port": p, "protocol": "tcp", "state": "open", "service": s,
             "product": "", "version": "", "cpe": []}
            for p, s in ports
        ],
    }


def _scan(hosts, scanned_at, status=ScanStatus.done):
    s = Scan(target="192.168.1.0/24", profile=ScanProfile.quick, status=status, created_by=1)
    s.result = json.dumps(
        {"scanned_at": scanned_at, "profile": "quick", "arguments": "-sT",
         "hosts": hosts, "stats": {}},
        ensure_ascii=False,
    )
    return s


def _scope(cidr, description=""):
    return AllowedScope(cidr=cidr, description=description)


def test_groups_hosts_into_matching_subnet():
    m = build_network_map(
        [_scan([_host("192.168.1.10", [(22, "ssh")])], "2026-01-01T00:00:00")],
        [_scope("192.168.1.0/24", "дом")],
    )
    assert m["networks"][0]["cidr"] == "192.168.1.0/24"
    assert m["networks"][0]["hosts"][0]["ip"] == "192.168.1.10"
    assert m["totals"]["hosts"] == 1


def test_host_outside_every_scope_lands_in_ungrouped():
    m = build_network_map(
        [_scan([_host("10.9.9.9")], "2026-01-01T00:00:00")],
        [_scope("192.168.1.0/24")],
    )
    assert m["networks"][0]["hosts"] == []
    assert m["ungrouped"][0]["ip"] == "10.9.9.9"


def test_newer_scan_wins_for_port_count():
    m = build_network_map(
        [
            _scan([_host("192.168.1.10", [(22, "ssh")])], "2026-01-01T00:00:00"),
            _scan([_host("192.168.1.10", [(22, "ssh"), (80, "http")])], "2026-06-01T00:00:00"),
        ],
        [_scope("192.168.1.0/24")],
    )
    host = m["networks"][0]["hosts"][0]
    assert host["open_ports"] == 2
    assert host["services"] == ["http", "ssh"]
    assert host["last_seen"] == "2026-06-01T00:00:00"


def test_older_scan_does_not_erase_mac_found_earlier():
    """MAC и ОС видны не во всех профилях — свежий скан без них не должен затирать."""
    m = build_network_map(
        [
            _scan([_host("192.168.1.10", mac="AA:BB:CC:DD:EE:FF",
                         vendor="Raspberry Pi", os_name="Linux 5.X")], "2026-01-01T00:00:00"),
            _scan([_host("192.168.1.10", [(22, "ssh")])], "2026-06-01T00:00:00"),
        ],
        [_scope("192.168.1.0/24")],
    )
    host = m["networks"][0]["hosts"][0]
    assert host["mac"] == "AA:BB:CC:DD:EE:FF"
    assert host["vendor"] == "Raspberry Pi"
    assert host["os"] == "Linux 5.X"
    assert host["open_ports"] == 1  # но количество портов — из свежего


def test_ignores_unfinished_and_broken_scans():
    broken = _scan([_host("192.168.1.10")], "2026-01-01T00:00:00")
    broken.result = "{не json"
    unfinished = _scan([_host("192.168.1.11")], "2026-01-01T00:00:00", status=ScanStatus.queued)

    m = build_network_map([broken, unfinished], [_scope("192.168.1.0/24")])
    assert m["totals"]["hosts"] == 0


def test_ipv4_host_not_matched_against_ipv6_scope():
    m = build_network_map(
        [_scan([_host("192.168.1.10")], "2026-01-01T00:00:00")],
        [_scope("2001:db8::/32")],
    )
    assert m["networks"][0]["hosts"] == []
    assert m["ungrouped"][0]["ip"] == "192.168.1.10"


def test_hostnames_accumulate_across_scans():
    m = build_network_map(
        [
            _scan([_host("192.168.1.10", hostnames=["pi.local"])], "2026-01-01T00:00:00"),
            _scan([_host("192.168.1.10", hostnames=["pi"])], "2026-06-01T00:00:00"),
        ],
        [_scope("192.168.1.0/24")],
    )
    assert sorted(m["networks"][0]["hosts"][0]["hostnames"]) == ["pi", "pi.local"]


# ── эндпоинт ──


def test_network_endpoint_available_to_viewer(client, viewer_headers):
    r = client.get("/analytics/network", headers=viewer_headers)
    assert r.status_code == 200
    assert "networks" in r.json()


def test_network_endpoint_reflects_stored_scans(client, admin_headers):
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        s = _scan([_host("192.168.1.77", [(443, "https")])], "2026-07-01T00:00:00")
        s.created_by = admin.id
        db.add(s)
        db.commit()
    finally:
        db.close()

    d = client.get("/analytics/network", headers=admin_headers).json()
    all_ips = [h["ip"] for n in d["networks"] for h in n["hosts"]] + [
        h["ip"] for h in d["ungrouped"]
    ]
    assert "192.168.1.77" in all_ips
