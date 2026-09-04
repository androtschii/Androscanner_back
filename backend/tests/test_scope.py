"""Allowed-scope: главное правило — сканировать можно только свои сети."""


def test_scan_within_scope_is_created(client, admin_headers):
    r = client.post("/scans", headers=admin_headers, json={"target": "192.168.1.10", "profile": "quick"})
    assert r.status_code == 200
    assert r.json()["status"] == "queued"


def test_scan_outside_scope_returns_403(client, admin_headers):
    r = client.post("/scans", headers=admin_headers, json={"target": "8.8.8.8", "profile": "quick"})
    assert r.status_code == 403


def test_scan_wider_range_than_scope_returns_403(client, admin_headers):
    """192.168.0.0/16 шире разрешённого 192.168.1.0/24 — не должен проходить."""
    r = client.post("/scans", headers=admin_headers, json={"target": "192.168.0.0/16", "profile": "quick"})
    assert r.status_code == 403


def test_scan_ipv6_target_does_not_500(client, admin_headers):
    """Регрессия: IPv6-цель при IPv4-scope раньше падала в 500
    (TypeError внутри ipaddress.subnet_of при сравнении разных версий)."""
    r = client.post("/scans", headers=admin_headers, json={"target": "2001:db8::1", "profile": "quick"})
    assert r.status_code == 403
