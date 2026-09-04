"""RBAC: viewer может только читать, запуск сканов и логи — admin/analyst."""


def test_viewer_cannot_create_scan(client, viewer_headers):
    r = client.post("/scans", headers=viewer_headers, json={"target": "192.168.1.10", "profile": "quick"})
    assert r.status_code == 403


def test_viewer_can_list_scans(client, viewer_headers):
    r = client.get("/scans", headers=viewer_headers)
    assert r.status_code == 200


def test_viewer_cannot_read_audit_log(client, viewer_headers):
    r = client.get("/audit", headers=viewer_headers)
    assert r.status_code == 403


def test_admin_can_read_audit_log(client, admin_headers):
    r = client.get("/audit", headers=admin_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
