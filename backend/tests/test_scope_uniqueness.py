"""Дубликаты в allowed-scope и канонизация CIDR.

Найденный дефект: одну и ту же сеть можно было добавить сколько угодно раз,
в том числе записанную по-разному (192.168.1.77/24 хранилось дословно).
Проверено вживую: админ удаляет запись, считая, что отозвал доступ к сети,
а оставшийся дубликат продолжает её разрешать — сканы по-прежнему проходят.

Для инструмента, чья главная защита это белый список, «отзыв не отзывает»
недопустимо.
"""

from app.database import SessionLocal
from app.models import AllowedScope


def _cleanup(cidr_prefix):
    db = SessionLocal()
    try:
        db.query(AllowedScope).filter(
            AllowedScope.cidr.startswith(cidr_prefix)
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── канонизация ──


def test_host_address_is_normalized_to_network(client, admin_headers):
    """172.20.5.77/24 и 172.20.5.0/24 — одна сеть, хранить надо одинаково."""
    _cleanup("172.20.5.")
    r = client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.20.5.77/24", "description": "test"}
    )
    assert r.status_code == 200
    assert r.json()["cidr"] == "172.20.5.0/24"
    _cleanup("172.20.5.")


def test_single_address_keeps_prefix(client, admin_headers):
    _cleanup("172.21.")
    r = client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.21.0.5", "description": "one host"}
    )
    assert r.status_code == 200
    assert r.json()["cidr"] == "172.21.0.5/32"
    _cleanup("172.21.")


def test_audit_records_canonical_form(client, admin_headers):
    """В журнале должно быть то, что реально записано, а не что ввели."""
    _cleanup("172.22.")
    client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.22.9.9/16", "description": "x"}
    )
    audit = client.get("/audit?action=add_scope&limit=50", headers=admin_headers).json()["items"]
    assert any(e["detail"] == "172.22.0.0/16" for e in audit)
    _cleanup("172.22.")


# ── дубликаты ──


def test_exact_duplicate_rejected(client, admin_headers):
    _cleanup("172.23.")
    assert client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.23.0.0/24", "description": "первая"}
    ).status_code == 200

    r = client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.23.0.0/24", "description": "вторая"}
    )
    assert r.status_code == 409
    assert "уже разрешён" in r.json()["detail"]
    _cleanup("172.23.")


def test_same_network_written_differently_rejected(client, admin_headers):
    """Главная проверка: без канонизации этот дубликат прошёл бы."""
    _cleanup("172.24.")
    client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.24.0.0/24", "description": "первая"}
    )

    r = client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.24.0.99/24", "description": "она же"}
    )
    assert r.status_code == 409
    _cleanup("172.24.")


def test_error_explains_why_duplicates_matter(client, admin_headers):
    _cleanup("172.25.")
    client.post("/scopes", headers=admin_headers, json={"cidr": "172.25.0.0/24", "description": ""})
    r = client.post("/scopes", headers=admin_headers, json={"cidr": "172.25.0.0/24", "description": ""})
    assert "отозвал доступ" in r.json()["detail"]
    _cleanup("172.25.")


def test_different_masks_are_different_scopes(client, admin_headers):
    """/24 и /16 — разные сети, обе должны приниматься."""
    _cleanup("172.26.")
    assert client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.26.0.0/24", "description": ""}
    ).status_code == 200
    assert client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.26.0.0/16", "description": ""}
    ).status_code == 200
    _cleanup("172.26.")


# ── главный сценарий ──


def test_deleting_scope_actually_revokes_access(client, admin_headers):
    """Ради этого всё и делалось: удаление записи должно закрывать доступ."""
    _cleanup("172.27.")
    created = client.post(
        "/scopes", headers=admin_headers, json={"cidr": "172.27.0.0/24", "description": "времянка"}
    ).json()

    # Пока диапазон разрешён — скан проходит
    ok = client.post("/scans", headers=admin_headers, json={"target": "172.27.0.10", "profile": "quick"})
    assert ok.status_code == 200

    client.delete(f"/scopes/{created['id']}", headers=admin_headers)

    # После отзыва — не проходит
    blocked = client.post(
        "/scans", headers=admin_headers, json={"target": "172.27.0.10", "profile": "quick"}
    )
    assert blocked.status_code == 403, "удаление записи не отозвало доступ"
    _cleanup("172.27.")
