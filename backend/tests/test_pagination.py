"""Тесты пагинации и фильтров.

До этого GET /scans отдавал ВСЕ сканы разом, а /audit — жёстко 200 последних
записей без возможности листать: всё, что старше, было недоступно в принципе.
"""

from app.database import SessionLocal
from app.models import Scan, ScanProfile, ScanStatus, User


def _seed_scans(count, target_prefix="10.20.30."):
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        for i in range(count):
            db.add(
                Scan(
                    target=f"{target_prefix}{i}",
                    profile=ScanProfile.quick,
                    status=ScanStatus.done if i % 2 else ScanStatus.failed,
                    created_by=admin.id,
                )
            )
        db.commit()
    finally:
        db.close()


def _cleanup(target_prefix="10.20.30."):
    db = SessionLocal()
    try:
        db.query(Scan).filter(Scan.target.startswith(target_prefix)).delete(
            synchronize_session=False
        )
        db.commit()
    finally:
        db.close()


# ── форма ответа ──


def test_response_has_page_envelope(client, admin_headers):
    body = client.get("/scans", headers=admin_headers).json()
    assert set(body) >= {"items", "total", "limit", "offset"}
    assert isinstance(body["items"], list)


def test_total_counts_all_matching_not_just_page(client, admin_headers):
    """total — это сколько всего подходит под фильтр, а не сколько на странице."""
    _seed_scans(15)
    body = client.get("/scans?limit=5", headers=admin_headers).json()
    assert len(body["items"]) == 5
    assert body["total"] >= 15
    _cleanup()


# ── листание ──


def test_offset_shifts_the_window(client, admin_headers):
    _seed_scans(10)
    first = client.get("/scans?limit=3&offset=0", headers=admin_headers).json()
    second = client.get("/scans?limit=3&offset=3", headers=admin_headers).json()

    first_ids = {s["id"] for s in first["items"]}
    second_ids = {s["id"] for s in second["items"]}
    assert first_ids.isdisjoint(second_ids), "страницы не должны пересекаться"
    _cleanup()


def test_offset_past_the_end_returns_empty_not_error(client, admin_headers):
    body = client.get("/scans?offset=100000", headers=admin_headers).json()
    assert body["items"] == []
    assert body["total"] >= 0


# ── границы ──


def test_limit_above_cap_rejected(client, admin_headers):
    """Верхний предел защищает от запроса «отдай мне всё одним куском»."""
    assert client.get("/scans?limit=100000", headers=admin_headers).status_code == 422


def test_negative_offset_rejected(client, admin_headers):
    assert client.get("/scans?offset=-5", headers=admin_headers).status_code == 422


def test_zero_limit_rejected(client, admin_headers):
    assert client.get("/scans?limit=0", headers=admin_headers).status_code == 422


# ── фильтры ──


def test_filter_by_status(client, admin_headers):
    _seed_scans(10)
    body = client.get("/scans?status=failed&limit=200", headers=admin_headers).json()
    assert body["items"], "должны найтись проваленные сканы"
    assert all(s["status"] == "failed" for s in body["items"])
    _cleanup()


def test_filter_by_target_substring(client, admin_headers):
    _seed_scans(5, target_prefix="172.16.99.")
    body = client.get("/scans?target=172.16.99&limit=200", headers=admin_headers).json()
    assert len(body["items"]) >= 5
    assert all("172.16.99" in s["target"] for s in body["items"])
    _cleanup("172.16.99.")


def test_filters_combine(client, admin_headers):
    _seed_scans(10, target_prefix="192.0.2.")
    body = client.get(
        "/scans?target=192.0.2&status=done&limit=200", headers=admin_headers
    ).json()
    assert all(
        "192.0.2" in s["target"] and s["status"] == "done" for s in body["items"]
    )
    _cleanup("192.0.2.")


def test_unknown_status_value_rejected(client, admin_headers):
    assert client.get("/scans?status=vydumannyy", headers=admin_headers).status_code == 422


# ── audit-log ──


def test_audit_is_paginated(client, admin_headers):
    body = client.get("/audit?limit=5", headers=admin_headers).json()
    assert len(body["items"]) <= 5
    assert body["total"] >= len(body["items"])


def test_audit_filter_by_action(client, admin_headers):
    body = client.get("/audit?action=login&limit=200", headers=admin_headers).json()
    assert all(e["action"] == "login" for e in body["items"])


def test_audit_older_entries_reachable_by_offset(client, admin_headers):
    """Раньше записи старше 200-й были недоступны в принципе."""
    first = client.get("/audit?limit=2&offset=0", headers=admin_headers).json()
    if first["total"] > 2:
        second = client.get("/audit?limit=2&offset=2", headers=admin_headers).json()
        assert second["items"], "вторая страница журнала должна быть доступна"
        assert {e["id"] for e in first["items"]}.isdisjoint(
            {e["id"] for e in second["items"]}
        )
