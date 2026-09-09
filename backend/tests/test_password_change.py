"""Тесты смены собственного пароля."""

from app.database import SessionLocal
from app.models import User


def _make_user(client, admin_headers, username, password, role="viewer"):
    client.post(
        "/users",
        headers=admin_headers,
        json={"username": username, "password": password, "role": role},
    )
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _drop_user(username):
    db = SessionLocal()
    try:
        db.query(User).filter(User.username == username).delete()
        db.commit()
    finally:
        db.close()


def test_password_change_then_login_with_new_one(client, admin_headers):
    h = _make_user(client, admin_headers, "smenshchik", "staryy-parol-123")

    r = client.post(
        "/users/me/password",
        headers=h,
        json={"current_password": "staryy-parol-123", "new_password": "novyy-parol-4567"},
    )
    assert r.status_code == 200

    # старый больше не подходит
    assert client.post(
        "/auth/login", data={"username": "smenshchik", "password": "staryy-parol-123"}
    ).status_code == 401
    # новый работает
    assert client.post(
        "/auth/login", data={"username": "smenshchik", "password": "novyy-parol-4567"}
    ).status_code == 200

    _drop_user("smenshchik")


def test_wrong_current_password_rejected(client, admin_headers):
    h = _make_user(client, admin_headers, "zabyvchivyy", "moy-parol-12345")

    r = client.post(
        "/users/me/password",
        headers=h,
        json={"current_password": "ne-tot-parol", "new_password": "novyy-parol-4567"},
    )
    assert r.status_code == 400
    assert "Текущий пароль неверен" in r.json()["detail"]

    # пароль не изменился
    assert client.post(
        "/auth/login", data={"username": "zabyvchivyy", "password": "moy-parol-12345"}
    ).status_code == 200

    _drop_user("zabyvchivyy")


def test_short_new_password_rejected(client, admin_headers):
    h = _make_user(client, admin_headers, "korotysh", "normalnyy-parol")

    r = client.post(
        "/users/me/password",
        headers=h,
        json={"current_password": "normalnyy-parol", "new_password": "kort"},
    )
    assert r.status_code == 422

    _drop_user("korotysh")


def test_same_password_rejected(client, admin_headers):
    h = _make_user(client, admin_headers, "upryamyy", "tot-zhe-parol-1")

    r = client.post(
        "/users/me/password",
        headers=h,
        json={"current_password": "tot-zhe-parol-1", "new_password": "tot-zhe-parol-1"},
    )
    assert r.status_code == 400
    assert "совпадает" in r.json()["detail"]

    _drop_user("upryamyy")


def test_viewer_can_change_own_password(client, admin_headers):
    """Смена своего пароля — не админское действие."""
    h = _make_user(client, admin_headers, "skromnyy", "parol-viewera-1", role="viewer")

    r = client.post(
        "/users/me/password",
        headers=h,
        json={"current_password": "parol-viewera-1", "new_password": "drugoy-parol-22"},
    )
    assert r.status_code == 200

    _drop_user("skromnyy")


def test_change_is_recorded_in_audit(client, admin_headers):
    h = _make_user(client, admin_headers, "auditor", "parol-dlya-loga")

    client.post(
        "/users/me/password",
        headers=h,
        json={"current_password": "parol-dlya-loga", "new_password": "novyy-dlya-loga"},
    )

    audit = client.get("/audit", headers=admin_headers).json()
    assert any(
        e["action"] == "change_password" and e["detail"] == "auditor" for e in audit
    )

    _drop_user("auditor")


def test_anonymous_cannot_change_password(client):
    r = client.post(
        "/users/me/password",
        json={"current_password": "chto-ugodno", "new_password": "novyy-parol-123"},
    )
    assert r.status_code == 401
