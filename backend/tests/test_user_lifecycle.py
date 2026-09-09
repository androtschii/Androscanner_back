"""Тесты отключения и включения пользователей.

Раньше DELETE /users/{id} удалял строку по-настоящему. Это давало две беды:

1. На SQLite внешние ключи по умолчанию не проверяются — удаление
   проходило, а сканы и записи журнала оставались ссылаться на
   несуществующего пользователя. На PostgreSQL то же удаление упало бы
   с нарушением целостности и вернуло 500. Один и тот же запрос вёл себя
   по-разному в зависимости от базы.

2. В инструменте с audit-log удаление пользователя стирает
   ответственность: кто запускал сканы — уже не узнать.
"""

from app.database import SessionLocal
from app.models import Scan, ScanProfile, User


def _make_user(client, admin_headers, username, role="analyst"):
    r = client.post(
        "/users",
        headers=admin_headers,
        json={"username": username, "password": "parol-dlinnyy-1", "role": role},
    )
    assert r.status_code == 200
    return r.json()["id"]


def _token(client, username):
    r = client.post("/auth/login", data={"username": username, "password": "parol-dlinnyy-1"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"} if r.status_code == 200 else None


def _is_active(user_id):
    db = SessionLocal()
    try:
        return db.get(User, user_id).is_active
    finally:
        db.close()


# ── отключение ──


def test_deactivate_keeps_the_row(client, admin_headers):
    """Строка должна остаться: на ней висят сканы и журнал."""
    user_id = _make_user(client, admin_headers, "otklyuchaemyy")
    r = client.delete(f"/users/{user_id}", headers=admin_headers)
    assert r.status_code == 200

    db = SessionLocal()
    try:
        assert db.get(User, user_id) is not None, "пользователь не должен исчезать"
    finally:
        db.close()
    assert _is_active(user_id) is False


def test_scans_of_deactivated_user_keep_valid_author(client, admin_headers):
    """Главная проверка: скан не должен осиротеть."""
    user_id = _make_user(client, admin_headers, "avtor_skanov")

    db = SessionLocal()
    try:
        scan = Scan(target="192.168.1.70", profile=ScanProfile.quick, created_by=user_id)
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    client.delete(f"/users/{user_id}", headers=admin_headers)

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        author = db.get(User, scan.created_by)
        assert author is not None, "скан ссылается на несуществующего пользователя"
        assert author.username == "avtor_skanov"
    finally:
        db.close()


def test_deactivated_user_cannot_log_in(client, admin_headers):
    user_id = _make_user(client, admin_headers, "bolshe_ne_voydet")
    assert _token(client, "bolshe_ne_voydet") is not None

    client.delete(f"/users/{user_id}", headers=admin_headers)
    r = client.post(
        "/auth/login", data={"username": "bolshe_ne_voydet", "password": "parol-dlinnyy-1"}
    )
    assert r.status_code == 403


def test_existing_token_stops_working_immediately(client, admin_headers):
    """Отзыва JWT в системе нет, но проверка is_active в get_current_user
    его здесь заменяет: токен отключённого перестаёт работать сразу,
    не дожидаясь истечения срока."""
    user_id = _make_user(client, admin_headers, "s_zhivym_tokenom")
    headers = _token(client, "s_zhivym_tokenom")
    assert client.get("/users/me", headers=headers).status_code == 200

    client.delete(f"/users/{user_id}", headers=admin_headers)
    assert client.get("/users/me", headers=headers).status_code == 401


def test_cannot_deactivate_self(client, admin_headers):
    me = client.get("/users/me", headers=admin_headers).json()
    r = client.delete(f"/users/{me['id']}", headers=admin_headers)
    assert r.status_code == 400
    assert _is_active(me["id"]) is True


def test_double_deactivate_rejected(client, admin_headers):
    user_id = _make_user(client, admin_headers, "dvazhdy_otklyuchennyy")
    assert client.delete(f"/users/{user_id}", headers=admin_headers).status_code == 200
    assert client.delete(f"/users/{user_id}", headers=admin_headers).status_code == 409


def test_deactivation_is_logged(client, admin_headers):
    user_id = _make_user(client, admin_headers, "v_zhurnale")
    client.delete(f"/users/{user_id}", headers=admin_headers)

    audit = client.get("/audit?action=deactivate_user", headers=admin_headers).json()["items"]
    assert any(e["detail"] == "v_zhurnale" for e in audit)


# ── включение обратно ──


def test_activate_restores_access(client, admin_headers):
    user_id = _make_user(client, admin_headers, "vernuvshiysya")
    client.delete(f"/users/{user_id}", headers=admin_headers)
    assert _token(client, "vernuvshiysya") is None

    r = client.post(f"/users/{user_id}/activate", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["is_active"] is True
    assert _token(client, "vernuvshiysya") is not None


def test_activate_already_active_rejected(client, admin_headers):
    user_id = _make_user(client, admin_headers, "uzhe_aktiven")
    assert client.post(f"/users/{user_id}/activate", headers=admin_headers).status_code == 409


def test_activate_404_for_missing_user(client, admin_headers):
    assert client.post("/users/999999/activate", headers=admin_headers).status_code == 404


def test_activation_is_logged(client, admin_headers):
    user_id = _make_user(client, admin_headers, "vklyuchennyy_v_zhurnale")
    client.delete(f"/users/{user_id}", headers=admin_headers)
    client.post(f"/users/{user_id}/activate", headers=admin_headers)

    audit = client.get("/audit?action=activate_user", headers=admin_headers).json()["items"]
    assert any(e["detail"] == "vklyuchennyy_v_zhurnale" for e in audit)


# ── права ──


def test_viewer_cannot_deactivate(client, admin_headers, viewer_headers):
    user_id = _make_user(client, admin_headers, "zashchishchennyy")
    assert client.delete(f"/users/{user_id}", headers=viewer_headers).status_code == 403
    assert _is_active(user_id) is True


def test_viewer_cannot_activate(client, admin_headers, viewer_headers):
    user_id = _make_user(client, admin_headers, "zashchishchennyy2")
    client.delete(f"/users/{user_id}", headers=admin_headers)
    assert client.post(f"/users/{user_id}/activate", headers=viewer_headers).status_code == 403
