"""Проверяет, что события реально дёргают уведомления, а не только
что сам модуль telegram.py работает в изоляции. Telegram здесь не
настроен (нет токена в .env тестов) — send_message внутри отправит
запрос в замоканную функцию, что и требуется: важен сам факт вызова
с правильными аргументами, а не поход в сеть.
"""

from unittest.mock import patch


def test_login_success_notifies(client, admin_headers):
    with patch("app.api.auth.notify_login") as notify:
        r = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    notify.assert_called_once_with("admin", "admin")


def test_login_failure_notifies(client):
    with patch("app.api.auth.notify_login_failed") as notify:
        r = client.post(
            "/auth/login", data={"username": "admin", "password": "definitely-wrong"}
        )
    assert r.status_code == 401
    notify.assert_called_once_with("admin")


def test_create_scan_notifies_started(client, admin_headers, home_scope):
    with patch("app.api.scans.notify_scan_started") as notify:
        r = client.post(
            "/scans",
            headers=admin_headers,
            json={"target": "192.168.1.50", "profile": "ping"},
        )
    assert r.status_code == 200
    notify.assert_called_once_with("admin", "192.168.1.50", "ping")


def test_cancel_scan_notifies_finished(client, admin_headers, home_scope):
    created = client.post(
        "/scans",
        headers=admin_headers,
        json={"target": "192.168.1.51", "profile": "ping"},
    ).json()

    with patch("app.api.scans.notify_scan_finished") as notify:
        r = client.post(f"/scans/{created['id']}/cancel", headers=admin_headers)

    # Скан мог успеть выполниться в BackgroundTasks раньше отмены — тогда
    # cancel вернёт 409, и уведомление об отмене не отправится, это не
    # баг теста. Проверяем оба легитимных исхода.
    if r.status_code == 200:
        notify.assert_called_once_with("192.168.1.51", "cancelled")
    else:
        assert r.status_code == 409
        notify.assert_not_called()
