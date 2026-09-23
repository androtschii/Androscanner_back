"""Тесты модуля уведомлений в Telegram.

Бот только отправляет — не слушает команды, поэтому вся интеграция
сводится к одному HTTP POST на Bot API. Токен/chat_id не заданы
по умолчанию — тесты проверяют это как штатный случай, а не как ошибку.
"""

from unittest.mock import MagicMock, patch

import httpx as httpx_module

from app.config import settings
from app.notifications import telegram


def test_not_configured_by_default():
    """Пустой токен/chat_id — штатное состояние, не ошибка."""
    with patch.object(settings, "telegram_bot_token", ""):
        assert telegram.is_configured() is False


def test_configured_when_both_present():
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            assert telegram.is_configured() is True


def test_send_message_noop_when_not_configured():
    """Без токена — просто ничего не происходит, HTTP не вызывается."""
    with patch.object(settings, "telegram_bot_token", ""):
        with patch("app.notifications.telegram.httpx.post") as post:
            telegram.send_message("тест")
    post.assert_not_called()


def test_send_message_posts_to_bot_api_when_configured():
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post") as post:
                telegram.send_message("привет")

    post.assert_called_once()
    url, kwargs = post.call_args[0][0], post.call_args[1]
    assert "123:ABC" in url
    assert kwargs["json"]["chat_id"] == "42"
    assert kwargs["json"]["text"] == "привет"


def test_network_error_does_not_propagate():
    """Недоступный Telegram не должен ронять то действие, которое
    вызвало уведомление (вход, запуск скана)."""
    import httpx as httpx_module

    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch(
                "app.notifications.telegram.httpx.post",
                side_effect=httpx_module.ConnectError("недоступен"),
            ):
                telegram.send_message("это не должно упасть")  # не бросает


def test_notify_scan_finished_formats_message():
    with patch("app.notifications.telegram.send_message") as send:
        telegram.notify_scan_finished("192.168.1.10", "done", hosts_up=3)
    text = send.call_args[0][0]
    assert "192.168.1.10" in text
    assert "done" in text
    assert "3" in text


def test_notify_login_formats_message():
    with patch("app.notifications.telegram.send_message") as send:
        telegram.notify_login("admin", "admin")
    assert "admin" in send.call_args[0][0]


# ── меню команд и inline-кнопки ──


def test_send_message_includes_reply_markup_when_given():
    keyboard = {"inline_keyboard": [[{"text": "x", "callback_data": "y"}]]}
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post") as post:
                telegram.send_message("привет", reply_markup=keyboard)

    assert post.call_args[1]["json"]["reply_markup"] == keyboard


def test_send_message_omits_reply_markup_when_not_given():
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post") as post:
                telegram.send_message("привет")

    assert "reply_markup" not in post.call_args[1]["json"]


def test_set_commands_noop_when_not_configured():
    with patch.object(settings, "telegram_bot_token", ""):
        with patch("app.notifications.telegram.httpx.post") as post:
            telegram.set_commands([("status", "описание")])
    post.assert_not_called()


def test_set_commands_posts_command_list():
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post") as post:
                telegram.set_commands([("status", "последние сканы")])

    body = post.call_args[1]["json"]
    assert body["commands"] == [{"command": "status", "description": "последние сканы"}]


def test_answer_callback_query_noop_when_not_configured():
    with patch.object(settings, "telegram_bot_token", ""):
        with patch("app.notifications.telegram.httpx.post") as post:
            telegram.answer_callback_query("cb1")
    post.assert_not_called()


def test_answer_callback_query_posts_id():
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post") as post:
                telegram.answer_callback_query("cb1", text="готово")

    body = post.call_args[1]["json"]
    assert body["callback_query_id"] == "cb1"
    assert body["text"] == "готово"


def test_edit_message_noop_when_not_configured():
    with patch.object(settings, "telegram_bot_token", ""):
        with patch("app.notifications.telegram.httpx.post") as post:
            telegram.edit_message(1, "текст")
    post.assert_not_called()


def test_edit_message_posts_message_id_and_text():
    keyboard = {"inline_keyboard": [[{"text": "X", "callback_data": "ttt:0"}]]}
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post") as post:
                telegram.edit_message(777, "твой ход", reply_markup=keyboard)

    body = post.call_args[1]["json"]
    assert body["message_id"] == 777
    assert body["text"] == "твой ход"
    assert body["reply_markup"] == keyboard


def test_send_message_returns_message_id():
    fake_response = MagicMock()
    fake_response.json.return_value = {"result": {"message_id": 123}}
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch("app.notifications.telegram.httpx.post", return_value=fake_response):
                assert telegram.send_message("привет") == 123


def test_send_message_returns_none_on_error():
    with patch.object(settings, "telegram_bot_token", "123:ABC"):
        with patch.object(settings, "telegram_chat_id", "42"):
            with patch(
                "app.notifications.telegram.httpx.post",
                side_effect=httpx_module.ConnectError("недоступен"),
            ):
                assert telegram.send_message("привет") is None
