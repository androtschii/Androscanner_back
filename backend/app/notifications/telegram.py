"""Уведомления и HTTP-обёртка над Telegram Bot API.

Отправка (push-уведомления о событиях) и приём команд (см. app/notifications/
bot.py) — разные вещи; здесь только низкоуровневые вызовы Bot API, которыми
пользуются оба.

Токен и chat_id — из .env. Если не заданы, все функции тихо ничего не
делают: отсутствие Telegram не должно ронять сканирование или вход.
"""

import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

API_BASE = "https://api.telegram.org"
TIMEOUT = 5.0


def is_configured() -> bool:
    return bool(settings.telegram_bot_token and settings.telegram_chat_id)


def send_message(text: str, reply_markup: dict | None = None) -> int | None:
    """Отправляет текст в чат. Ошибки только логируются — Telegram лежит
    или токен неверный не должны ронять запрос, который вызвал уведомление.

    reply_markup — inline-кнопки под сообщением (см. _keyboard в bot.py),
    например «📄 Отчёт #7» вместо необходимости набирать /report 7 руками.

    Возвращает message_id отправленного сообщения (или None при ошибке/
    неконфигурированном боте) — нужен, чтобы потом отредактировать это
    же сообщение (см. edit_message, игра в крестики-нолики).
    """
    if not is_configured():
        return None

    url = f"{API_BASE}/bot{settings.telegram_bot_token}/sendMessage"
    payload = {
        "chat_id": settings.telegram_chat_id,
        "text": text,
        "parse_mode": "HTML",
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        r = httpx.post(url, json=payload, timeout=TIMEOUT)
        return r.json().get("result", {}).get("message_id")
    except httpx.HTTPError as exc:
        logger.warning("Не удалось отправить уведомление в Telegram: %s", exc)
        return None


def edit_message(message_id: int, text: str, reply_markup: dict | None = None) -> None:
    """Правит уже отправленное сообщение на месте — используется игрой
    в крестики-нолики, чтобы поле обновлялось в том же сообщении,
    а не заваливало чат новым на каждый ход.
    """
    if not is_configured():
        return
    url = f"{API_BASE}/bot{settings.telegram_bot_token}/editMessageText"
    payload = {
        "chat_id": settings.telegram_chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        httpx.post(url, json=payload, timeout=TIMEOUT)
    except httpx.HTTPError as exc:
        logger.warning("Не удалось отредактировать сообщение в Telegram: %s", exc)


def answer_callback_query(callback_query_id: str, text: str = "") -> None:
    """Убирает «часики» с нажатой inline-кнопки. Без этого вызова кнопка
    в клиенте Telegram виснет в состоянии ожидания до таймаута."""
    if not is_configured():
        return
    url = f"{API_BASE}/bot{settings.telegram_bot_token}/answerCallbackQuery"
    try:
        httpx.post(
            url,
            json={"callback_query_id": callback_query_id, "text": text},
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        logger.warning("Не удалось ответить на нажатие кнопки: %s", exc)


def set_commands(commands: list[tuple[str, str]]) -> None:
    """Регистрирует список команд для встроенного меню Telegram (иконка
    «/» рядом с полем ввода) — вызывается один раз при старте бота.
    """
    if not is_configured():
        return
    url = f"{API_BASE}/bot{settings.telegram_bot_token}/setMyCommands"
    try:
        httpx.post(
            url,
            json={"commands": [{"command": c, "description": d} for c, d in commands]},
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        logger.warning("Не удалось зарегистрировать меню команд: %s", exc)


def send_document(filename: str, content: bytes, caption: str = "", chat_id: str | None = None) -> bool:
    """Отправляет файл в чат (используется ботом для команды /report).

    chat_id можно передать явно — на случай, если в будущем чатов станет
    больше одного; сейчас всегда совпадает с settings.telegram_chat_id.
    Возвращает True/False, а не молчит, как send_message: вызывающий код
    (обработчик команды) должен сам сообщить пользователю об ошибке.
    """
    if not is_configured():
        return False

    url = f"{API_BASE}/bot{settings.telegram_bot_token}/sendDocument"
    try:
        r = httpx.post(
            url,
            data={"chat_id": chat_id or settings.telegram_chat_id, "caption": caption},
            files={"document": (filename, content, "application/pdf")},
            timeout=30.0,
        )
        return r.status_code == 200
    except httpx.HTTPError as exc:
        logger.warning("Не удалось отправить файл в Telegram: %s", exc)
        return False


def notify_login(username: str, role: str) -> None:
    send_message(f"🔓 Вход: <b>{username}</b> ({role})")


def notify_login_failed(username: str) -> None:
    send_message(f"⚠️ Неудачный вход: <b>{username}</b>")


def notify_scan_started(username: str, target: str, profile: str) -> None:
    send_message(f"🔍 {username} запустил скан <code>{target}</code> ({profile})")


def notify_scan_finished(target: str, status: str, hosts_up: int | None = None) -> None:
    icon = {"done": "✅", "failed": "❌", "cancelled": "⏹"}.get(status, "•")
    extra = f", живых хостов: {hosts_up}" if hosts_up is not None else ""
    send_message(f"{icon} Скан <code>{target}</code> завершён: {status}{extra}")


def notify_anomaly_detected(target: str, summary: dict) -> None:
    """Что-то новое появилось с прошлого скана той же цели — см.
    app/tasks/runner.py::_check_anomalies. Не про закрывшиеся порты и
    пропавшие хосты — те не расширяют поверхность атаки, шуметь ими незачем.
    """
    parts = []
    if summary.get("hosts_added"):
        parts.append(f"новых хостов: {summary['hosts_added']}")
    if summary.get("ports_opened"):
        parts.append(f"новых открытых портов: {summary['ports_opened']}")
    send_message(f"⚠️ Изменения в сети <code>{target}</code> — {', '.join(parts)}")
