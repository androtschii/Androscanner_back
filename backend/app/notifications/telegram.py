"""Уведомления в Telegram.

Бот только ОТПРАВЛЯЕТ сообщения — не принимает команды и не слушает
обновления. Поэтому не нужен ни long polling, ни webhook: обычный HTTP POST
на Bot API при нужном событии, и всё. Никакой отдельной службы бота нет —
это несколько строк внутри уже существующего бэкенда.

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


def send_message(text: str) -> None:
    """Отправляет текст в чат. Ошибки только логируются — Telegram лежит
    или токен неверный не должны ронять запрос, который вызвал уведомление.
    """
    if not is_configured():
        return

    url = f"{API_BASE}/bot{settings.telegram_bot_token}/sendMessage"
    try:
        httpx.post(
            url,
            json={
                "chat_id": settings.telegram_chat_id,
                "text": text,
                "parse_mode": "HTML",
            },
            timeout=TIMEOUT,
        )
    except httpx.HTTPError as exc:
        logger.warning("Не удалось отправить уведомление в Telegram: %s", exc)


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
