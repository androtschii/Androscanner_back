"""Приём команд из Telegram: /status и /report <id>.

Только чтение. Команды на запуск скана нет и не будет здесь намеренно —
это была бы вторая поверхность для запуска сканов в обход веб-интерфейса,
RBAC и одобренного allowed-scope, а бот отвечает единственному chat_id
из .env, у которого нет понятия «роль». Расширять RBAC на Telegram того
не стоило — риск несопоставим с удобством.

Работает в отдельном потоке через long polling (getUpdates), а не как
asyncio-таска: вся остальная работа с БД в проекте синхронная (обычная
SQLAlchemy Session), и мешать её с event loop без блокировок — отдельная
головная боль на ровном месте. Поток демонический — процесс завершается,
не дожидаясь его, но start()/stop() всё равно аккуратно останавливают
поллинг при выключении приложения, чтобы тестовый TestClient не оставлял
висящие потоки между прогонами.
"""

import logging
import socket
import threading
import time

import httpx

from app.config import settings
from app.database import SessionLocal
from app.models import AuditLog, Scan, ScanStatus
from app.notifications.telegram import (
    answer_callback_query,
    is_configured,
    send_document,
    send_message,
    set_commands,
)
from app.reports import ReportError, render_scan_report

logger = logging.getLogger(__name__)

API_BASE = "https://api.telegram.org"
STATUS_LIMIT = 5

# Показывается во встроенном меню Telegram (иконка «/» рядом с полем ввода) —
# регистрируется один раз при старте, см. start().
COMMANDS = [
    ("status", "последние сканы, с кнопками на отчёт"),
    ("report", "PDF-отчёт по номеру: /report 7"),
    ("ip", "текущий IP этой машины в сети"),
    ("help", "список команд"),
]

HELP_TEXT = (
    "Доступные команды:\n"
    "/status — последние сканы\n"
    "/report &lt;id&gt; — PDF-отчёт по скану\n"
    "/ip — текущий IP этой машины в сети"
)


def _detect_local_ip() -> str | None:
    """IP, который эта машина использует для исходящих соединений — тот
    самый адрес, что нужно прописывать в VITE_API_URL/allowed-scope
    после смены сети (Wi-Fi ↔ Ethernet, другая точка доступа и т.п.).

    Реального соединения не открывается — UDP connect() на сокете только
    выбирает исходящий интерфейс по таблице маршрутизации, ни один пакет
    никуда не уходит. Тот же приём, которым для этого пользуются сами
    сетевые утилиты.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def _handle_ip() -> None:
    ip = _detect_local_ip()
    if ip:
        send_message(f"🖥 IP этой машины в текущей сети: <code>{ip}</code>")
    else:
        send_message("Не удалось определить IP — сеть недоступна")


def _format_status(scans: list[Scan]) -> str:
    if not scans:
        return "Сканов пока нет."
    lines = [f"Последние {len(scans)} сканов:"]
    for s in scans:
        lines.append(f"#{s.id} <code>{s.target}</code> [{s.profile.value}] — {s.status.value}")
    return "\n".join(lines)


def _status_keyboard(scans: list[Scan]) -> dict | None:
    """Кнопка «Отчёт #N» под каждым завершённым сканом — нажал и получил
    PDF, не набирая /report <id> руками. Для незавершённых сканов кнопки
    нет: отчёт по ним всё равно ничего не покажет."""
    rows = [
        [{"text": f"📄 Отчёт #{s.id}", "callback_data": f"report:{s.id}"}]
        for s in scans
        if s.status == ScanStatus.done
    ]
    return {"inline_keyboard": rows} if rows else None


def _handle_status() -> None:
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(STATUS_LIMIT).all()
        send_message(_format_status(scans), reply_markup=_status_keyboard(scans))
    finally:
        db.close()


def _handle_report(arg: str) -> None:
    if not arg.isdigit():
        send_message("Нужен числовой ID: /report 42")
        return

    scan_id = int(arg)
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            send_message(f"Скан #{scan_id} не найден")
            return

        try:
            pdf = render_scan_report(scan, requested_by="telegram-bot")
        except ReportError as exc:
            send_message(f"Не удалось собрать отчёт: {exc}")
            return

        # Такая же запись, как у скачивания через веб — «кто и что смотрел»
        # должно быть видно в audit-log независимо от канала.
        db.add(AuditLog(user_id=None, action="export_report", detail=f"scan {scan_id} via telegram"))
        db.commit()

        ok = send_document(
            f"androscanner-scan-{scan_id}.pdf",
            pdf,
            caption=f"Отчёт по скану #{scan_id} ({scan.target})",
        )
        if not ok:
            send_message("Не удалось отправить файл — попробуйте ещё раз")
    finally:
        db.close()


def _handle_command(text: str) -> None:
    parts = text.strip().split(maxsplit=1)
    command = parts[0].split("@")[0]  # /report@androscanner_bot -> /report
    arg = parts[1] if len(parts) > 1 else ""

    if command == "/status":
        _handle_status()
    elif command == "/report":
        _handle_report(arg)
    elif command == "/ip":
        _handle_ip()
    elif command in ("/start", "/help"):
        send_message(HELP_TEXT)
    else:
        send_message(f"Неизвестная команда. {HELP_TEXT}")


def _handle_callback(callback_query: dict) -> None:
    """Нажатие inline-кнопки под /status («📄 Отчёт #N»)."""
    data = callback_query.get("data", "")
    callback_id = callback_query["id"]

    command, _, arg = data.partition(":")
    if command == "report" and arg.isdigit():
        _handle_report(arg)
        answer_callback_query(callback_id)
    else:
        answer_callback_query(callback_id, text="Неизвестное действие")


def _poll_once(client: httpx.Client, offset: int) -> tuple[int, list[dict]]:
    url = f"{API_BASE}/bot{settings.telegram_bot_token}/getUpdates"
    r = client.get(url, params={"offset": offset, "timeout": 25})
    r.raise_for_status()
    updates = r.json().get("result", [])
    next_offset = offset
    for update in updates:
        next_offset = max(next_offset, update["update_id"] + 1)
    return next_offset, updates


def _poll_loop(stop_event: threading.Event) -> None:
    offset = 0
    # Клиентский timeout чуть больше серверного long-poll (25с в _poll_once),
    # иначе httpx оборвёт соединение раньше, чем Telegram успеет ответить.
    with httpx.Client(timeout=30.0) as client:
        while not stop_event.is_set():
            try:
                offset, updates = _poll_once(client, offset)
            except httpx.HTTPError as exc:
                logger.warning("Ошибка long polling Telegram: %s", exc)
                time.sleep(5)
                continue

            for update in updates:
                callback_query = update.get("callback_query")
                message = (callback_query or {}).get("message") or update.get("message") or {}
                chat_id = message.get("chat", {}).get("id")

                # Отвечаем только своему chat_id — у бота нет ролей,
                # и это единственная граница доступа к его командам и кнопкам.
                if str(chat_id) != str(settings.telegram_chat_id):
                    logger.warning("Обращение от чужого chat_id %s проигнорировано", chat_id)
                    continue

                try:
                    if callback_query:
                        _handle_callback(callback_query)
                    elif update.get("message", {}).get("text"):
                        _handle_command(update["message"]["text"])
                except Exception:
                    logger.exception("Ошибка обработки обновления Telegram: %s", update)


_thread: threading.Thread | None = None
_stop_event = threading.Event()


def start() -> None:
    """Запускает поллинг в фоновом потоке, если бот настроен."""
    global _thread
    if not is_configured():
        return
    set_commands(COMMANDS)
    _stop_event.clear()
    _thread = threading.Thread(target=_poll_loop, args=(_stop_event,), daemon=True, name="telegram-bot-poll")
    _thread.start()


def stop() -> None:
    _stop_event.set()
    if _thread is not None:
        _thread.join(timeout=2)
