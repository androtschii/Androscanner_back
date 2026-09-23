"""Тесты приёма команд из Telegram (/status, /report).

Long polling (getUpdates) сетью не проверяется — только логика
обработки команд и продвижение offset на фейковом ответе API.
"""

import json
from unittest.mock import MagicMock, patch

from app.database import SessionLocal
from app.models import AuditLog, Scan, ScanProfile, ScanStatus, User
from app.notifications import bot
from app.reports import ReportError


def _make_scan(target="192.168.1.50", status=ScanStatus.done, result=None):
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        s = Scan(
            target=target,
            profile=ScanProfile.quick,
            status=status,
            created_by=admin.id,
            result=json.dumps(result, ensure_ascii=False) if result else None,
        )
        db.add(s)
        db.commit()
        db.refresh(s)
        return s.id
    finally:
        db.close()


# ── /status ──


def test_format_status_empty():
    assert "нет" in bot._format_status([])


def test_handle_status_lists_recent_scans(client, admin_headers, home_scope):
    scan_id = _make_scan()
    with patch("app.notifications.bot.send_message") as send:
        bot._handle_status()
    text = send.call_args[0][0]
    assert f"#{scan_id}" in text
    assert "192.168.1.50" in text


def test_status_keyboard_has_button_per_done_scan():
    scan_id = _make_scan(status=ScanStatus.done)
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(Scan.id == scan_id).all()
    finally:
        db.close()

    keyboard = bot._status_keyboard(scans)
    assert keyboard["inline_keyboard"] == [
        [{"text": f"📄 Отчёт #{scan_id}", "callback_data": f"report:{scan_id}"}]
    ]


def test_status_keyboard_skips_unfinished_scans():
    scan_id = _make_scan(status=ScanStatus.running)
    db = SessionLocal()
    try:
        scans = db.query(Scan).filter(Scan.id == scan_id).all()
    finally:
        db.close()

    assert bot._status_keyboard(scans) is None


def test_handle_status_sends_keyboard(client, admin_headers, home_scope):
    scan_id = _make_scan(status=ScanStatus.done)
    with patch("app.notifications.bot.send_message") as send:
        bot._handle_status()

    keyboard = send.call_args.kwargs["reply_markup"]
    buttons = [b["callback_data"] for row in keyboard["inline_keyboard"] for b in row]
    assert f"report:{scan_id}" in buttons


# ── /report ──


def test_handle_report_rejects_non_numeric_id():
    with patch("app.notifications.bot.send_message") as send:
        bot._handle_report("abc")
    assert "числовой" in send.call_args[0][0]


def test_handle_report_missing_scan():
    with patch("app.notifications.bot.send_message") as send:
        bot._handle_report("999999")
    assert "не найден" in send.call_args[0][0]


def test_handle_report_reportError_tells_user_why(client, admin_headers, home_scope):
    scan_id = _make_scan()
    with patch("app.notifications.bot.render_scan_report", side_effect=ReportError("нет Pango")):
        with patch("app.notifications.bot.send_message") as send:
            bot._handle_report(str(scan_id))
    assert "нет Pango" in send.call_args[0][0]


def test_handle_report_success_sends_document_and_logs(client, admin_headers, home_scope):
    scan_id = _make_scan()
    with patch("app.notifications.bot.render_scan_report", return_value=b"%PDF-1.7 fake"):
        with patch("app.notifications.bot.send_document", return_value=True) as send_doc:
            bot._handle_report(str(scan_id))

    send_doc.assert_called_once()
    filename, content = send_doc.call_args[0][:2]
    assert filename == f"androscanner-scan-{scan_id}.pdf"
    assert content == b"%PDF-1.7 fake"

    audit = client.get("/audit", headers=admin_headers).json()["items"]
    assert any(
        e["action"] == "export_report" and "telegram" in e["detail"] for e in audit
    )


def test_handle_report_failed_send_notifies_user(client, admin_headers, home_scope):
    scan_id = _make_scan()
    with patch("app.notifications.bot.render_scan_report", return_value=b"%PDF-1.7 fake"):
        with patch("app.notifications.bot.send_document", return_value=False):
            with patch("app.notifications.bot.send_message") as send:
                bot._handle_report(str(scan_id))
    assert send.called


# ── /ip ──


def test_detect_local_ip_returns_an_address():
    """Реальный вызов — не мокаем сокет: проверяем только форму ответа,
    не конкретное значение (оно зависит от сети машины, на которой
    гоняются тесты)."""
    ip = bot._detect_local_ip()
    assert ip is None or ip.count(".") == 3


def test_handle_ip_reports_detected_address():
    with patch("app.notifications.bot._detect_local_ip", return_value="192.168.1.50"):
        with patch("app.notifications.bot.send_message") as send:
            bot._handle_ip()
    assert "192.168.1.50" in send.call_args[0][0]


def test_handle_ip_includes_clickable_frontend_link():
    with patch("app.notifications.bot._detect_local_ip", return_value="192.168.1.50"):
        with patch("app.notifications.bot.send_message") as send:
            bot._handle_ip()
    text = send.call_args[0][0]
    assert f"http://192.168.1.50:{bot.FRONTEND_PORT}" in text


def test_handle_ip_reports_failure_when_undetectable():
    with patch("app.notifications.bot._detect_local_ip", return_value=None):
        with patch("app.notifications.bot.send_message") as send:
            bot._handle_ip()
    assert "не удалось" in send.call_args[0][0].lower()


def test_handle_command_dispatches_ip():
    with patch("app.notifications.bot._handle_ip") as h:
        bot._handle_command("/ip")
    h.assert_called_once()


# ── диспетчер команд ──


def test_handle_command_dispatches_status():
    with patch("app.notifications.bot._handle_status") as h:
        bot._handle_command("/status")
    h.assert_called_once()


def test_handle_command_dispatches_report_with_arg():
    with patch("app.notifications.bot._handle_report") as h:
        bot._handle_command("/report 42")
    h.assert_called_once_with("42")


def test_handle_command_strips_bot_username_suffix():
    with patch("app.notifications.bot._handle_status") as h:
        bot._handle_command("/status@androscanner_bot")
    h.assert_called_once()


def test_handle_command_help_for_unknown():
    with patch("app.notifications.bot.send_message") as send:
        bot._handle_command("/banana")
    assert "команда" in send.call_args[0][0].lower()


# ── нажатие inline-кнопки ──


def test_handle_callback_triggers_report():
    with patch("app.notifications.bot._handle_report") as report:
        with patch("app.notifications.bot.answer_callback_query") as ack:
            bot._handle_callback({"id": "cb1", "data": "report:42"})

    report.assert_called_once_with("42")
    ack.assert_called_once_with("cb1")


def test_handle_callback_ignores_non_numeric_id():
    with patch("app.notifications.bot._handle_report") as report:
        with patch("app.notifications.bot.answer_callback_query") as ack:
            bot._handle_callback({"id": "cb1", "data": "report:abc"})

    report.assert_not_called()
    assert ack.call_args.kwargs["text"] == "Неизвестное действие"


def test_handle_callback_unknown_action_does_not_crash():
    with patch("app.notifications.bot.answer_callback_query") as ack:
        bot._handle_callback({"id": "cb1", "data": "banana:1"})
    ack.assert_called_once()


# ── long polling: продвижение offset ──


def test_poll_once_advances_offset_past_last_update():
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "result": [{"update_id": 100}, {"update_id": 101}, {"update_id": 99}]
    }
    fake_client = MagicMock()
    fake_client.get.return_value = fake_response

    next_offset, updates = bot._poll_once(fake_client, offset=50)
    assert next_offset == 102
    assert len(updates) == 3


def test_poll_once_keeps_offset_when_no_updates():
    fake_response = MagicMock()
    fake_response.json.return_value = {"result": []}
    fake_client = MagicMock()
    fake_client.get.return_value = fake_response

    next_offset, updates = bot._poll_once(fake_client, offset=50)
    assert next_offset == 50
    assert updates == []


# ── старт/стоп ──


def test_start_is_noop_when_not_configured():
    """В тестовом окружении токен пуст (см. conftest) — поток не должен
    подниматься вообще, иначе он бы дрался за getUpdates с реальным
    dev-сервером, если тот запущен параллельно."""
    bot.start()
    assert bot._thread is None or not bot._thread.is_alive()


def test_start_registers_command_menu_when_configured():
    with patch("app.notifications.bot.is_configured", return_value=True):
        with patch("app.notifications.bot.set_commands") as set_cmds:
            with patch("app.notifications.bot.threading.Thread") as thread_cls:
                bot.start()

    set_cmds.assert_called_once_with(bot.COMMANDS)
    thread_cls.assert_called_once()
