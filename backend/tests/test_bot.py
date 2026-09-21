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
