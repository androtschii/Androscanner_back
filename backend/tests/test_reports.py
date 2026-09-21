"""Тесты PDF-отчётов.

Вёрстка проверяется на уровне HTML — это не требует GTK. Сам путь
HTML→PDF проверяется отдельно и пропускается, если библиотек нет.
"""

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from app.database import SessionLocal
from app.models import Scan, ScanProfile, ScanStatus, User
from app.reports import ReportError, render_scan_html


def _scan(status=ScanStatus.done, result=None):
    return Scan(
        id=1,
        target="192.168.1.10",
        profile=ScanProfile.quick,
        status=status,
        created_by=1,
        created_at=datetime(2026, 3, 1, 12, 30, tzinfo=timezone.utc),
        result=json.dumps(result, ensure_ascii=False) if result else None,
    )


def _good_result():
    return {
        "scanned_at": "2026-03-01T12:30:00+00:00",
        "profile": "quick",
        "arguments": "-sT -T4 --top-ports 100",
        "hosts": [
            {
                "ip": "192.168.1.10",
                "hostnames": ["nas.local"],
                "state": "up",
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Synology",
                "os": [{"name": "Linux 5.X", "accuracy": 96}],
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                     "product": "OpenSSH", "version": "9.6", "cpe": []},
                    {"port": 80, "protocol": "tcp", "state": "closed", "service": "http",
                     "product": "", "version": "", "cpe": []},
                ],
            }
        ],
        "stats": {"hosts_total": 1, "hosts_up": 1, "open_ports": 1},
    }


# ── вёрстка ──


def test_html_contains_scan_facts():
    html = render_scan_html(_scan(result=_good_result()), "admin")
    assert "192.168.1.10" in html
    assert "nas.local" in html
    assert "AA:BB:CC:DD:EE:FF" in html
    assert "Synology" in html
    assert "Linux 5.X" in html
    assert "OpenSSH 9.6" in html
    assert "-sT -T4 --top-ports 100" in html


def test_html_states_scope_restriction():
    """В отчёте должно быть сказано, что скан шёл только по разрешённым сетям."""
    html = render_scan_html(_scan(result=_good_result()), "admin")
    assert "allowed scope" in html


def test_html_names_who_requested_it():
    html = render_scan_html(_scan(result=_good_result()), "vasya")
    assert "vasya" in html


def test_failed_scan_shows_error_not_hosts():
    html = render_scan_html(
        _scan(status=ScanStatus.failed, result={"error": "Профиль full требует прав администратора"}),
        "admin",
    )
    assert "Профиль full требует прав администратора" in html
    assert "Скан не выполнен" in html


def test_broken_result_does_not_crash_rendering():
    scan = _scan()
    scan.result = "{не json"
    html = render_scan_html(scan, "admin")
    assert "повреждён" in html


def test_unfinished_scan_renders_placeholder():
    html = render_scan_html(_scan(status=ScanStatus.queued), "admin")
    assert "не завершён" in html


def test_html_escapes_hostile_hostname():
    """Имя хоста приходит из сети — его нельзя вставлять в HTML как есть."""
    result = _good_result()
    result["hosts"][0]["hostnames"] = ["<script>alert(1)</script>"]
    html = render_scan_html(_scan(result=result), "admin")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_flags_risky_open_port():
    result = _good_result()
    result["hosts"][0]["ports"].append(
        {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet",
         "product": "", "version": "", "cpe": []}
    )
    html = render_scan_html(_scan(result=result), "admin")
    assert 'class="risk-badge risk-high"' in html
    assert "текстом" in html


def test_html_does_not_flag_closed_risky_port():
    """Закрытый порт неэксплуатируем — бейдж риска был бы ложной тревогой."""
    result = _good_result()
    result["hosts"][0]["ports"].append(
        {"port": 23, "protocol": "tcp", "state": "closed", "service": "telnet",
         "product": "", "version": "", "cpe": []}
    )
    html = render_scan_html(_scan(result=result), "admin")
    assert 'class="risk-badge' not in html


# ── обработка отсутствия GTK ──


def test_missing_gtk_gives_actionable_error():
    from app.reports import pdf as pdf_module

    with patch.object(pdf_module, "_load_weasyprint",
                      side_effect=ReportError("нет GTK, поставь GtkD.GtkPlusRuntime.x64")):
        with pytest.raises(ReportError) as exc:
            pdf_module.render_scan_report(_scan(result=_good_result()), "admin")
    assert "GtkD.GtkPlusRuntime.x64" in str(exc.value)


# ── эндпоинт ──


def test_report_404_for_missing_scan(client, admin_headers):
    r = client.get("/scans/999999/report.pdf", headers=admin_headers)
    assert r.status_code == 404


def test_report_returns_503_when_gtk_missing(client, admin_headers):
    """Без GTK пользователь должен получить объяснение, а не 500."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        s = Scan(target="192.168.1.10", profile=ScanProfile.quick, status=ScanStatus.done,
                 created_by=admin.id, result=json.dumps(_good_result(), ensure_ascii=False))
        db.add(s)
        db.commit()
        db.refresh(s)
        scan_id = s.id
    finally:
        db.close()

    with patch("app.api.scans.render_scan_report",
               side_effect=ReportError("PDF-отчёты требуют библиотек GTK")):
        r = client.get(f"/scans/{scan_id}/report.pdf", headers=admin_headers)

    assert r.status_code == 503
    assert "GTK" in r.json()["detail"]


def test_report_is_pdf_and_logged(client, admin_headers):
    """Успешная выгрузка отдаёт PDF и попадает в audit-log."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        s = Scan(target="192.168.1.11", profile=ScanProfile.quick, status=ScanStatus.done,
                 created_by=admin.id, result=json.dumps(_good_result(), ensure_ascii=False))
        db.add(s)
        db.commit()
        db.refresh(s)
        scan_id = s.id
    finally:
        db.close()

    with patch("app.api.scans.render_scan_report", return_value=b"%PDF-1.7 fake"):
        r = client.get(f"/scans/{scan_id}/report.pdf", headers=admin_headers)

    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert f"androscanner-scan-{scan_id}.pdf" in r.headers["content-disposition"]

    audit = client.get("/audit", headers=admin_headers).json()["items"]
    assert any(e["action"] == "export_report" for e in audit)


def test_report_available_to_viewer(client, viewer_headers, admin_headers):
    """Отчёт — это чтение, наблюдателю доступен."""
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        s = Scan(target="192.168.1.12", profile=ScanProfile.quick, status=ScanStatus.done,
                 created_by=admin.id, result=json.dumps(_good_result(), ensure_ascii=False))
        db.add(s)
        db.commit()
        db.refresh(s)
        scan_id = s.id
    finally:
        db.close()

    with patch("app.api.scans.render_scan_report", return_value=b"%PDF-1.7 fake"):
        r = client.get(f"/scans/{scan_id}/report.pdf", headers=viewer_headers)
    assert r.status_code == 200
