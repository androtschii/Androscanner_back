"""Тесты движка сканирования.

Реальные сканы здесь не запускаются: nmap подменяется моком. Проверяется
логика вокруг него — allowed-scope, права, разбор результата.
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.database import SessionLocal
from app.models import AllowedScope, ScanProfile
from app.scanner import ScannerError, get_profile, run_nmap_scan
from app.scanner.parser import parse_scan


@pytest.fixture
def db(client):
    """Сессия к тестовой БД. Зависит от client, чтобы миграции уже прошли."""
    session = SessionLocal()
    if not session.query(AllowedScope).filter(AllowedScope.cidr == "192.168.1.0/24").first():
        session.add(AllowedScope(cidr="192.168.1.0/24", description="test"))
        session.commit()
    yield session
    session.close()


# ── allowed-scope: вторая линия защиты внутри движка ──


def test_engine_blocks_target_outside_scope(db):
    """Движок вызван напрямую, в обход API — цель вне scope всё равно отсекается."""
    with pytest.raises(HTTPException) as exc:
        run_nmap_scan("8.8.8.8", ScanProfile.quick, db)
    assert exc.value.status_code == 403


def test_engine_blocks_before_touching_nmap(db):
    """Проверка scope стоит ДО запуска nmap — сканер даже не создаётся."""
    with patch("app.scanner.engine._build_scanner") as build:
        with pytest.raises(HTTPException):
            run_nmap_scan("8.8.8.8", ScanProfile.quick, db)
        build.assert_not_called()


# ── права ──


def test_privileged_profile_fails_without_rights(db):
    """Профиль, требующий raw-сокетов, падает с внятной ошибкой, а не молча слабеет."""
    with patch("app.scanner.engine.has_raw_socket_privilege", return_value=False):
        with pytest.raises(ScannerError) as exc:
            run_nmap_scan("192.168.1.10", ScanProfile.full, db)
    assert "администратора" in str(exc.value)


def test_unprivileged_profile_runs_without_rights(db):
    """quick — connect-скан, прав не требует и до nmap доходит."""
    scanner = MagicMock()
    scanner.all_hosts.return_value = []
    with patch("app.scanner.engine.has_raw_socket_privilege", return_value=False):
        with patch("app.scanner.engine._build_scanner", return_value=scanner):
            result = run_nmap_scan("192.168.1.10", ScanProfile.quick, db)
    scanner.scan.assert_called_once()
    assert result["profile"] == "quick"


def test_profiles_declare_privilege_honestly():
    assert get_profile(ScanProfile.quick).requires_privilege is False
    assert get_profile(ScanProfile.full).requires_privilege is True
    assert get_profile(ScanProfile.discovery).requires_privilege is True


# ── парсер ──


def test_parser_normalizes_host_and_ports():
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["192.168.1.10"]
    scanner.__getitem__.return_value = {
        "addresses": {"ipv4": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
        "vendor": {"AA:BB:CC:DD:EE:FF": "Raspberry Pi Foundation"},
        "hostnames": [{"name": "pi.local", "type": "PTR"}],
        "status": {"state": "up"},
        "osmatch": [{"name": "Linux 5.X", "accuracy": "95"}],
        "tcp": {
            22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.4", "cpe": "cpe:/a:openbsd:openssh:8.4"},
            80: {"state": "closed", "name": "http", "product": "", "version": "", "cpe": ""},
        },
    }

    result = parse_scan(scanner, "full", "-sS -sV -O")
    host = result["hosts"][0]

    assert host["ip"] == "192.168.1.10"
    assert host["mac"] == "AA:BB:CC:DD:EE:FF"
    assert host["vendor"] == "Raspberry Pi Foundation"
    assert host["hostnames"] == ["pi.local"]
    assert host["os"] == [{"name": "Linux 5.X", "accuracy": 95}]

    ssh = next(p for p in host["ports"] if p["port"] == 22)
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert ssh["cpe"] == ["cpe:/a:openbsd:openssh:8.4"]

    # закрытые порты не считаются открытыми
    assert result["stats"] == {"hosts_total": 1, "hosts_up": 1, "open_ports": 1}


def test_parser_handles_host_without_optional_fields():
    """Скан без -sV/-O не отдаёт osmatch и vendor — парсер не должен падать."""
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["127.0.0.1"]
    scanner.__getitem__.return_value = {
        "addresses": {"ipv4": "127.0.0.1"},
        "hostnames": [],
        "status": {"state": "up"},
        "tcp": {135: {"state": "open", "name": "msrpc"}},
    }

    host = parse_scan(scanner, "quick", "-sT")["hosts"][0]
    assert host["mac"] is None
    assert host["vendor"] is None
    assert host["os"] == []
    assert host["ports"][0]["product"] == ""
