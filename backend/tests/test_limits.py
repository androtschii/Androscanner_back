"""Тесты пределов: длина полей журнала и размер сканируемой цели.

Обе проверки закрывают дефекты, найденные разбором кода, а не падением:

1. В AuditLog.detail попадает логин из формы входа, а он ничем не ограничен.
   Колонка — VARCHAR(512). SQLite длину не проверяет и сохранял 5000 символов;
   PostgreSQL выдал бы StringDataRightTruncation, и попытка входа обернулась
   бы 500. Третье подряд расхождение между этими базами.

2. Размер цели не ограничивался ничем. Скан 10.0.0.0/8 профилем full —
   это 16.7 млн адресов по 65535 портов: часы работы, упор в часовой лимит
   Celery, и в итоге failed без объяснения причины.
"""

from unittest.mock import MagicMock

import pytest

from app.database import SessionLocal
from app.models import AuditLog, ScanProfile
from app.models.scan import ACTION_MAX, DETAIL_MAX
from app.scanner import ScannerError
from app.scanner.engine import _assert_size_is_sane
from app.scanner.profiles import get_profile


# ── длина полей журнала ──


def test_long_detail_is_truncated_not_rejected(client):
    db = SessionLocal()
    try:
        entry = AuditLog(action="test_truncate", detail="A" * 5000)
        db.add(entry)
        db.commit()
        db.refresh(entry)
        assert len(entry.detail) == DETAIL_MAX
        assert entry.detail.endswith("…"), "обрезка должна быть видна"
    finally:
        db.close()


def test_long_action_is_truncated(client):
    db = SessionLocal()
    try:
        entry = AuditLog(action="B" * 500, detail="x")
        db.add(entry)
        db.commit()
        db.refresh(entry)
        assert len(entry.action) == ACTION_MAX
    finally:
        db.close()


def test_short_values_untouched(client):
    db = SessionLocal()
    try:
        entry = AuditLog(action="login", detail="admin")
        db.add(entry)
        db.commit()
        db.refresh(entry)
        assert entry.action == "login"
        assert entry.detail == "admin"
    finally:
        db.close()


def test_login_with_absurd_username_does_not_break(client):
    """Через форму входа логин попадает прямо в журнал."""
    r = client.post("/auth/login", data={"username": "Z" * 5000, "password": "x"})
    assert r.status_code == 401, "должен быть обычный отказ, а не 500"

    db = SessionLocal()
    try:
        entry = (
            db.query(AuditLog)
            .filter(AuditLog.action == "login_failed")
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert len(entry.detail) <= DETAIL_MAX
    finally:
        db.close()


def test_none_detail_is_left_alone(client):
    """Валидатор не должен спотыкаться на None."""
    db = SessionLocal()
    try:
        entry = AuditLog(action="test_none", detail=None)
        db.add(entry)
        db.commit()
    finally:
        db.close()


# ── размер цели ──


@pytest.mark.parametrize(
    "profile,target",
    [
        (ScanProfile.full, "10.0.0.0/8"),
        (ScanProfile.full, "192.168.0.0/16"),
        (ScanProfile.quick, "10.0.0.0/16"),
        (ScanProfile.discovery, "10.0.0.0/8"),
    ],
)
def test_oversized_target_rejected(profile, target):
    with pytest.raises(ScannerError) as exc:
        _assert_size_is_sane(target, get_profile(profile))
    message = str(exc.value)
    assert "рассчитан максимум" in message
    assert "Раздели диапазон" in message, "ошибка должна говорить, что делать"


@pytest.mark.parametrize(
    "profile,target",
    [
        (ScanProfile.full, "192.168.1.10"),
        (ScanProfile.full, "192.168.1.0/24"),
        (ScanProfile.quick, "192.168.0.0/20"),
        (ScanProfile.discovery, "192.168.0.0/16"),
    ],
)
def test_reasonable_target_passes(profile, target):
    """Контроль: предел не должен мешать обычной работе."""
    _assert_size_is_sane(target, get_profile(profile))


def test_message_names_both_numbers():
    """Пользователю нужны оба числа: сколько запросил и сколько можно."""
    with pytest.raises(ScannerError) as exc:
        _assert_size_is_sane("10.0.0.0/8", get_profile(ScanProfile.full))
    message = str(exc.value)
    assert "16 777 216" in message, "не названо фактическое число адресов"
    assert "256" in message, "не назван предел профиля"


def test_profiles_limits_reflect_their_cost():
    """Чем дороже профиль на один адрес, тем меньше адресов он берёт."""
    full = get_profile(ScanProfile.full).max_hosts
    quick = get_profile(ScanProfile.quick).max_hosts
    discovery = get_profile(ScanProfile.discovery).max_hosts
    assert full < quick < discovery


def test_size_check_runs_before_nmap(client):
    """Отказ должен случиться до запуска сканера, а не после."""
    from unittest.mock import patch

    db = MagicMock()
    scope = MagicMock()
    scope.cidr = "10.0.0.0/8"
    db.query.return_value.all.return_value = [scope]

    from app.scanner.engine import run_nmap_scan

    with patch("app.scanner.engine._build_scanner") as build:
        with pytest.raises(ScannerError):
            run_nmap_scan("10.0.0.0/8", ScanProfile.full, db)
        build.assert_not_called()


# ── набор из 9 профилей (Nessus-style) ──


def test_nine_profiles_exist():
    from app.scanner import PROFILES

    assert len(PROFILES) == 9


def test_every_profile_declares_privilege_honestly():
    """Каждый профиль должен явно объявлять, нужны ли ему права —
    молчаливого дефолта нет."""
    from app.scanner import PROFILES

    for prof in PROFILES.values():
        assert isinstance(prof.requires_privilege, bool)
        assert prof.max_hosts > 0


def test_ping_profile_needs_no_privilege_and_no_ports():
    prof = get_profile(ScanProfile.ping)
    assert prof.requires_privilege is False
    assert "-sn" in prof.arguments
    assert "-p" not in prof.arguments  # без портов вообще


def test_udp_profile_requires_privilege():
    """UDP-скан требует raw-сокетов, чтобы поймать ICMP port-unreachable."""
    assert get_profile(ScanProfile.udp).requires_privilege is True


def test_vuln_profile_does_not_require_privilege():
    """Скрипты uязвимостей работают поверх обычного connect-скана."""
    assert get_profile(ScanProfile.vuln).requires_privilege is False


def test_heaviest_profiles_have_smallest_limits():
    """vuln и udp — самые медленные на хост, поэтому и предел у них
    самый маленький."""
    vuln = get_profile(ScanProfile.vuln).max_hosts
    udp = get_profile(ScanProfile.udp).max_hosts
    full = get_profile(ScanProfile.full).max_hosts
    quick = get_profile(ScanProfile.quick).max_hosts
    assert vuln < full < quick
    assert udp < full


def test_all_nine_profiles_pass_size_check_for_single_host(client, admin_headers):
    """Одиночный IP должен проходить проверку размера для любого профиля —
    иначе профиль был бы бесполезен даже для одного хоста."""
    from app.scanner import PROFILES
    from app.scanner.engine import _assert_size_is_sane

    for prof in PROFILES.values():
        _assert_size_is_sane("192.168.1.10", prof)  # не должно бросить исключение
