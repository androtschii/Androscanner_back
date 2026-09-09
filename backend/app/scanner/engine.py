"""Движок сканирования поверх python-nmap.

ГЛАВНОЕ ПРАВИЛО: сканировать можно только свои сети.

Проверка allowed-scope стоит здесь, внутри движка, а не только в API.
Это вторая линия защиты: даже если кто-то вызовет run_nmap_scan() в обход
HTTP-слоя (из скрипта, из Celery-задачи, из консоли), скан по цели вне
белого списка не уйдёт.
"""

import ipaddress

import nmap
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ScanProfile
from app.scanner.parser import parse_scan
from app.scanner.privileges import has_raw_socket_privilege, privilege_hint
from app.scanner.profiles import get_profile
from app.security.scope import assert_in_scope


class ScannerError(RuntimeError):
    """Скан не удалось выполнить — текст пойдёт пользователю в поле result."""


def _assert_size_is_sane(target: str, prof) -> None:
    """Отказывает, если цель слишком велика для выбранного профиля.

    Без этой проверки скан 10.0.0.0/8 профилем full (16.7 млн адресов
    по 65535 портов) принимался бы молча, шёл бы часами, упёрся
    в часовой лимит Celery и вернулся как failed без объяснения причины.
    Лучше отказать сразу и сказать, что делать.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        # Сюда не дойти: assert_in_scope уже отсеял всё, что не IP и не CIDR
        return

    if network.num_addresses > prof.max_hosts:
        # Разряды разделяем пробелом, как принято в русском. Через
        # формат, а не replace(",", " ") по всей строке: тот заодно
        # съедал бы обычные запятые предложения.
        found = f"{network.num_addresses:,}".replace(",", " ")
        allowed = f"{prof.max_hosts:,}".replace(",", " ")
        raise ScannerError(
            f"Цель {target} содержит {found} адресов, а профиль «{prof.name}» "
            f"рассчитан максимум на {allowed}. Это {prof.description} — "
            f"на таком объёме скан шёл бы часами и упёрся бы в лимит времени "
            f"задачи. Раздели диапазон на части или возьми более лёгкий профиль."
        )


def _build_scanner() -> nmap.PortScanner:
    """Создаёт PortScanner, подсказывая путь к nmap, если его нет в PATH."""
    try:
        if settings.nmap_path:
            return nmap.PortScanner(nmap_search_path=(settings.nmap_path,))
        return nmap.PortScanner()
    except nmap.PortScannerError as exc:
        raise ScannerError(
            "nmap не найден. Установи его и укажи путь в NMAP_PATH, "
            f"если он не в PATH. Подробности: {exc}"
        ) from exc


def run_nmap_scan(target: str, profile: ScanProfile, db: Session) -> dict:
    """Запускает скан. Кидает HTTPException(403), если цель вне allowed-scope."""
    # ── Вторая линия защиты: без этого дальше не идём ──
    assert_in_scope(target, db)

    prof = get_profile(profile)
    _assert_size_is_sane(target, prof)

    if prof.requires_privilege and not has_raw_socket_privilege():
        raise ScannerError(
            f"Профиль «{prof.name}» ({prof.description}) требует прав администратора "
            f"для доступа к raw-сокетам, но процесс запущен без них. {privilege_hint()} "
            f"Либо используй профиль «quick» — ему права не нужны."
        )

    scanner = _build_scanner()
    try:
        scanner.scan(hosts=target, arguments=prof.arguments)
    except nmap.PortScannerError as exc:
        raise ScannerError(f"nmap завершился с ошибкой: {exc}") from exc

    return parse_scan(scanner, prof.name, prof.arguments)
