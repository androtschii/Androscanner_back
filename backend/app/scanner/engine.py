"""Движок сканирования поверх python-nmap.

ГЛАВНОЕ ПРАВИЛО: сканировать можно только свои сети.

Проверка allowed-scope стоит здесь, внутри движка, а не только в API.
Это вторая линия защиты: даже если кто-то вызовет run_nmap_scan() в обход
HTTP-слоя (из скрипта, из Celery-задачи, из консоли), скан по цели вне
белого списка не уйдёт.
"""

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
