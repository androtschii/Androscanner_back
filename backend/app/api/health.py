"""Проверка работоспособности.

Раньше /health отвечал «ok», не проверяя ничего. Такой ответ вреднее
отсутствия проверки: оркестратор считает контейнер живым, а он не может
достучаться до базы, и сканы молча копятся в очереди.
"""

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db

router = APIRouter(tags=["system"])


def _check_database(db: Session) -> tuple[bool, str]:
    try:
        db.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 — важен сам факт недоступности
        return False, f"недоступна: {type(exc).__name__}"


def _check_redis() -> tuple[bool, str]:
    """Redis нужен только когда сканы уходят в Celery."""
    if not settings.use_celery:
        return True, "не используется (USE_CELERY=false)"
    try:
        import redis

        redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2).ping()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, f"недоступен: {type(exc).__name__}"


def _check_nmap() -> tuple[bool, str]:
    """Без nmap сканирование невозможно, но API остаётся полезным:
    результаты прошлых сканов, отчёты и аналитика работают. Поэтому
    это предупреждение, а не отказ."""
    try:
        import nmap

        scanner = (
            nmap.PortScanner(nmap_search_path=(settings.nmap_path,))
            if settings.nmap_path
            else nmap.PortScanner()
        )
        return True, f"ok ({scanner.nmap_version()[0]}.{scanner.nmap_version()[1]})"
    except Exception as exc:  # noqa: BLE001
        return False, f"не найден: {type(exc).__name__}"


@router.get("/health")
def health(response: Response, db: Session = Depends(get_db)):
    """Возвращает 503, если отвалилось то, без чего сервис бесполезен.

    nmap в приговор не входит: без него нельзя запускать новые сканы,
    но всё уже собранное остаётся доступным.
    """
    db_ok, db_detail = _check_database(db)
    redis_ok, redis_detail = _check_redis()
    nmap_ok, nmap_detail = _check_nmap()

    healthy = db_ok and redis_ok
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if healthy else "degraded",
        "checks": {
            "database": {"ok": db_ok, "detail": db_detail},
            "redis": {"ok": redis_ok, "detail": redis_detail},
            "nmap": {"ok": nmap_ok, "detail": nmap_detail, "critical": False},
        },
    }
