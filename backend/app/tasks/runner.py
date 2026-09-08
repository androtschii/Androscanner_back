"""Выполнение скана и запись результата в БД.

Тело задачи (execute_scan) от способа запуска не зависит. Запуск выбирает
dispatch_scan по настройке USE_CELERY:

    USE_CELERY=true   → Celery: run_scan.delay(scan_id)      (prod, Docker)
    USE_CELERY=false  → FastAPI BackgroundTasks              (dev на Windows)

Второй режим нужен потому, что нативного Redis под Windows нет, а Celery
официально не поддерживает Windows с версии 4.
"""

import json

from fastapi import BackgroundTasks, HTTPException

from app.config import settings
from app.database import SessionLocal
from app.models import Scan, ScanStatus
from app.scanner import ScannerError, run_nmap_scan
from app.tasks.celery_app import celery_app


def execute_scan(scan_id: int) -> None:
    """Прогоняет скан и сохраняет результат. Открывает свою сессию БД:
    задача живёт дольше HTTP-запроса, сессию запроса переиспользовать нельзя."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return

        scan.status = ScanStatus.running
        db.commit()

        try:
            result = run_nmap_scan(scan.target, scan.profile, db)
            scan.result = json.dumps(result, ensure_ascii=False)
            scan.status = ScanStatus.done
        except HTTPException as exc:
            # allowed-scope отсеял цель уже внутри движка
            scan.result = json.dumps({"error": exc.detail}, ensure_ascii=False)
            scan.status = ScanStatus.failed
        except ScannerError as exc:
            scan.result = json.dumps({"error": str(exc)}, ensure_ascii=False)
            scan.status = ScanStatus.failed
        except Exception as exc:  # noqa: BLE001 — иначе скан навсегда зависнет в running
            scan.result = json.dumps(
                {"error": f"Непредвиденная ошибка: {exc}"}, ensure_ascii=False
            )
            scan.status = ScanStatus.failed

        db.commit()
    finally:
        db.close()


@celery_app.task(name="scan.run")
def run_scan(scan_id: int) -> None:
    """Celery-обёртка над execute_scan. Вся логика — в execute_scan."""
    execute_scan(scan_id)


def dispatch_scan(scan_id: int, background_tasks: BackgroundTasks) -> None:
    """Ставит скан на выполнение выбранным способом."""
    if settings.use_celery:
        run_scan.delay(scan_id)
    else:
        background_tasks.add_task(execute_scan, scan_id)
