"""Выполнение скана и запись результата в БД.

Сама задача (execute_scan) от способа запуска не зависит — её вызывает
тонкий диспетчер:

    dev (Windows)  → FastAPI BackgroundTasks, см. dispatch_scan ниже
    prod (Linux)   → Celery: run_scan.delay(scan_id)   ← Фаза 3

При переходе на Celery меняется только dispatch_scan, тело задачи остаётся.
"""

import json

from fastapi import BackgroundTasks, HTTPException

from app.database import SessionLocal
from app.models import Scan, ScanStatus
from app.scanner import ScannerError, run_nmap_scan


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


def dispatch_scan(scan_id: int, background_tasks: BackgroundTasks) -> None:
    """Ставит скан на выполнение. В Фазе 3 здесь будет run_scan.delay(scan_id)."""
    background_tasks.add_task(execute_scan, scan_id)
