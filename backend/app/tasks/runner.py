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

        # Скан могли отменить, пока задача ждала в очереди. Без этой
        # проверки отмена «queued» ничего бы не давала: воркер всё равно
        # взял бы задачу и пошёл сканировать.
        if scan.status == ScanStatus.cancelled:
            return

        scan.status = ScanStatus.running
        db.commit()

        try:
            result = run_nmap_scan(scan.target, scan.profile, db)
        except HTTPException as exc:
            # allowed-scope отсеял цель уже внутри движка
            _finish(db, scan, ScanStatus.failed, {"error": exc.detail})
            return
        except ScannerError as exc:
            _finish(db, scan, ScanStatus.failed, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 — иначе скан навсегда зависнет в running
            _finish(db, scan, ScanStatus.failed, {"error": f"Непредвиденная ошибка: {exc}"})
            return

        # Пока шёл скан, его могли отменить. Результат сохраняем — работа
        # уже сделана, выбрасывать её незачем, — но статус не перебиваем
        # на done: пользователь просил отменить, и в списке скан должен
        # остаться отменённым.
        db.refresh(scan)
        final = ScanStatus.cancelled if scan.status == ScanStatus.cancelled else ScanStatus.done
        _finish(db, scan, final, result)
    finally:
        db.close()


def _finish(db, scan: Scan, status: ScanStatus, payload: dict) -> None:
    scan.status = status
    scan.result = json.dumps(payload, ensure_ascii=False)
    db.commit()


@celery_app.task(name="scan.run")
def run_scan(scan_id: int) -> None:
    """Celery-обёртка над execute_scan. Вся логика — в execute_scan."""
    execute_scan(scan_id)


def dispatch_scan(scan_id: int, background_tasks: BackgroundTasks) -> None:
    """Ставит скан на выполнение выбранным способом."""
    if settings.use_celery:
        task = run_scan.delay(scan_id)
        # Сохраняем id задачи: без него отозвать её потом будет нечем
        db = SessionLocal()
        try:
            scan = db.get(Scan, scan_id)
            if scan is not None:
                scan.celery_task_id = task.id
                db.commit()
        finally:
            db.close()
    else:
        background_tasks.add_task(execute_scan, scan_id)


def revoke_scan_task(celery_task_id: str) -> bool:
    """Пытается снять задачу с воркера. Возвращает False, если не вышло.

    terminate=True убивает процесс, в котором идёт nmap: без этого
    отменённый скан продолжал бы работать до конца, просто его результат
    никого бы не интересовал.
    """
    try:
        celery_app.control.revoke(celery_task_id, terminate=True, signal="SIGTERM")
        return True
    except Exception:  # noqa: BLE001 — брокер может быть недоступен
        return False
