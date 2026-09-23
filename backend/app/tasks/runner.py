"""Выполнение скана и запись результата в БД.

Тело задачи (execute_scan) от способа запуска не зависит. Запуск выбирает
dispatch_scan по настройке USE_CELERY:

    USE_CELERY=true   → Celery: run_scan.delay(scan_id)      (prod, Docker)
    USE_CELERY=false  → FastAPI BackgroundTasks              (dev на Windows)

Второй режим нужен потому, что нативного Redis под Windows нет, а Celery
официально не поддерживает Windows с версии 4.
"""

import json
import uuid

from fastapi import BackgroundTasks, HTTPException

from app.analytics.diff import diff_results
from app.config import settings
from app.database import SessionLocal
from app.models import Scan, ScanStatus
from app.models.types import utcnow
from app.notifications import notify_anomaly_detected, notify_scan_finished
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
        scan.updated_at = utcnow()
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
    scan.updated_at = utcnow()
    scan.result = json.dumps(payload, ensure_ascii=False)
    db.commit()
    notify_scan_finished(scan.target, status.value, payload.get("stats", {}).get("hosts_up"))
    if status == ScanStatus.done:
        _check_anomalies(db, scan, payload)


def _check_anomalies(db, scan: Scan, payload: dict) -> None:
    """Сравнивает свежий скан с предыдущим завершённым сканом той же цели
    и уведомляет в Telegram, если появилось что-то новое.

    Закрывшиеся порты и пропавшие хосты не считаются аномалией — они не
    расширяют поверхность атаки, а nmap мог просто не застать временно
    выключенное устройство. Шумели бы напрасно.
    """
    previous = (
        db.query(Scan)
        .filter(
            Scan.target == scan.target,
            Scan.status == ScanStatus.done,
            Scan.result.isnot(None),
            Scan.created_at < scan.created_at,
            Scan.id != scan.id,
        )
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not previous or not previous.result:
        return

    try:
        previous_data = json.loads(previous.result)
    except json.JSONDecodeError:
        return

    diff = diff_results(previous_data, payload)
    summary = diff["summary"]
    if summary["hosts_added"] or summary["ports_opened"]:
        notify_anomaly_detected(scan.target, summary)


@celery_app.task(name="scan.run")
def run_scan(scan_id: int) -> None:
    """Celery-обёртка над execute_scan. Вся логика — в execute_scan."""
    execute_scan(scan_id)


def dispatch_scan(scan_id: int, background_tasks: BackgroundTasks) -> None:
    """Ставит скан на выполнение выбранным способом."""
    if not settings.use_celery:
        background_tasks.add_task(execute_scan, scan_id)
        return

    # Идентификатор задачи генерируем САМИ и записываем ДО постановки
    # в очередь. Раньше было наоборот: delay() публиковал задачу, и только
    # потом id сохранялся в базу. В этом промежутке воркер уже мог взять
    # задачу, а запрос на отмену — увидеть celery_task_id = None и ничего
    # не отозвать: скан помечался отменённым, а nmap продолжал работать.
    task_id = str(uuid.uuid4())

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.celery_task_id = task_id
        db.commit()
    finally:
        db.close()

    run_scan.apply_async(args=[scan_id], task_id=task_id)


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
