from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, require_role
from app.database import get_db
from app.models import AuditLog, Role, Scan, ScanStatus, User
from app.reports import ReportError, render_scan_report
from app.schemas import Page, ScanCreate, ScanOut, ScanSummary
from app.security.scope import assert_in_scope
from app.tasks import dispatch_scan, revoke_scan_task

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=Page[ScanSummary])
def list_scans(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: ScanStatus | None = None,
    target: str | None = Query(None, description="Поиск по подстроке цели"),
):
    """Просмотр сканов — доступно всем ролям (включая viewer).

    Пагинация обязательна: без неё эндпоинт отдавал бы все сканы разом,
    и на паре тысяч записей ответ измерялся бы мегабайтами.
    """
    query = db.query(Scan)
    if status is not None:
        query = query.filter(Scan.status == status)
    if target:
        # icontains вместо contains: LIKE регистрозависим в PostgreSQL
        # и регистронезависим в SQLite, то есть один и тот же поиск давал
        # бы разные результаты на разных базах. icontains ведёт себя
        # одинаково на обеих.
        #
        # autoescape обязателен: без него поиск по «%» превращается
        # в подстановочный знак и возвращает вообще всё, а «_»
        # совпадает с любым символом.
        query = query.filter(Scan.target.icontains(target, autoescape=True))

    total = query.count()
    items = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Не найден")
    return scan


@router.post(
    "",
    response_model=ScanOut,
    dependencies=[Depends(require_role(Role.admin, Role.analyst))],
)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Запуск скана — admin и analyst. Viewer сюда не пройдёт (403)."""
    assert_in_scope(payload.target, db)

    scan = Scan(target=payload.target, profile=payload.profile, created_by=user.id)
    db.add(scan)
    db.add(AuditLog(user_id=user.id, action="create_scan", detail=payload.target))
    db.commit()
    db.refresh(scan)

    # Фаза 3 заменит диспетчер на Celery, тело задачи останется прежним
    dispatch_scan(scan.id, background_tasks)
    return scan


@router.delete("/{scan_id}", dependencies=[Depends(require_role(Role.admin))])
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    """Удаление — только admin."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Не найден")
    db.delete(scan)
    db.add(AuditLog(user_id=admin.id, action="delete_scan", detail=str(scan_id)))
    db.commit()
    return {"deleted": scan_id}


@router.get("/{scan_id}/report.pdf")
def scan_report(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """PDF-отчёт по скану. Доступен всем ролям — это чтение."""
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Не найден")

    try:
        pdf = render_scan_report(scan, requested_by=user.username)
    except ReportError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    db.add(AuditLog(user_id=user.id, action="export_report", detail=f"scan {scan_id}"))
    db.commit()

    filename = f"androscanner-scan-{scan_id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Отменяет скан. Может админ или тот, кто его запустил.

    Viewer сюда не попадёт: он не может создавать сканы, значит и своих
    у него нет, а чужие отменять права не имеет.
    """
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Не найден")

    if user.role != Role.admin and scan.created_by != user.id:
        raise HTTPException(
            status_code=403, detail="Отменить можно только свой скан"
        )

    if scan.status in (ScanStatus.done, ScanStatus.failed, ScanStatus.cancelled):
        raise HTTPException(
            status_code=409,
            detail=f"Скан уже завершён со статусом «{scan.status.value}» — отменять нечего",
        )

    # Снимаем задачу с воркера, если она туда попала. В режиме
    # BackgroundTasks отзывать нечего: задача проверит статус сама
    # и выйдет, не начав сканировать.
    if scan.celery_task_id:
        revoke_scan_task(scan.celery_task_id)

    scan.status = ScanStatus.cancelled
    db.add(AuditLog(user_id=user.id, action="cancel_scan", detail=str(scan_id)))
    db.commit()
    db.refresh(scan)
    return scan
