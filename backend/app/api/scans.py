from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, require_role
from app.database import get_db
from app.models import AuditLog, Role, Scan, User
from app.schemas import ScanCreate, ScanOut, ScanSummary
from app.security.scope import assert_in_scope
from app.tasks import dispatch_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Просмотр сканов — доступно всем ролям (включая viewer)."""
    return db.query(Scan).order_by(Scan.created_at.desc()).all()


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
