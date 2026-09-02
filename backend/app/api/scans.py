import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, require_role
from app.database import get_db
from app.models import AllowedScope, AuditLog, Role, Scan, User
from app.schemas import ScanCreate, ScanOut

router = APIRouter(prefix="/scans", tags=["scans"])


def target_in_scope(target: str, db: Session) -> bool:
    """Проверяет, что цель попадает хотя бы в один разрешённый диапазон.

    Это главная защита: скан вне allowed scope не запускается.
    Поддерживает одиночный IP и CIDR-цель.
    """
    scopes = db.query(AllowedScope).all()
    if not scopes:
        return False
    try:
        target_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for scope in scopes:
        allowed = ipaddress.ip_network(scope.cidr, strict=False)
        if target_net.subnet_of(allowed):
            return True
    return False


@router.get("", response_model=list[ScanOut])
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
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Запуск скана — admin и analyst. Viewer сюда не пройдёт (403)."""
    if not target_in_scope(payload.target, db):
        raise HTTPException(
            status_code=403,
            detail="Цель вне разрешённого диапазона (allowed scope)",
        )

    scan = Scan(target=payload.target, profile=payload.profile, created_by=user.id)
    db.add(scan)
    db.add(AuditLog(user_id=user.id, action="create_scan", detail=payload.target))
    db.commit()
    db.refresh(scan)
    # TODO (Фаза 3): здесь отправляем задачу в Celery: run_scan.delay(scan.id)
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
