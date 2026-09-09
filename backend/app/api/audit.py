from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.database import get_db
from app.models import AuditLog, Role
from app.schemas import AuditLogOut, Page

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditLogOut], dependencies=[Depends(require_role(Role.admin))])
def list_audit_log(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, description="Фильтр по типу действия"),
):
    """Журнал действий — видят только admin.

    Раньше отдавалось жёстко 200 последних записей без возможности листать:
    всё, что старше, было недоступно в принципе.
    """
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)

    total = query.count()
    items = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return Page(items=items, total=total, limit=limit, offset=offset)
