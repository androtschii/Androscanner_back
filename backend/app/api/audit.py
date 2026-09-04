from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.database import get_db
from app.models import AuditLog, Role
from app.schemas import AuditLogOut

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut], dependencies=[Depends(require_role(Role.admin))])
def list_audit_log(db: Session = Depends(get_db), limit: int = 200):
    """Журнал действий — видят только admin."""
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
