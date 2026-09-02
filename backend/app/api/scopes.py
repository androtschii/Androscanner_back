import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, require_role
from app.database import get_db
from app.models import AllowedScope, AuditLog, Role, User
from app.schemas import ScopeCreate, ScopeOut

router = APIRouter(prefix="/scopes", tags=["scopes"])


@router.get("", response_model=list[ScopeOut])
def list_scopes(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(AllowedScope).all()


@router.post("", response_model=ScopeOut, dependencies=[Depends(require_role(Role.admin))])
def add_scope(
    payload: ScopeCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    try:
        ipaddress.ip_network(payload.cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Некорректный CIDR")

    scope = AllowedScope(cidr=payload.cidr, description=payload.description)
    db.add(scope)
    db.add(AuditLog(user_id=admin.id, action="add_scope", detail=payload.cidr))
    db.commit()
    db.refresh(scope)
    return scope


@router.delete("/{scope_id}", dependencies=[Depends(require_role(Role.admin))])
def delete_scope(
    scope_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    scope = db.get(AllowedScope, scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="Не найден")
    db.delete(scope)
    db.add(AuditLog(user_id=admin.id, action="delete_scope", detail=scope.cidr))
    db.commit()
    return {"deleted": scope_id}
