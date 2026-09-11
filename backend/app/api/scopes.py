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
        network = ipaddress.ip_network(payload.cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Некорректный CIDR")

    # Приводим к каноническому виду: 192.168.1.77/24 и 192.168.1.0/24 —
    # одна и та же сеть, и храниться она должна одинаково. Без этого
    # проверка на дубликат по строке ничего не даст.
    canonical = str(network)

    existing = db.query(AllowedScope).filter(AllowedScope.cidr == canonical).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Диапазон {canonical} уже разрешён (запись #{existing.id}). "
                f"Дубликаты опасны: удалив одну запись, админ решил бы, что "
                f"отозвал доступ, а вторая продолжала бы его разрешать."
            ),
        )

    scope = AllowedScope(cidr=canonical, description=payload.description)
    db.add(scope)
    db.add(AuditLog(user_id=admin.id, action="add_scope", detail=canonical))
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
