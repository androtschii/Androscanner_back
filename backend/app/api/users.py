from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user, require_role
from app.auth.security import hash_password, verify_password
from app.database import get_db
from app.models import AuditLog, Role, User
from app.schemas import PasswordChange, UserCreate, UserOut

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    """Текущий пользователь — доступно всем авторизованным."""
    return user


@router.post("/me/password")
def change_own_password(
    payload: PasswordChange,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Смена собственного пароля. Доступна всем ролям: каждый отвечает
    за свой пароль сам, и запрещать это наблюдателю бессмысленно."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Текущий пароль неверен")
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="Новый пароль совпадает с текущим")

    user.hashed_password = hash_password(payload.new_password)
    db.add(AuditLog(user_id=user.id, action="change_password", detail=user.username))
    db.commit()

    # Отзыва токенов в системе нет: ранее выданные JWT останутся
    # действительными до истечения срока. Для домашнего инструмента
    # это приемлемо, но знать об этом надо — отражено в README.
    return {"status": "ok"}


@router.get("", response_model=list[UserOut], dependencies=[Depends(require_role(Role.admin))])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()


@router.post("", response_model=UserOut, dependencies=[Depends(require_role(Role.admin))])
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Пользователь уже существует")

    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.add(AuditLog(user_id=admin.id, action="create_user", detail=payload.username))
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", dependencies=[Depends(require_role(Role.admin))])
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Не найден")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить самого себя")

    db.delete(user)
    db.add(AuditLog(user_id=admin.id, action="delete_user", detail=user.username))
    db.commit()
    return {"deleted": user_id}
