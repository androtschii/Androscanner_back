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
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    """Отключает пользователя вместо удаления.

    Раньше здесь было настоящее удаление строки, и это давало две беды.

    На SQLite (dev) внешние ключи по умолчанию не проверяются: удаление
    проходило, а сканы и записи журнала оставались ссылаться на
    несуществующего пользователя. На PostgreSQL (prod) то же удаление
    упало бы с нарушением целостности и вернуло 500.

    Но главное даже не это. В инструменте с audit-log удаление
    пользователя стирает ответственность: кто запускал сканы — уже
    не узнать. Поэтому пользователь отключается, а история остаётся.

    Полезный побочный эффект: get_current_user проверяет is_active,
    поэтому токен отключённого перестаёт работать сразу — не дожидаясь
    истечения срока. Отзыва JWT в системе нет, и здесь это его заменяет.
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Не найден")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Нельзя отключить самого себя")
    if not user.is_active:
        raise HTTPException(status_code=409, detail="Пользователь уже отключён")

    user.is_active = False
    db.add(AuditLog(user_id=admin.id, action="deactivate_user", detail=user.username))
    db.commit()
    return {"deactivated": user_id}


@router.post(
    "/{user_id}/activate",
    response_model=UserOut,
    dependencies=[Depends(require_role(Role.admin))],
)
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_user),
):
    """Включает отключённого пользователя обратно."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Не найден")
    if user.is_active:
        raise HTTPException(status_code=409, detail="Пользователь уже активен")

    user.is_active = True
    db.add(AuditLog(user_id=admin.id, action="activate_user", detail=user.username))
    db.commit()
    db.refresh(user)
    return user
