from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import settings
from app.models import Role, User


def seed_admin(db: Session) -> None:
    """Создаёт дефолтного администратора, если пользователей ещё нет."""
    exists = db.query(User).filter(User.username == settings.default_admin_username).first()
    if exists:
        return
    admin = User(
        username=settings.default_admin_username,
        hashed_password=hash_password(settings.default_admin_password),
        role=Role.admin,
    )
    db.add(admin)
    db.commit()
    print(f"[seed] Создан администратор: {settings.default_admin_username}")
