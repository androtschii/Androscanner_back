import logging

from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import settings
from app.models import Role, User
from app.schemas import MIN_PASSWORD_LENGTH

logger = logging.getLogger(__name__)

# Пароли, которые точно нельзя оставлять в работающей системе
OBVIOUS_PASSWORDS = {"admin", "password", "123456", "changeme", "scanner"}


def _warn_if_weak(password: str) -> None:
    """Сидер обходит валидацию схемы, поэтому слабый пароль сюда пролезет.
    Молча его принимать нельзя — иначе admin/admin доживёт до боевой сети."""
    problems = []
    if password.lower() in OBVIOUS_PASSWORDS:
        problems.append("он есть в списке очевидных")
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"он короче {MIN_PASSWORD_LENGTH} символов")

    if problems:
        logger.warning(
            "!" * 70 + "\n"
            "ПАРОЛЬ АДМИНИСТРАТОРА НЕБЕЗОПАСЕН: %s.\n"
            "Смени его сразу после первого входа. Этот сканер видит твою сеть —\n"
            "доступ к нему стоит защищать не хуже, чем сам роутер.\n" + "!" * 70,
            " и ".join(problems),
        )


def seed_admin(db: Session) -> None:
    """Создаёт дефолтного администратора, если пользователей ещё нет."""
    exists = db.query(User).filter(User.username == settings.default_admin_username).first()
    if exists:
        return

    _warn_if_weak(settings.default_admin_password)

    admin = User(
        username=settings.default_admin_username,
        hashed_password=hash_password(settings.default_admin_password),
        role=Role.admin,
    )
    db.add(admin)
    db.commit()
    logger.info("Создан администратор: %s", settings.default_admin_username)
