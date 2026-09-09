"""Защита входа от перебора паролей.

Счётчик живёт в audit-log, а не в памяти процесса: так он переживает
перезапуск и не обнуляется, если бэкенд поднят в нескольких экземплярах.
Заодно закрывается пробел в аудите — неудачные входы раньше не логировались
вообще, и подбор пароля не оставлял следов.

ВАЖНО: журнал только пополняется. Первая версия этого модуля удаляла
записи о неудачах после успешного входа — «чтобы счётчик не копился».
Последствие: злоумышленник, подобравший пароль с пятой попытки, стирал
следы своих четырёх неудач самим фактом успеха. Ровно те записи, ради
которых журнал и нужен, исчезали в момент удачной атаки.

Теперь счётчик отсчитывается ОТ ПОСЛЕДНЕГО УСПЕШНОГО ВХОДА: тот же
эффект «не копится», но история цела.
"""

from datetime import timedelta

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.models.types import utcnow

ACTION_FAILED = "login_failed"
ACTION_SUCCESS = "login"

MAX_ATTEMPTS = 5
WINDOW_MINUTES = 15


def _count_since_last_success(username: str, db: Session) -> int:
    """Неудачные попытки в пределах окна, но не раньше последнего
    успешного входа."""
    since = utcnow() - timedelta(minutes=WINDOW_MINUTES)

    last_success = (
        db.query(AuditLog.created_at)
        .filter(AuditLog.action == ACTION_SUCCESS, AuditLog.detail == username)
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    # Успешный вход обнуляет счётчик, но не стирает записи
    if last_success and last_success[0] > since:
        since = last_success[0]

    return (
        db.query(AuditLog)
        .filter(
            AuditLog.action == ACTION_FAILED,
            AuditLog.detail == username,
            AuditLog.created_at > since,
        )
        .count()
    )


def assert_not_locked_out(username: str, db: Session) -> None:
    """Кидает 429, если по этому логину слишком много неудач подряд."""
    if _count_since_last_success(username, db) >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Слишком много неудачных попыток входа. "
                f"Попробуй через {WINDOW_MINUTES} минут."
            ),
            headers={"Retry-After": str(WINDOW_MINUTES * 60)},
        )


def record_failure(username: str, db: Session) -> None:
    """Отмечает неудачную попытку. user_id не пишем: пользователя может
    не существовать, да и утверждать, что попытка принадлежит ему, нельзя."""
    db.add(AuditLog(user_id=None, action=ACTION_FAILED, detail=username))
    db.commit()
