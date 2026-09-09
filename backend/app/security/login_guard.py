"""Защита входа от перебора паролей.

Счётчик держится в audit-log, а не в памяти процесса: так он переживает
перезапуск и не обнуляется, если бэкенд поднят в нескольких экземплярах.
Заодно закрывается пробел в аудите — неудачные входы раньше не логировались
вообще, и подбор пароля не оставлял следов.
"""

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import AuditLog

ACTION_FAILED = "login_failed"

MAX_ATTEMPTS = 5
WINDOW_MINUTES = 15


def _recent_failures(username: str, db: Session) -> int:
    since = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)
    return (
        db.query(AuditLog)
        .filter(
            AuditLog.action == ACTION_FAILED,
            AuditLog.detail == username,
            AuditLog.created_at >= since,
        )
        .count()
    )


def assert_not_locked_out(username: str, db: Session) -> None:
    """Кидает 429, если по этому логину слишком много неудач подряд."""
    if _recent_failures(username, db) >= MAX_ATTEMPTS:
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


def clear_failures(username: str, db: Session) -> None:
    """После успешного входа счётчик обнуляем, чтобы старые неудачи
    не копились и не блокировали живого пользователя."""
    since = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)
    db.query(AuditLog).filter(
        AuditLog.action == ACTION_FAILED,
        AuditLog.detail == username,
        AuditLog.created_at >= since,
    ).delete(synchronize_session=False)
    db.commit()
