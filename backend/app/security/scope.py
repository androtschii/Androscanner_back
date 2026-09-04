import ipaddress

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import AllowedScope


def target_in_scope(target: str, db: Session) -> bool:
    """Проверяет, что цель попадает хотя бы в один разрешённый диапазон.

    Единственная точка допуска к сканированию — используется и в API
    (быстрый отказ до постановки в очередь), и внутри самого движка
    сканирования, чтобы обход API не позволял сканировать чужие сети.
    """
    scopes = db.query(AllowedScope).all()
    if not scopes:
        return False
    try:
        target_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for scope in scopes:
        try:
            allowed = ipaddress.ip_network(scope.cidr, strict=False)
        except ValueError:
            continue
        if target_net.version != allowed.version:
            # subnet_of() кидает TypeError при сравнении IPv4 с IPv6
            continue
        if target_net.subnet_of(allowed):
            return True
    return False


def assert_in_scope(target: str, db: Session) -> None:
    """Кидает 403, если цель вне allowed scope. Вызывать перед любым сканом."""
    if not target_in_scope(target, db):
        raise HTTPException(
            status_code=403,
            detail="Цель вне разрешённого диапазона (allowed scope)",
        )
