"""Сводная аналитика по всем сканам.

Агрегация живёт на сервере, а не в браузере: иначе фронтенду пришлось бы
тянуть результаты всех сканов целиком ради нескольких чисел.
"""

import json
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.deps import get_current_user
from app.database import get_db
from app.models import Scan, ScanStatus, User
from app.schemas import AnalyticsSummary, NamedCount

router = APIRouter(prefix="/analytics", tags=["analytics"])

TOP_N = 8


def _counts(counter: Counter, limit: int | None = None) -> list[NamedCount]:
    items = counter.most_common(limit)
    return [NamedCount(name=str(name), count=count) for name, count in items]


@router.get("/summary", response_model=AnalyticsSummary)
def summary(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Сводка по всем сканам — доступна всем ролям, включая viewer."""
    scans = db.query(Scan).all()

    by_status = Counter(s.status.value for s in scans)
    by_profile = Counter(s.profile.value for s in scans)

    hosts: set[str] = set()
    services: Counter = Counter()
    ports: Counter = Counter()
    open_ports_total = 0

    for scan in scans:
        if scan.status != ScanStatus.done or not scan.result:
            continue
        try:
            data = json.loads(scan.result)
        except json.JSONDecodeError:
            continue
        if "hosts" not in data:
            continue

        for host in data["hosts"]:
            hosts.add(host.get("ip", ""))
            for port in host.get("ports", []):
                if port.get("state") != "open":
                    continue
                open_ports_total += 1
                ports[port["port"]] += 1
                if port.get("service"):
                    services[port["service"]] += 1

    hosts.discard("")

    return AnalyticsSummary(
        scans_total=len(scans),
        scans_by_status=_counts(by_status),
        scans_by_profile=_counts(by_profile),
        hosts_unique=len(hosts),
        open_ports_total=open_ports_total,
        top_services=_counts(services, TOP_N),
        top_ports=_counts(ports, TOP_N),
    )
