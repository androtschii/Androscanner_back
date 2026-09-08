"""Сводная аналитика по всем сканам.

Агрегация живёт на сервере, а не в браузере: иначе фронтенду пришлось бы
тянуть результаты всех сканов целиком ради нескольких чисел.
"""

import json
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.analytics import build_network_map, diff_results
from app.auth.deps import get_current_user
from app.database import get_db
from app.models import AllowedScope, Scan, ScanStatus, User
from app.schemas import AnalyticsSummary, NamedCount, NetworkMap, ScanDiff

router = APIRouter(prefix="/analytics", tags=["analytics"])

TOP_N = 8


def _load_done_scan(scan_id: int, db: Session, role: str) -> tuple[Scan, dict]:
    """Достаёт скан и разбирает его результат. Сравнивать можно только завершённые."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Скан {role} не найден")
    if scan.status != ScanStatus.done or not scan.result:
        raise HTTPException(
            status_code=400,
            detail=f"Скан {role} (#{scan_id}) не завершён успешно — сравнивать нечего",
        )
    try:
        data = json.loads(scan.result)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail=f"Результат скана #{scan_id} повреждён")
    if "hosts" not in data:
        raise HTTPException(status_code=400, detail=f"В результате скана #{scan_id} нет хостов")
    return scan, data


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


@router.get("/diff", response_model=ScanDiff)
def diff(
    base: int,
    compare: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Что изменилось в сети между двумя сканами.

    base — более ранний скан, compare — более поздний.
    """
    if base == compare:
        raise HTTPException(status_code=400, detail="Нужны два разных скана")

    base_scan, base_data = _load_done_scan(base, db, "base")
    compare_scan, compare_data = _load_done_scan(compare, db, "compare")

    return ScanDiff(
        base=base_scan,
        compare=compare_scan,
        **diff_results(base_data, compare_data),
    )


@router.get("/network", response_model=NetworkMap)
def network(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Карта сети: все найденные хосты, разложенные по разрешённым диапазонам.

    Это карта принадлежности, а не топология: профили сканирования не выясняют,
    как устройства соединены между собой.
    """
    scans = db.query(Scan).all()
    scopes = db.query(AllowedScope).all()
    return build_network_map(scans, scopes)
