"""Сводная карта сети по всем успешным сканам.

ВАЖНО про «граф»: наши профили сканирования не выясняют топологию — нет ни
traceroute, ни опроса таблиц маршрутизации. Поэтому здесь строится карта
ПРИНАДЛЕЖНОСТИ (какой хост в какой разрешённой подсети), а не обнаруженная
структура связей. Рёбра «подсеть — хост» отражают вхождение адреса в CIDR,
и ничего больше.

Идея визуализации сети взята из дашборда WebMap. Код свой: WebMap под GPL-3.0,
копировать оттуда нельзя.
"""

import ipaddress
import json
from typing import Any

from app.models import AllowedScope, Scan, ScanStatus


def _merge_host(into: dict[str, Any], host: dict[str, Any], seen_at: str) -> None:
    """Данные о хосте из более свежего скана дополняют накопленные."""
    open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]

    if seen_at > into["last_seen"]:
        into["last_seen"] = seen_at
        into["open_ports"] = len(open_ports)
        into["services"] = sorted({p["service"] for p in open_ports if p.get("service")})

    # MAC, вендор, ОС и имена появляются только в некоторых профилях —
    # не затираем найденное раньше пустым значением из более свежего скана
    if host.get("mac") and not into["mac"]:
        into["mac"] = host["mac"]
    if host.get("vendor") and not into["vendor"]:
        into["vendor"] = host["vendor"]
    if host.get("os") and not into["os"]:
        into["os"] = host["os"][0]["name"]
    for name in host.get("hostnames", []):
        if name not in into["hostnames"]:
            into["hostnames"].append(name)


def build_network_map(scans: list[Scan], scopes: list[AllowedScope]) -> dict[str, Any]:
    """Собирает хосты из всех завершённых сканов и раскладывает по подсетям."""
    hosts: dict[str, dict[str, Any]] = {}

    for scan in scans:
        if scan.status != ScanStatus.done or not scan.result:
            continue
        try:
            data = json.loads(scan.result)
        except json.JSONDecodeError:
            continue

        seen_at = data.get("scanned_at", "")
        for host in data.get("hosts", []):
            ip = host.get("ip")
            if not ip:
                continue
            if ip not in hosts:
                hosts[ip] = {
                    "ip": ip,
                    "hostnames": [],
                    "mac": None,
                    "vendor": None,
                    "os": None,
                    "open_ports": 0,
                    "services": [],
                    "last_seen": "",
                }
            _merge_host(hosts[ip], host, seen_at)

    # Раскладываем по разрешённым диапазонам
    networks = []
    for scope in scopes:
        try:
            net = ipaddress.ip_network(scope.cidr, strict=False)
        except ValueError:
            continue
        members = []
        for ip, host in hosts.items():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                members.append(host)
        networks.append(
            {
                "cidr": scope.cidr,
                "description": scope.description,
                "hosts": sorted(members, key=lambda h: ipaddress.ip_address(h["ip"])),
            }
        )

    # Хосты, не попавшие ни в один диапазон: сканы могли идти до того,
    # как диапазон удалили из allowed-scope
    claimed = {h["ip"] for n in networks for h in n["hosts"]}
    orphans = sorted(
        (h for ip, h in hosts.items() if ip not in claimed),
        key=lambda h: h["ip"],
    )

    return {
        "networks": networks,
        "ungrouped": orphans,
        "totals": {
            "hosts": len(hosts),
            "networks": len(networks),
            "open_ports": sum(h["open_ports"] for h in hosts.values()),
        },
    }
