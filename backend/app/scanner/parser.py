"""Нормализация выхлопа python-nmap в нашу структуру.

python-nmap отдаёт вложенные словари, форма которых зависит от того, какие
флаги были переданы nmap. Здесь всё приводится к одному предсказуемому виду,
чтобы фронтенд и генератор отчётов не разбирали сырой формат.

Структура полей (host, ports, service, CPE) повторяет то, что показывает
дашборд WebMap, но код написан с нуля: WebMap под GPL-3.0, копировать нельзя.
"""

from datetime import datetime, timezone
from typing import Any


def _parse_ports(host_data: dict[str, Any]) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    for proto in ("tcp", "udp"):
        for port, info in (host_data.get(proto) or {}).items():
            cpe = info.get("cpe") or ""
            ports.append(
                {
                    "port": int(port),
                    "protocol": proto,
                    "state": info.get("state", ""),
                    "service": info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    # nmap отдаёт CPE строкой; приводим к списку для единообразия
                    "cpe": [c for c in cpe.split("\n") if c] if isinstance(cpe, str) else list(cpe),
                }
            )
    ports.sort(key=lambda p: (p["protocol"], p["port"]))
    return ports


def _parse_host(ip: str, host_data: dict[str, Any]) -> dict[str, Any]:
    addresses = host_data.get("addresses") or {}
    vendors = host_data.get("vendor") or {}
    mac = addresses.get("mac")

    return {
        "ip": addresses.get("ipv4") or addresses.get("ipv6") or ip,
        "hostnames": [h.get("name") for h in host_data.get("hostnames", []) if h.get("name")],
        "state": (host_data.get("status") or {}).get("state", ""),
        "mac": mac,
        "vendor": vendors.get(mac) if mac else None,
        "os": [
            {"name": m.get("name", ""), "accuracy": int(m.get("accuracy", 0))}
            for m in host_data.get("osmatch", [])
        ],
        "ports": _parse_ports(host_data),
    }


def parse_scan(scanner: Any, profile_name: str, arguments: str) -> dict[str, Any]:
    """Собирает итоговый JSON скана из объекта nmap.PortScanner."""
    hosts = [_parse_host(ip, scanner[ip]) for ip in scanner.all_hosts()]

    hosts_up = sum(1 for h in hosts if h["state"] == "up")
    open_ports = sum(1 for h in hosts for p in h["ports"] if p["state"] == "open")

    return {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile_name,
        "arguments": arguments,
        "hosts": hosts,
        "stats": {
            "hosts_total": len(hosts),
            "hosts_up": hosts_up,
            "open_ports": open_ports,
        },
    }
