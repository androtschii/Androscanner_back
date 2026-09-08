"""Сравнение двух сканов: что изменилось в сети между ними.

Идея взята из rackerlabs/scantron (Apache-2.0), где diff между последовательными
сканами — основная фича. Реализация своя: там сравнение опирается на ndiff и
XML-выхлоп nmap, здесь — на нашу нормализованную структуру результата.

Для домашней сети это самое ценное: не «какие порты открыты», а «что
появилось с прошлого раза».
"""

from typing import Any


def _hosts_by_ip(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {h["ip"]: h for h in result.get("hosts", []) if h.get("ip")}


def _open_ports(host: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    """Открытые порты хоста, ключ — (протокол, номер)."""
    return {
        (p["protocol"], p["port"]): p
        for p in host.get("ports", [])
        if p.get("state") == "open"
    }


def _port_brief(port: dict[str, Any]) -> dict[str, Any]:
    return {
        "port": port["port"],
        "protocol": port["protocol"],
        "service": port.get("service", ""),
    }


def _service_label(port: dict[str, Any]) -> str:
    """Сервис с версией, если nmap её определил."""
    parts = [port.get("service", ""), port.get("product", ""), port.get("version", "")]
    return " ".join(p for p in parts if p).strip()


def diff_results(base: dict[str, Any], compare: dict[str, Any]) -> dict[str, Any]:
    """Что изменилось при переходе от base к compare.

    base    — более ранний скан
    compare — более поздний
    """
    base_hosts = _hosts_by_ip(base)
    compare_hosts = _hosts_by_ip(compare)

    added = sorted(set(compare_hosts) - set(base_hosts))
    removed = sorted(set(base_hosts) - set(compare_hosts))

    host_changes: list[dict[str, Any]] = []
    ports_opened_total = 0
    ports_closed_total = 0

    for ip in sorted(set(base_hosts) & set(compare_hosts)):
        before = _open_ports(base_hosts[ip])
        after = _open_ports(compare_hosts[ip])

        opened = [_port_brief(after[k]) for k in sorted(set(after) - set(before))]
        closed = [_port_brief(before[k]) for k in sorted(set(before) - set(after))]

        services_changed = []
        for key in sorted(set(before) & set(after)):
            was, now = _service_label(before[key]), _service_label(after[key])
            if was != now:
                services_changed.append(
                    {
                        "port": after[key]["port"],
                        "protocol": after[key]["protocol"],
                        "before": was,
                        "after": now,
                    }
                )

        if opened or closed or services_changed:
            host_changes.append(
                {
                    "ip": ip,
                    "ports_opened": opened,
                    "ports_closed": closed,
                    "services_changed": services_changed,
                }
            )
            ports_opened_total += len(opened)
            ports_closed_total += len(closed)

    # Порты появившихся и исчезнувших хостов тоже считаем в итогах:
    # новый хост с пятью открытыми портами — это пять новых открытых портов
    for ip in added:
        ports_opened_total += len(_open_ports(compare_hosts[ip]))
    for ip in removed:
        ports_closed_total += len(_open_ports(base_hosts[ip]))

    return {
        "hosts_added": [
            {"ip": ip, "ports": [_port_brief(p) for p in _open_ports(compare_hosts[ip]).values()]}
            for ip in added
        ],
        "hosts_removed": [
            {"ip": ip, "ports": [_port_brief(p) for p in _open_ports(base_hosts[ip]).values()]}
            for ip in removed
        ],
        "host_changes": host_changes,
        "summary": {
            "hosts_added": len(added),
            "hosts_removed": len(removed),
            "ports_opened": ports_opened_total,
            "ports_closed": ports_closed_total,
            "hosts_changed": len(host_changes),
        },
    }
