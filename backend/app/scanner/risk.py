"""Эвристическая оценка риска открытого порта/сервиса.

НЕ настоящее сканирование уязвимостей — нет базы CVE, нет проверки
конкретных версий ПО (этим занимается профиль vuln через NSE-скрипты,
и то не по каждому сервису). Это статические, широко известные
правила «что обычно опасно оставлять открытым наружу» — быстрый и
честный ориентир, а не замена настоящему аудиту.

Правила проверяются по порту ИЛИ по названию сервиса (нижний регистр,
подстрокой) — nmap не всегда называет сервис одинаково на разных ОС.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Risk:
    level: str  # "high" | "medium"
    reason: str


_RULES: list[tuple[frozenset[int], frozenset[str], Risk]] = [
    (
        frozenset({23}),
        frozenset({"telnet"}),
        Risk("high", "Telnet передаёт логин и пароль открытым текстом"),
    ),
    (
        frozenset({21}),
        frozenset({"ftp"}),
        Risk("high", "FTP передаёт логин и пароль открытым текстом"),
    ),
    (
        frozenset({512, 513, 514}),
        frozenset({"rlogin", "rsh", "exec", "shell"}),
        Risk("high", "Устаревший протокол удалённого доступа без шифрования"),
    ),
    (
        frozenset({5900, 5901}),
        frozenset({"vnc"}),
        Risk("high", "VNC часто доступен без пароля или со слабым паролем"),
    ),
    (
        frozenset({6379}),
        frozenset({"redis"}),
        Risk("high", "Redis по умолчанию работает без аутентификации"),
    ),
    (
        frozenset({27017, 27018}),
        frozenset({"mongodb", "mongod"}),
        Risk("high", "MongoDB по умолчанию работает без аутентификации"),
    ),
    (
        frozenset({9200, 9300}),
        frozenset({"elasticsearch", "elastic"}),
        Risk("high", "Elasticsearch по умолчанию работает без аутентификации"),
    ),
    (
        frozenset({11211}),
        frozenset({"memcached"}),
        Risk("high", "Memcached без аутентификации отдаёт данные любому запросу"),
    ),
    (
        frozenset({3306}),
        frozenset({"mysql"}),
        Risk("medium", "СУБД MySQL доступна из сети — стоит ограничить брандмауэром"),
    ),
    (
        frozenset({5432}),
        frozenset({"postgresql"}),
        Risk("medium", "СУБД PostgreSQL доступна из сети — стоит ограничить брандмауэром"),
    ),
    (
        frozenset({161, 162}),
        frozenset({"snmp"}),
        Risk("medium", "SNMP часто использует community-строку по умолчанию «public»"),
    ),
    (
        frozenset({3389}),
        frozenset({"ms-wbt-server", "rdp"}),
        Risk("medium", "RDP наружу — частая цель перебора паролей и эксплойтов"),
    ),
    (
        frozenset({445, 139}),
        frozenset({"microsoft-ds", "netbios-ssn"}),
        Risk("medium", "SMB — частая цель эксплойтов (например, WannaCry)"),
    ),
]


def assess_port_risk(port: int, service: str | None) -> Risk | None:
    """Возвращает оценку риска или None, если порт не входит ни в одно
    из известных правил (не значит «безопасно» — значит «нет данных»)."""
    service_lower = (service or "").lower()
    for ports, keywords, risk in _RULES:
        if port in ports or any(keyword in service_lower for keyword in keywords):
            return risk
    return None
