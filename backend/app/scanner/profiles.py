"""Профили сканирования — какие аргументы передавать nmap.

Подход к организации профилей взят из frangelbarrera/Network-Scanner (MIT),
но аргументы переписаны под python-nmap и урезаны до безопасного минимума:
никакой разведки чужих доменов, только то, что имеет смысл в своей сети.

Набор из 9 профилей — по образцу шаблонов сканирования Nessus (Basic Network
Scan, Host Discovery, Advanced Scan и т.д.), адаптированный под то, что умеет
nmap без сторонних движков.

Каждый профиль честно объявляет, нужны ли ему права администратора.
Движок НЕ подменяет профиль на более слабый втихую — если прав нет,
скан падает с понятной ошибкой (см. engine.py).
"""

from dataclasses import dataclass

from app.models import ScanProfile


@dataclass(frozen=True)
class Profile:
    name: str
    arguments: str
    requires_privilege: bool
    description: str
    # Предел размера цели. Стоимость профилей отличается на порядки:
    # ping шлёт по одному пакету на адрес, full — 65535 проб, vuln ждёт
    # ответа от каждого NSE-скрипта. Без предела скан 10.0.0.0/8 тяжёлым
    # профилем упёрся бы в часовой лимит Celery и вернулся бы как failed
    # без внятной причины.
    max_hosts: int


PROFILES: dict[ScanProfile, Profile] = {
    ScanProfile.ping: Profile(
        name="ping",
        # -sn: без портов вообще, только «жив или нет». Без -PR (в отличие
        # от discovery), поэтому работает и за пределами своего L2-сегмента,
        # и без прав — nmap сам выберет ICMP или TCP-пробы по обстоятельствам.
        arguments="-sn",
        requires_privilege=False,
        description="Только живые хосты, без сканирования портов — самый быстрый способ узнать, кто в сети",
        max_hosts=65536,
    ),
    ScanProfile.discovery: Profile(
        name="discovery",
        # -sn: без сканирования портов, только поиск живых хостов
        # -PR: ARP-пинг — работает только в своём L2-сегменте, требует raw-сокетов
        arguments="-sn -PR",
        requires_privilege=True,
        description="Поиск живых хостов в локальном сегменте через ARP",
        # По пакету на адрес — /16 проходится за минуты.
        # ARP всё равно не выходит за свой сегмент, так что запас щедрый.
        max_hosts=65536,
    ),
    ScanProfile.quick: Profile(
        name="quick",
        # -sT: полноценный TCP connect — единственный базовый режим, которому
        #      НЕ нужны права администратора. Это не «ослабленный SYN»,
        #      а другой тип скана.
        arguments="-sT -T4 --top-ports 100",
        requires_privilege=False,
        description="TCP connect-скан 100 самых популярных портов",
        # 100 портов на адрес: /20 это 409 600 проб — уже десятки минут
        max_hosts=4096,
    ),
    ScanProfile.top1000: Profile(
        name="top1000",
        # Без --top-ports или -p — nmap по умолчанию берёт top-1000
        arguments="-sT -T4",
        requires_privilege=False,
        description="TCP connect-скан 1000 популярных портов — глубже quick, но всё ещё без прав",
        # В 10 раз дороже quick на порт — предел меньше во столько же раз
        max_hosts=512,
    ),
    ScanProfile.version: Profile(
        name="version",
        # -sV пробует определить версию сервиса на каждом открытом порту —
        # не требует raw-сокетов, но ощутимо медленнее из-за самих проб
        arguments="-sT -sV --top-ports 100",
        requires_privilege=False,
        description="Определение версий сервисов на 100 популярных портах",
        max_hosts=1024,
    ),
    ScanProfile.udp: Profile(
        name="udp",
        # -sU: UDP-скан. Требует raw-сокетов, чтобы поймать ICMP
        # port-unreachable — так nmap отличает closed от filtered.
        # UDP — то, что чаще всего забывают проверить: DNS, SNMP, DHCP,
        # NTP сидят именно там, а TCP-сканы их не видят вообще.
        arguments="-sU -T4 --top-ports 100",
        requires_privilege=True,
        description="UDP-скан 100 популярных портов — DNS, SNMP, DHCP и то, что не видно в TCP",
        # UDP кратно медленнее TCP: таймаут ожидания на каждый закрытый порт
        max_hosts=64,
    ),
    ScanProfile.vuln: Profile(
        name="vuln",
        # --script vuln: категория NSE-скриптов, проверяющих известные
        # уязвимости (устаревшие версии, дефолтные пароли, известные CVE
        # у конкретных сервисов). Не требует raw-сокетов — работает поверх
        # обычного connect-скана.
        arguments="-sT -sV --script vuln --top-ports 100",
        requires_privilege=False,
        description="Поиск известных уязвимостей скриптами nmap (устаревшие версии сервисов)",
        # Каждый скрипт — отдельный обмен пакетами с таймаутами; самый
        # медленный профиль на хост
        max_hosts=16,
    ),
    ScanProfile.full: Profile(
        name="full",
        # -sS: SYN-скан, -sV: версии сервисов, -O: определение ОС — всё требует raw
        arguments="-sS -sV -O -T4 -p-",
        requires_privilege=True,
        description="SYN-скан всех 65535 портов с определением сервисов и ОС",
        # 65535 портов на адрес: даже /24 это 16.7 млн проб, часы работы
        max_hosts=256,
    ),
    ScanProfile.aggressive: Profile(
        name="aggressive",
        # -A: версии + ОС + NSE-скрипты категории default + traceroute разом.
        # Самый информативный профиль и самый тяжёлый после vuln — сочетает
        # SYN-скан с определением ОС, поэтому требует прав.
        arguments="-sS -A -T4 --top-ports 100",
        requires_privilege=True,
        description="Версии сервисов, ОС, стандартные скрипты и трассировка маршрута разом",
        max_hosts=64,
    ),
}


def get_profile(profile: ScanProfile) -> Profile:
    try:
        return PROFILES[profile]
    except KeyError:
        raise ValueError(f"Неизвестный профиль сканирования: {profile}")
