"""Профили сканирования — какие аргументы передавать nmap.

Подход к организации профилей взят из frangelbarrera/Network-Scanner (MIT),
но аргументы переписаны под python-nmap и урезаны до безопасного минимума:
никакой разведки чужих доменов, только то, что имеет смысл в своей сети.

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
    # discovery шлёт по одному пакету на адрес, full — 65535 проб.
    # Без предела скан 10.0.0.0/8 профилем full упёрся бы в часовой
    # лимит Celery и вернулся бы как failed без внятной причины.
    max_hosts: int


PROFILES: dict[ScanProfile, Profile] = {
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
        # -sT: полноценный TCP connect — единственный режим, которому НЕ нужны
        #      права администратора. Это не «ослабленный SYN», а другой тип скана.
        arguments="-sT -T4 --top-ports 100",
        requires_privilege=False,
        description="TCP connect-скан 100 самых популярных портов",
        # 100 портов на адрес: /20 это 409 600 проб — уже десятки минут
        max_hosts=4096,
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
}


def get_profile(profile: ScanProfile) -> Profile:
    try:
        return PROFILES[profile]
    except KeyError:
        raise ValueError(f"Неизвестный профиль сканирования: {profile}")
