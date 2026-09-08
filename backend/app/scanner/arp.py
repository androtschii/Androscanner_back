"""ARP-discovery локального сегмента через scapy.

Дополняет nmap: ARP-ответ приходит даже от хостов, которые молчат на ICMP
и закрыли все порты, поэтому в своей локалке это самый надёжный способ
увидеть все устройства.

Работает ТОЛЬКО в своём L2-сегменте — ARP не маршрутизируется. Для целей
за роутером вернёт пусто, это нормально, а не ошибка.
"""

from sqlalchemy.orm import Session

from app.scanner.privileges import has_raw_socket_privilege, privilege_hint
from app.security.scope import assert_in_scope


class ArpError(RuntimeError):
    pass


def arp_sweep(target: str, db: Session, timeout: int = 3) -> list[dict[str, str]]:
    """Рассылает ARP-запросы по диапазону, возвращает [{ip, mac}, ...]."""
    # Та же вторая линия защиты, что и в engine.py
    assert_in_scope(target, db)

    if not has_raw_socket_privilege():
        raise ArpError(f"ARP-discovery требует прав администратора. {privilege_hint()}")

    # scapy импортируем лениво: он тяжёлый и на Windows тянет Npcap,
    # без него остальной бэкенд должен продолжать работать
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
    except ImportError as exc:
        raise ArpError(f"scapy недоступен: {exc}") from exc

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    answered, _ = srp(packet, timeout=timeout, verbose=0)

    return [{"ip": received.psrc, "mac": received.hwsrc} for _, received in answered]
