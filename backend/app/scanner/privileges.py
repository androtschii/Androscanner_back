"""Проверка прав на raw-сокеты.

SYN-скан (-sS), ARP-пинг (-PR) и определение ОС (-O) требуют доступа
к raw-сокетам: root на Linux, администратор + Npcap на Windows.
"""

import os
import sys


def has_raw_socket_privilege() -> bool:
    """True, если процесс может открывать raw-сокеты."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def privilege_hint() -> str:
    """Подсказка, как получить нужные права на текущей платформе."""
    if sys.platform == "win32":
        return (
            "Запусти backend от имени администратора "
            "(PowerShell → «Запуск от имени администратора») и убедись, что установлен Npcap."
        )
    return "Запусти backend от root или выдай nmap права: sudo setcap cap_net_raw+eip $(which nmap)"
