"""Генерация PDF-отчёта по скану.

Структура разделов отчёта — по мотивам report_generator.py из
frangelbarrera/Network-Scanner (MIT). Движок другой: там ReportLab/HTML,
здесь Jinja2 + WeasyPrint, как задумано для проекта.

WeasyPrint на Windows требует библиотек GTK (Pango, cairo). Импорт поэтому
ленивый: без него весь остальной бэкенд должен продолжать работать, а
пользователь — получать внятное объяснение вместо стены трейсбека.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import Scan, ScanStatus
from app.reports.charts import render_bar_chart_data_uri

TEMPLATE_DIR = Path(__file__).resolve().parent


class ReportError(RuntimeError):
    """Отчёт не удалось построить — текст пойдёт пользователю."""


_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)


def _load_weasyprint():
    """Ленивый импорт: без GTK библиотека не загрузится, и это не повод
    ронять весь бэкенд."""
    try:
        from weasyprint import HTML
    except OSError as exc:
        raise ReportError(
            "PDF-отчёты требуют библиотеки Pango (версии 1.44 или новее), которой нет в PATH "
            "этого процесса. В Docker она уже стоит — там отчёты работают. "
            "Проверено локально на Windows: MSYS2 + `pacman -S mingw-w64-x86_64-pango "
            "mingw-w64-x86_64-cairo mingw-w64-x86_64-gdk-pixbuf2`, затем C:\\msys64\\mingw64\\bin "
            "должен быть в PATH ДО запуска uvicorn (см. run-dev.ps1 — переменная окружения не "
            "долетает, если процесс уже стартовал без нужного PATH). "
            "Учти: GTK3-рантайм с gtkd.org не подойдёт — он несёт Pango 1.42, "
            "слишком старый для WeasyPrint. "
            f"Исходная ошибка: {exc}"
        ) from exc
    except ImportError as exc:
        raise ReportError(f"WeasyPrint не установлен: {exc}") from exc
    return HTML


def render_scan_html(scan: Scan, requested_by: str) -> str:
    """Собирает HTML отчёта. Отделено от PDF, чтобы вёрстку можно было
    проверять без GTK."""
    result = None
    error = None

    if scan.result:
        try:
            data = json.loads(scan.result)
        except json.JSONDecodeError:
            error = "Результат скана повреждён: не удалось разобрать JSON."
        else:
            # У провалившегося скана в result лежит объяснение, а не хосты
            if scan.status == ScanStatus.failed or "error" in data:
                error = data.get("error", "Скан завершился с ошибкой.")
            else:
                result = data
    elif scan.status == ScanStatus.failed:
        error = "Скан завершился с ошибкой, подробности не сохранены."

    return _env.get_template("template.html").render(
        scan=scan,
        result=result,
        error=error,
        requested_by=requested_by,
        generated_at=datetime.now(timezone.utc),
        charts=_build_charts(result) if result else None,
    )


def _build_charts(result: dict) -> dict[str, str] | None:
    """Три графика по данным ЭТОГО скана — не по всей истории (это отдельная
    сводка на дашборде): распределение хостов по статусам, топ сервисов,
    топ открытых портов. Возвращает data-URI картинок для <img> в шаблоне.
    """
    hosts = result.get("hosts", [])
    if not hosts:
        return None

    statuses = Counter(h.get("state", "unknown") for h in hosts)

    services: Counter = Counter()
    ports: Counter = Counter()
    for host in hosts:
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            ports[f"{port['port']}/{port['protocol']}"] += 1
            if port.get("service"):
                services[port["service"]] += 1

    if not ports:
        # Хосты есть, открытых портов нет (например, профиль ping) —
        # графики по портам и сервисам были бы пустыми прямоугольниками
        return {"statuses": render_bar_chart_data_uri(statuses.most_common())}

    return {
        "statuses": render_bar_chart_data_uri(statuses.most_common()),
        "services": render_bar_chart_data_uri(services.most_common(8)),
        "ports": render_bar_chart_data_uri(ports.most_common(8)),
    }


def render_scan_report(scan: Scan, requested_by: str) -> bytes:
    """Собирает PDF по скану. Возвращает содержимое файла."""
    html = render_scan_html(scan, requested_by)
    HTML = _load_weasyprint()
    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
