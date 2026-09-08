"""Генерация PDF-отчёта по скану.

Структура разделов отчёта — по мотивам report_generator.py из
frangelbarrera/Network-Scanner (MIT). Движок другой: там ReportLab/HTML,
здесь Jinja2 + WeasyPrint, как задумано для проекта.

WeasyPrint на Windows требует библиотек GTK (Pango, cairo). Импорт поэтому
ленивый: без него весь остальной бэкенд должен продолжать работать, а
пользователь — получать внятное объяснение вместо стены трейсбека.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import Scan, ScanStatus

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
            "PDF-отчёты требуют библиотеки Pango (версии 1.44 или новее), которой нет в системе. "
            "В Docker она уже стоит — там отчёты работают. "
            "Если нужен PDF локально на Windows: поставь MSYS2 и в нём "
            "pacman -S mingw-w64-x86_64-pango, затем добавь его bin в PATH. "
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
    )


def render_scan_report(scan: Scan, requested_by: str) -> bytes:
    """Собирает PDF по скану. Возвращает содержимое файла."""
    html = render_scan_html(scan, requested_by)
    HTML = _load_weasyprint()
    return HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
