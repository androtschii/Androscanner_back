"""Простые столбчатые диаграммы для PDF-отчёта — без matplotlib.

WeasyPrint не выполняет JavaScript, поэтому графики в PDF не могут быть
интерактивным SVG/Chart.js, как на дашборде, — только готовые растровые
картинки. Pillow уже тянется как зависимость самого WeasyPrint, поэтому
рисуем им напрямую: тащить matplotlib (~40 МБ) ради трёх столбиков было бы
избыточно.

Шрифт — встроенный в Pillow (`ImageFont.load_default(size=...)`), а не файл
по имени вроде DejaVuSans.ttf: тот есть не на каждой системе (в частности,
не нашёлся по прямому имени на Windows), а бандл Pillow работает одинаково
и в Docker, и на Windows, и поддерживает кириллицу.

Один синий цвет на все столбцы, без градиента по величине — тот же принцип,
что и в BarCard на фронтенде: красить столбцы по значению значило бы кодировать
длину столбца ещё и оттенком.
"""

import base64
from io import BytesIO

from PIL import Image, ImageDraw, ImageFont

BAR_COLOR = (42, 120, 214)  # #2a78d6 — прошёл валидатор палитры для интерфейса
TEXT_COLOR = (17, 17, 17)
MUTED_COLOR = (120, 120, 120)

WIDTH = 640
ROW_HEIGHT = 32
LEFT_MARGIN = 170
RIGHT_MARGIN = 50
TOP_MARGIN = 6
FONT_SIZE = 14


def _truncate(label: str, limit: int = 22) -> str:
    return label if len(label) <= limit else label[: limit - 1] + "…"


def render_bar_chart_png(items: list[tuple[str, int]], *, max_bars: int = 8) -> bytes:
    """items — [(подпись, значение), ...]. Берутся первые max_bars как есть —
    сортировку и отбор топа делает вызывающий код."""
    items = items[:max_bars]
    if not items:
        items = [("нет данных", 0)]

    font = ImageFont.load_default(size=FONT_SIZE)
    height = TOP_MARGIN * 2 + ROW_HEIGHT * len(items)
    img = Image.new("RGB", (WIDTH, height), "white")
    draw = ImageDraw.Draw(img)

    max_value = max(v for _, v in items) or 1
    bar_area = WIDTH - LEFT_MARGIN - RIGHT_MARGIN

    for i, (label, value) in enumerate(items):
        y = TOP_MARGIN + i * ROW_HEIGHT
        bar_w = round(bar_area * value / max_value)

        draw.text((0, y + ROW_HEIGHT / 2 - FONT_SIZE / 2), _truncate(label),
                   fill=TEXT_COLOR, font=font)
        draw.rectangle(
            [LEFT_MARGIN, y + 6, LEFT_MARGIN + max(bar_w, 2), y + ROW_HEIGHT - 6],
            fill=BAR_COLOR,
        )
        # значение у кончика столбца — тот же принцип «не только в подсказке»,
        # что и на фронтенде, только здесь подсказки вообще нет, PDF статичен
        draw.text(
            (LEFT_MARGIN + bar_w + 8, y + ROW_HEIGHT / 2 - FONT_SIZE / 2),
            str(value), fill=MUTED_COLOR, font=font,
        )

    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def render_bar_chart_data_uri(items: list[tuple[str, int]], **kwargs) -> str:
    """Готовая строка для <img src="...">."""
    png = render_bar_chart_png(items, **kwargs)
    encoded = base64.b64encode(png).decode("ascii")
    return f"data:image/png;base64,{encoded}"
