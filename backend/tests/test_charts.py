"""Тесты генерации графиков для PDF-отчёта."""

from app.reports.charts import render_bar_chart_data_uri, render_bar_chart_png


def test_produces_valid_png_bytes():
    png = render_bar_chart_png([("ssh", 5), ("http", 3)])
    assert png.startswith(b"\x89PNG"), "не похоже на PNG-заголовок"


def test_empty_items_does_not_crash():
    """Пустой список не должен ронять рендер — должен быть плейсхолдер."""
    png = render_bar_chart_png([])
    assert png.startswith(b"\x89PNG")


def test_data_uri_has_correct_prefix():
    uri = render_bar_chart_data_uri([("ssh", 5)])
    assert uri.startswith("data:image/png;base64,")


def test_max_bars_limits_output():
    """8 столбцов — потолок по умолчанию для читаемости в PDF."""
    items = [(f"service{i}", i) for i in range(20)]
    # Косвенная проверка: рендер с большим списком не падает и работает
    png_many = render_bar_chart_png(items, max_bars=8)
    png_few = render_bar_chart_png(items[:8], max_bars=8)
    assert len(png_many) == len(png_few), "лишние столбцы должны быть отброшены"


def test_long_label_does_not_crash():
    png = render_bar_chart_png([("A" * 200, 1)])
    assert png.startswith(b"\x89PNG")


def test_cyrillic_label_does_not_crash():
    png = render_bar_chart_png([("подключённый сервис", 3)])
    assert png.startswith(b"\x89PNG")
