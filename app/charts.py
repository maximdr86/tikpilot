"""
Отрисовка графиков прямо на сервере, в виде SVG.

Почему так, а не готовой библиотекой: интерфейс должен работать в изолированной
сети, без внешних CDN, и мы не тащим сборщик фронтенда. Простая линия по точкам
рисуется десятком строк, а выглядит ровно так же, как у «взрослых» решений.

Цвета берутся из тех же CSS-переменных, что и остальной интерфейс, поэтому
графики автоматически подхватывают светлую и тёмную тему.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any, Sequence

# Размеры по умолчанию: широкая невысокая полоса, как в панелях мониторинга
WIDTH = 640
HEIGHT = 130
PAD_LEFT = 44
PAD_RIGHT = 8
PAD_TOP = 10
PAD_BOTTOM = 20


class Series:
    """Один ряд данных на графике."""

    def __init__(self, name: str, points: Sequence[tuple[Any, float | None]], color: str) -> None:
        self.name = name
        self.points = list(points)   # (метка времени, значение); None — пропуск
        self.color = color


# Палитра для нескольких линий на одном графике
COLORS = ["var(--accent)", "#2e7d32", "#b26a00", "#8e44ad", "#0f6b7a", "#c0392b"]


def line_chart(
    series: list[Series],
    unit: str = "",
    height: int = HEIGHT,
    width: int = WIDTH,
    y_min: float | None = None,
    y_max: float | None = None,
) -> str:
    """
    Построить линейный график по нескольким рядам.

    Пропуски (None) разрывают линию — так видно, что данных не было,
    а не что значение упало в ноль.
    """
    values = [v for s in series for _, v in s.points if v is not None]
    if not values:
        return _empty(width, height)

    low = y_min if y_min is not None else min(values)
    high = y_max if y_max is not None else max(values)
    if high - low < 1e-9:
        high = low + 1
    # Немного воздуха сверху, чтобы пик не упирался в край
    high += (high - low) * 0.1

    plot_w = width - PAD_LEFT - PAD_RIGHT
    plot_h = height - PAD_TOP - PAD_BOTTOM
    count = max(len(series[0].points), 1)

    def x_of(index: int) -> float:
        return PAD_LEFT + (plot_w * index / max(count - 1, 1))

    def y_of(value: float) -> float:
        return PAD_TOP + plot_h * (1 - (value - low) / (high - low))

    parts: list[str] = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" '
        f'style="display:block">'
    ]

    # Сетка и подписи по вертикали
    for fraction in (0, 0.5, 1):
        value = low + (high - low) * (1 - fraction)
        y = PAD_TOP + plot_h * fraction
        parts.append(
            f'<line x1="{PAD_LEFT}" y1="{y:.1f}" x2="{width - PAD_RIGHT}" y2="{y:.1f}" '
            f'stroke="var(--border)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{PAD_LEFT - 5}" y="{y + 3.5:.1f}" text-anchor="end" '
            f'font-size="10" fill="var(--muted)">{_fmt(value)}{html.escape(unit)}</text>'
        )

    # Подписи времени: начало и конец
    labels = [p[0] for p in series[0].points]
    if labels:
        parts.append(
            f'<text x="{PAD_LEFT}" y="{height - 5}" font-size="10" fill="var(--muted)">'
            f'{html.escape(_time_label(labels[0]))}</text>'
        )
        parts.append(
            f'<text x="{width - PAD_RIGHT}" y="{height - 5}" text-anchor="end" '
            f'font-size="10" fill="var(--muted)">{html.escape(_time_label(labels[-1]))}</text>'
        )

    # Сами линии
    for s in series:
        for segment in _segments(s.points):
            path = " ".join(
                f"{'M' if i == 0 else 'L'}{x_of(idx):.1f},{y_of(val):.1f}"
                for i, (idx, val) in enumerate(segment)
            )
            parts.append(
                f'<path d="{path}" fill="none" stroke="{s.color}" stroke-width="1.6" '
                f'stroke-linejoin="round" stroke-linecap="round"/>'
            )
            # Одиночную точку линией не нарисовать — ставим кружок
            if len(segment) == 1:
                idx, val = segment[0]
                parts.append(
                    f'<circle cx="{x_of(idx):.1f}" cy="{y_of(val):.1f}" r="2" fill="{s.color}"/>'
                )

    parts.append("</svg>")
    return "".join(parts)


def bar_chart(
    points: Sequence[tuple[str, float | None]],
    unit: str = "",
    height: int = 170,
    width: int = WIDTH,
    y_min: float | None = None,
    y_max: float | None = None,
    color_of: Any = None,
) -> str:
    """
    Столбики по готовым парам «подпись, значение».

    Отдельно от линии, потому что читаются они по-разному: линия про то,
    как менялось, столбики про то, сколько было в каждом отрезке. Для
    отчёта по дням нужно второе.

    `color_of` получает значение и возвращает цвет: в отчёте плохие дни
    красные, а не «такие же, только ниже».
    """
    values = [v for _, v in points if v is not None]
    if not values:
        return _empty(width, height)

    low = y_min if y_min is not None else min(min(values), 0.0)
    high = y_max if y_max is not None else max(values)
    if high - low < 1e-9:
        high = low + 1

    plot_w = width - PAD_LEFT - PAD_RIGHT
    plot_h = height - PAD_TOP - PAD_BOTTOM
    count = max(len(points), 1)
    slot = plot_w / count
    bar_w = max(2.0, min(slot * 0.68, 26.0))

    def y_of(value: float) -> float:
        value = max(low, min(high, value))
        return PAD_TOP + plot_h * (1 - (value - low) / (high - low))

    # Ширина по месту, высота пропорционально. Растягивать столбики
    # по ширине без сохранения пропорций нельзя: вместе с ними
    # растянутся подписи и станут вдвое шире букв на странице
    parts: list[str] = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="display:block;width:100%;height:auto">'
    ]

    for fraction in (0, 0.5, 1):
        value = low + (high - low) * (1 - fraction)
        y = PAD_TOP + plot_h * fraction
        parts.append(
            f'<line x1="{PAD_LEFT}" y1="{y:.1f}" x2="{width - PAD_RIGHT}" y2="{y:.1f}" '
            f'stroke="var(--border)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{PAD_LEFT - 5}" y="{y + 3.5:.1f}" text-anchor="end" '
            f'font-size="10" fill="var(--muted)">{_fmt(value)}{html.escape(unit)}</text>'
        )

    base = PAD_TOP + plot_h
    for index, (label, value) in enumerate(points):
        if value is None:
            continue
        x = PAD_LEFT + slot * (index + 0.5) - bar_w / 2
        y = y_of(float(value))
        colour = color_of(float(value)) if color_of else "var(--accent)"
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" '
            f'height="{max(1.0, base - y):.1f}" rx="1.5" fill="{colour}">'
            f'<title>{html.escape(str(label))}: {_fmt(float(value))}{html.escape(unit)}</title>'
            f'</rect>'
        )

    # Подписи снизу прореживаются: тридцать дат подряд сливаются в кашу
    step = max(1, round(count / 10))
    for index, (label, _value) in enumerate(points):
        if index % step:
            continue
        parts.append(
            f'<text x="{PAD_LEFT + slot * (index + 0.5):.1f}" y="{height - 5}" '
            f'text-anchor="middle" font-size="9" fill="var(--muted)">'
            f'{html.escape(str(label))}</text>'
        )

    parts.append("</svg>")
    return "".join(parts)


def legend(series: list[Series]) -> str:
    """Подписи к линиям под графиком."""
    items = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:5px;margin-right:14px">'
        f'<i style="width:10px;height:2px;background:{s.color};display:inline-block"></i>'
        f'{html.escape(s.name)}</span>'
        for s in series
    )
    return f'<div class="small muted" style="margin-top:6px">{items}</div>'


# ------------------------------------------------------------------ помощники
def _segments(points: list[tuple[Any, float | None]]) -> list[list[tuple[int, float]]]:
    """Разбить ряд на непрерывные куски, разрывая его на пропусках."""
    result: list[list[tuple[int, float]]] = []
    current: list[tuple[int, float]] = []
    for index, (_, value) in enumerate(points):
        if value is None:
            if current:
                result.append(current)
                current = []
        else:
            current.append((index, float(value)))
    if current:
        result.append(current)
    return result


def _fmt(value: float) -> str:
    """Компактная подпись значения на оси."""
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _time_label(value: Any) -> str:
    """Метка времени из БД → «дд.мм чч:мм» в местной зоне."""
    try:
        moment = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return str(value)
    return moment.astimezone().strftime("%d.%m %H:%M")


def _empty(width: int, height: int) -> str:
    """Заглушка, когда данных ещё нет."""
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" style="display:block">'
        f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" font-size="12" '
        f'fill="var(--muted)">данных пока нет</text></svg>'
    )
