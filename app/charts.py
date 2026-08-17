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

# Размеры по умолчанию. Виджет тянется на всю ширину панели, а пропорции
# сохраняются, поэтому важно не соотношение «как нарисовано», а то, каким
# оно станет на экране: широкая невысокая полоса. При 1200 на 170 график
# на типичной панели выходит примерно один к одному, подписи не мельчают
# и не растягиваются, а высота остаётся такой же, как была раньше.
WIDTH = 1200
HEIGHT = 170

#: Ширина для графиков, стоящих по двое в ряд. Пропорции сохраняются,
#: поэтому виджет надо рисовать примерно в том размере, в каком он будет
#: показан: нарисованный на 1200 и втиснутый в 600 даёт подписи вдвое мельче.
HALF_WIDTH = 620
HALF_HEIGHT = 150

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
    empty_text: str = "данных пока нет",
    fill: bool = False,
    peak: bool = False,
) -> str:
    """
    Построить линейный график по нескольким рядам.

    Пропуски (None) разрывают линию: так видно, что данных не было,
    а не что значение упало в ноль.

    Что здесь сделано ради читаемости, а не ради красоты:

    * **вертикальные линии времени.** Двух подписей по краям мало: на суточном
      графике невозможно сказать, когда именно был всплеск. Теперь время
      подписано в нескольких местах, а через график идут тонкие линии;
    * **дата в подписи только там, где сменились сутки.** Иначе «17.08» стоит
      в каждой подписи и не несёт ничего;
    * **заливка под линией** (`fill`). На трафике она отвечает на вопрос
      «когда было больше» быстрее, чем сама линия;
    * **отметка пика** (`peak`). Максимум подписан значением и временем:
      это тот единственный факт, который обычно и ищут глазами.

    Пропорции не ломаются. Раньше SVG растягивался по ширине панели
    (`preserveAspectRatio="none"`), и вместе с ним растягивались подписи:
    на широком мониторе цифры на оси выглядели раздавленными.
    """
    values = [v for s in series for _, v in s.points if v is not None]
    if not values:
        return _empty(width, height, empty_text)

    low = y_min if y_min is not None else min(values)
    high = y_max if y_max is not None else max(values)
    if high - low < 1e-9:
        high = low + 1
    # Немного воздуха сверху, чтобы пик не упирался в край
    high += (high - low) * 0.1

    # Место под подписи оси считаем по самой длинной из них. Раньше отступ
    # был жёстким, и «1.4 Мбит/с» уезжало за левый край: на графике
    # оставались обрезки вроде «4Мбит/с»
    axis_labels = [_fmt(low + (high - low) * (1 - f)) for f in (0, 0.5, 1)]
    pad_left = max(PAD_LEFT, int(max(len(t) for t in axis_labels) * 6) + 12)

    # Единице нужна своя строка сверху. Без неё подпись «Мбит/с» ложилась
    # на верхнее значение оси, и получалось «Мбит/49.2»
    label_unit = html.escape(unit.strip())
    pad_top = PAD_TOP + (9 if label_unit else 0)

    plot_w = width - pad_left - PAD_RIGHT
    plot_h = height - pad_top - PAD_BOTTOM
    count = max(len(series[0].points), 1)

    def x_of(index: int) -> float:
        return pad_left + (plot_w * index / max(count - 1, 1))

    def y_of(value: float) -> float:
        return pad_top + plot_h * (1 - (value - low) / (high - low))

    parts: list[str] = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'xmlns="http://www.w3.org/2000/svg" '
        f'style="display:block;height:auto">'
    ]

    # Сетка и подписи по вертикали. Четыре линии вместо двух: с одной
    # серединой на глаз не оценить, вдвое больше стало значение или втрое
    for fraction in (0, 0.25, 0.5, 0.75, 1):
        value = low + (high - low) * (1 - fraction)
        y = pad_top + plot_h * fraction
        middle = fraction not in (0, 1)
        parts.append(
            f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - PAD_RIGHT}" y2="{y:.1f}" '
            f'stroke="var(--border)" stroke-width="1"'
            + (' stroke-opacity="0.5"' if middle else "")
            + "/>"
        )
        if fraction not in (0.25, 0.75):
            # На оси только числа. Единица написана один раз сверху: она
            # одинакова для всех делений и в каждом только съедает место
            parts.append(
                f'<text x="{pad_left - 5}" y="{y + 3.5:.1f}" text-anchor="end" '
                f'font-size="10" fill="var(--muted)">{_fmt(value)}</text>'
            )

    if label_unit:
        parts.append(
            f'<text x="2" y="{PAD_TOP + 1}" font-size="9" fill="var(--muted)">'
            f'{label_unit}</text>'
        )

    # Подписи времени и вертикальная сетка
    labels = [p[0] for p in series[0].points]
    for index, text, with_date in _time_marks(labels, width):
        x = x_of(index)
        parts.append(
            f'<line x1="{x:.1f}" y1="{pad_top}" x2="{x:.1f}" y2="{pad_top + plot_h}" '
            f'stroke="var(--border)" stroke-width="1" stroke-opacity="0.45"/>'
        )
        anchor = "start" if index == 0 else ("end" if index == count - 1 else "middle")
        parts.append(
            f'<text x="{x:.1f}" y="{height - 5}" text-anchor="{anchor}" font-size="10" '
            f'fill="var(--muted)">{html.escape(text)}</text>'
        )

    # Сами линии
    for s in series:
        for segment in _segments(s.points):
            path = " ".join(
                f"{'M' if i == 0 else 'L'}{x_of(idx):.1f},{y_of(val):.1f}"
                for i, (idx, val) in enumerate(segment)
            )
            if fill and len(segment) > 1:
                # Заливка идёт до нижней границы поля, а не до нуля шкалы:
                # на графике с обрезанным низом «до нуля» уехало бы за край
                base = pad_top + plot_h
                area = (path
                        + f" L{x_of(segment[-1][0]):.1f},{base:.1f}"
                        + f" L{x_of(segment[0][0]):.1f},{base:.1f} Z")
                parts.append(
                    f'<path d="{area}" fill="{s.color}" fill-opacity="0.14" stroke="none"/>'
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

    if peak:
        parts.extend(_peak_mark(series, labels, x_of, y_of, unit, width))

    # Подсказка при наведении. Никакого JavaScript: над каждой точкой
    # стоит прозрачный столбец с <title>, и браузер сам показывает время
    # и значение. Работает и на публичных страницах, куда скрипты панели
    # не подключаются.
    parts.extend(_hover_targets(series, labels, x_of, plot_w, plot_h, count, unit, pad_top))

    parts.append("</svg>")
    return "".join(parts)


def _hover_targets(series: list[Series], labels: list[Any], x_of: Any,
                   plot_w: float, plot_h: float, count: int, unit: str,
                   pad_top: float = PAD_TOP) -> list[str]:
    """
    Прозрачные столбцы с подсказкой: время и значения в этой точке.

    Наводить курсор на саму линию неудобно, особенно на пик шириной
    в один пиксель, поэтому мишень это столбец во всю высоту поля.
    Подсказка собирается из всех рядов сразу: на графике с двумя целями
    пинга видно оба значения одним движением.
    """
    if count < 2:
        return []

    step = plot_w / max(count - 1, 1)
    out: list[str] = []
    for index in range(count):
        pieces = []
        for s in series:
            if index >= len(s.points):
                continue
            value = s.points[index][1]
            if value is None:
                continue
            name = f"{s.name}: " if len(series) > 1 else ""
            pieces.append(f"{name}{_fmt(float(value))}{unit}")
        if not pieces:
            continue

        when = _time_label(labels[index]) if index < len(labels) else ""
        title = " · ".join([when] + pieces) if when else " · ".join(pieces)
        out.append(
            f'<rect class="chart-hit" x="{x_of(index) - step / 2:.1f}" y="{pad_top:.1f}" '
            f'width="{step:.1f}" height="{plot_h:.1f}">'
            f'<title>{html.escape(title)}</title></rect>'
        )
    return out


def _peak_mark(series: list[Series], labels: list[Any], x_of: Any, y_of: Any,
               unit: str, width: int) -> list[str]:
    """
    Отметить самое высокое значение: кружок, значение и время.

    Пик это первое, что ищут глазами на графике трафика или задержки,
    и подпись избавляет от наведения курсора и подсчёта делений.
    """
    best_index = best_value = None
    for s in series:
        for index, (_, value) in enumerate(s.points):
            if value is not None and (best_value is None or value > best_value):
                best_index, best_value = index, float(value)
    if best_index is None or best_value is None:
        return []

    x, y = x_of(best_index), y_of(best_value)
    when = _clock_label(labels[best_index]) if best_index < len(labels) else ""
    text = f"{_fmt(best_value)}{unit}" + (f" · {when}" if when else "")

    # Подпись слева от пика, если он у правого края: иначе она уедет за поле
    if x > width * 0.7:
        anchor, dx = "end", -6
    else:
        anchor, dx = "start", 6
    return [
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="var(--text)" fill-opacity="0.75"/>',
        f'<text x="{x + dx:.1f}" y="{max(y - 6, 12):.1f}" text-anchor="{anchor}" '
        f'font-size="10" fill="var(--muted)">{html.escape(text)}</text>',
    ]


def _time_marks(labels: list[Any], width: int) -> list[tuple[int, str, bool]]:
    """
    Где ставить подписи времени и что в них писать.

    Число подписей считается от ширины: на узком графике шесть подписей
    сливаются в кашу, на широком четырёх мало. Дата пишется только там,
    где сменились сутки, и в самой первой подписи.
    """
    if not labels:
        return []

    wanted = max(3, min(8, width // 150))
    count = len(labels)
    if count <= wanted:
        indexes = list(range(count))
    else:
        step = (count - 1) / (wanted - 1)
        indexes = sorted({int(round(i * step)) for i in range(wanted)})

    marks: list[tuple[int, str, bool]] = []
    previous_day = None
    for position, index in enumerate(indexes):
        moment = _parse_moment(labels[index])
        if moment is None:
            marks.append((index, str(labels[index]), False))
            continue
        day = moment.strftime("%d.%m")
        with_date = position == 0 or day != previous_day
        previous_day = day
        marks.append((index, f"{day} {moment:%H:%M}" if with_date else f"{moment:%H:%M}",
                      with_date))
    return marks


def _parse_moment(value: Any) -> datetime | None:
    """Метка времени из БД в местное время. None, если это не время."""
    try:
        moment = datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return moment.astimezone()


def _clock_label(value: Any) -> str:
    """Только часы и минуты: для подписи пика дата обычно лишняя."""
    moment = _parse_moment(value)
    return moment.strftime("%H:%M") if moment else ""


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


def _empty(width: int, height: int, text: str = "данных пока нет") -> str:
    """
    Заглушка, когда данных ещё нет.

    Надпись приходит параметром, а не берётся из каталога здесь: рисование
    графика ничего не знает о языке страницы, и до появления параметра
    английская карточка показывала русскую надпись внутри SVG.
    """
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" style="display:block">'
        f'<text x="{width / 2}" y="{height / 2}" text-anchor="middle" font-size="12" '
        f'fill="var(--muted)">{text}</text></svg>'
    )
