#!/usr/bin/env python3
"""Сайт в корне FRONT.

Nginx на FRONT отвечает не только на путь XHTTP: всё остальное получает этот
сайт. Без него домен с настоящим сертификатом на любой запрос отдавал 404 и
выглядел заглушкой. Сайт - небольшой альбом генеративной графики: главная,
страницы листов, серии, общий список, страница о сайте, лента, карта сайта,
значок и собственная страница 404.

Содержимое у каждой установки своё: листы, палитры, названия, адреса страниц,
имена классов и оформление выводятся из случайного зерна установки. Одинаковые
настройки всегда дают один и тот же сайт, поэтому после замены FRONT он не
меняется. Используется только стандартная библиотека Python.
"""

from __future__ import annotations

import argparse
import colorsys
import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import shutil
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from string import Template

# Меняется только намеренно: от неё зависит, пересобирается ли сайт при
# обновлении каскада. Правка генератора без смены номера оставляет уже
# собранный сайт как есть, и его страницы не получают новые даты и ETag.
GENERATOR_REVISION = 1

MASK = (1 << 64) - 1
UTC = dt.timezone.utc


class SiteError(Exception):
    """Настройки сайта нельзя применить."""


class Rng:
    """Собственный генератор случайных чисел (splitmix64).

    random из стандартной библиотеки не подходит: его методы меняли алгоритм
    между версиями Python, а сайт обязан собираться одинаково на прежнем и на
    новом FRONT. Каждая часть сайта получает свой поток по метке, поэтому
    изменение одной части не сдвигает остальные.
    """

    def __init__(self, seed: str, *labels: object) -> None:
        material = "\x1f".join([seed, *(str(label) for label in labels)])
        digest = hashlib.sha256(material.encode("utf-8")).digest()
        self.state = int.from_bytes(digest[:8], "big")

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK
        return value ^ (value >> 31)

    def random(self) -> float:
        return (self.next() >> 11) / float(1 << 53)

    def below(self, limit: int) -> int:
        return self.next() % limit

    def randint(self, low: int, high: int) -> int:
        return low + self.below(high - low + 1)

    def uniform(self, low: float, high: float) -> float:
        return low + (high - low) * self.random()

    def chance(self, probability: float) -> bool:
        return self.random() < probability

    def choice(self, items):
        return items[self.below(len(items))]

    def shuffle(self, items: list) -> None:
        for index in range(len(items) - 1, 0, -1):
            other = self.below(index + 1)
            items[index], items[other] = items[other], items[index]

    def sample(self, items, count: int) -> list:
        pool = list(items)
        self.shuffle(pool)
        return pool[:count]


def esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def num(value: float) -> str:
    """Число для SVG: один знак после запятой, без хвоста '.0' и без '-0'."""
    text = f"{value:.1f}"
    if text.endswith(".0"):
        text = text[:-2]
    return "0" if text == "-0" else text


# --- цвет -------------------------------------------------------------------


def rgb(color: str) -> tuple[int, int, int]:
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


def to_hex(red: float, green: float, blue: float) -> str:
    parts = (max(0, min(255, round(part))) for part in (red, green, blue))
    return "#%02x%02x%02x" % tuple(parts)


def mix(first: str, second: str, share: float) -> str:
    one, two = rgb(first), rgb(second)
    return to_hex(*(a + (b - a) * share for a, b in zip(one, two)))


def rotate(color: str, degrees: float) -> str:
    red, green, blue = (part / 255 for part in rgb(color))
    hue, light, saturation = colorsys.rgb_to_hls(red, green, blue)
    red, green, blue = colorsys.hls_to_rgb((hue + degrees / 360) % 1, light, saturation)
    return to_hex(red * 255, green * 255, blue * 255)


def luminance(color: str) -> float:
    red, green, blue = rgb(color)
    return (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255


# Палитры листов: ключ, название по-русски и по-английски, фон, тушь, цвета.
# Оттенки каждой установки дополнительно сдвигаются на свой угол.
PALETTES = (
    ("sand", "Песок", "Sand", "#f3ead7", "#2b2a27", ("#c8553d", "#f28f3b", "#588b8b", "#2d3047")),
    ("harbour", "Гавань", "Harbour", "#eef2f3", "#1d2a35", ("#1f6f8b", "#99a8b2", "#e6d5b8", "#e45826")),
    ("moss", "Мох", "Moss", "#f1f0e4", "#22301f", ("#4f6f52", "#86a789", "#d2e3c8", "#b5651d")),
    ("ink", "Тушь", "Ink", "#f7f5f0", "#16161a", ("#16161a", "#7f7f86", "#c9c6bd", "#b23a48")),
    ("dusk", "Сумерки", "Dusk", "#1f2033", "#f2e9e4", ("#c9ada7", "#9a8c98", "#4a4e69", "#f2cc8f")),
    ("clay", "Глина", "Clay", "#f6efe9", "#3a2e2a", ("#a44a3f", "#d19c7e", "#6b705c", "#cb997e")),
    ("frost", "Иней", "Frost", "#f4f8fb", "#1b263b", ("#415a77", "#778da9", "#a8dadc", "#e63946")),
    ("plum", "Слива", "Plum", "#f5eef4", "#2d1e2f", ("#6d466b", "#b49fcc", "#ead7d7", "#3f7d6e")),
    ("signal", "Сигнал", "Signal", "#fafafa", "#111111", ("#e63946", "#1d3557", "#f1c453", "#2a9d8f")),
    ("night", "Ночь", "Night", "#101418", "#e8e6e3", ("#5bc0be", "#3a506b", "#f4d35e", "#ee6c4d")),
    ("paper", "Бумага", "Paper", "#fbf8f1", "#33312e", ("#33312e", "#8c8a84", "#d9b44a", "#7a9e9f")),
    ("kelp", "Водоросли", "Kelp", "#eaf0ea", "#17301c", ("#2f5d50", "#6a994e", "#bc4749", "#f2e8cf")),
)


@dataclass(frozen=True)
class Palette:
    key: str
    name: str
    background: str
    ink: str
    colors: tuple[str, ...]


def palette_for(entry: tuple, language: str, shift: float) -> Palette:
    key, russian, english, background, ink, colors = entry
    return Palette(
        key=key,
        name=russian if language == "ru" else english,
        background=rotate(background, shift),
        ink=rotate(ink, shift),
        colors=tuple(rotate(color, shift) for color in colors),
    )


# --- рисунки ----------------------------------------------------------------
#
# Каждая функция получает свой поток случайных чисел, палитру и размер листа и
# возвращает элементы SVG и параметры, которые показываются под листом.


def art_tiles(rng: Rng, palette: Palette, width: int, height: int):
    columns = rng.randint(7, 16)
    cell_x = width / columns
    rows = max(2, round(height / cell_x))
    cell_y = height / rows
    half_x, half_y = cell_x / 2, cell_y / 2
    arc = f"A{num(half_x)},{num(half_y)} 0 0 1 "
    parts = []
    for row in range(rows):
        for column in range(columns):
            left, top = column * cell_x, row * cell_y
            right, bottom = left + cell_x, top + cell_y
            if rng.chance(0.5):
                parts.append(f"M{num(left + half_x)},{num(top)}{arc}{num(left)},{num(top + half_y)}")
                parts.append(f"M{num(left + half_x)},{num(bottom)}{arc}{num(right)},{num(top + half_y)}")
            else:
                parts.append(f"M{num(right)},{num(top + half_y)}{arc}{num(left + half_x)},{num(top)}")
                parts.append(f"M{num(left)},{num(top + half_y)}{arc}{num(left + half_x)},{num(bottom)}")
    stroke = cell_x * rng.uniform(0.14, 0.32)
    color = rng.choice(palette.colors[:2] + (palette.ink,))
    elements = [
        f'<defs><path id="a" d="{"".join(parts)}"/></defs>',
        f'<use href="#a" fill="none" stroke="{color}" stroke-width="{num(stroke)}" stroke-linecap="round"/>',
    ]
    if rng.chance(0.45):
        elements.append(
            f'<use href="#a" fill="none" stroke="{palette.background}" '
            f'stroke-width="{num(stroke * 0.42)}" stroke-linecap="round"/>'
        )
    return elements, [("grid", f"{columns} × {rows}")]


def art_maze(rng: Rng, palette: Palette, width: int, height: int):
    columns = rng.randint(12, 28)
    cell_x = width / columns
    rows = max(2, round(height / cell_x))
    cell_y = height / rows
    bias = rng.uniform(0.35, 0.65)
    parts = []
    for row in range(rows):
        for column in range(columns):
            left, top = column * cell_x, row * cell_y
            right, bottom = left + cell_x, top + cell_y
            if rng.chance(bias):
                parts.append(f"M{num(left)},{num(top)}L{num(right)},{num(bottom)}")
            else:
                parts.append(f"M{num(right)},{num(top)}L{num(left)},{num(bottom)}")
    stroke = cell_x * rng.uniform(0.1, 0.26)
    cap = rng.choice(("round", "square", "butt"))
    color = rng.choice((palette.ink, palette.colors[0], palette.colors[1]))
    element = (
        f'<path d="{"".join(parts)}" fill="none" stroke="{color}" '
        f'stroke-width="{num(stroke)}" stroke-linecap="{cap}"/>'
    )
    return [element], [("grid", f"{columns} × {rows}")]


def art_rings(rng: Rng, palette: Palette, width: int, height: int):
    columns = rng.randint(4, 8)
    cell_x = width / columns
    rows = max(2, round(height / cell_x))
    cell_y = height / rows
    cycle = palette.colors + (palette.background,)
    elements = []
    for row in range(rows):
        for column in range(columns):
            centre_x, centre_y = (column + 0.5) * cell_x, (row + 0.5) * cell_y
            count = rng.randint(2, 5)
            offset = rng.below(len(cycle))
            reach = min(cell_x, cell_y) * rng.uniform(0.4, 0.58)
            for ring in range(count):
                radius = reach * (count - ring) / count
                color = cycle[(offset + ring) % len(cycle)]
                elements.append(
                    f'<circle cx="{num(centre_x)}" cy="{num(centre_y)}" r="{num(radius)}" fill="{color}"/>'
                )
    return elements, [("grid", f"{columns} × {rows}")]


def art_ridges(rng: Rng, palette: Palette, width: int, height: int):
    lines = rng.randint(16, 32)
    points = 56
    margin = width * 0.08
    top = height * 0.2
    step = height * 0.68 / lines
    amplitude = step * rng.uniform(2.2, 5.0)
    waves = [
        (rng.uniform(1.0, 7.0), rng.uniform(0, math.tau), rng.uniform(0.3, 1.0), rng.uniform(0.15, 0.6))
        for _ in range(4)
    ]
    weight = sum(wave[2] for wave in waves)
    stroke = rng.uniform(1.6, 3.2)
    elements = []
    for line in range(lines):
        base = top + line * step
        path = []
        for point in range(points + 1):
            share = point / points
            envelope = math.sin(math.pi * share) ** 2
            value = sum(
                size * math.sin(frequency * share * math.tau + phase + line * drift)
                for frequency, phase, size, drift in waves
            ) / weight
            path.append(
                f"{num(margin + share * (width - 2 * margin))},"
                f"{num(base - amplitude * envelope * abs(value))}"
            )
        # Контур не замкнут: заливка закрывает линии позади по хорде, а
        # обводка идёт только по самой кривой.
        elements.append(
            f'<path d="M{"L".join(path)}" fill="{palette.background}" stroke="{palette.ink}" '
            f'stroke-width="{num(stroke)}" stroke-linejoin="round"/>'
        )
    return elements, [("lines", str(lines))]


def art_flow(rng: Rng, palette: Palette, width: int, height: int):
    waves = [
        (
            rng.uniform(0.002, 0.008) * rng.choice((-1, 1)),
            rng.uniform(0.002, 0.008) * rng.choice((-1, 1)),
            rng.uniform(0, math.tau),
            rng.uniform(0.4, 1.0),
        )
        for _ in range(3)
    ]
    count = rng.randint(140, 220)
    steps = rng.randint(10, 18)
    length = rng.uniform(12, 20)
    # В части палитр тушь совпадает с одним из цветов: повторы убираются.
    inks = list(dict.fromkeys(rng.sample(palette.colors + (palette.ink,), 3)))
    groups: dict[str, list[str]] = {color: [] for color in inks}
    for _ in range(count):
        x, y = rng.uniform(0, width), rng.uniform(0, height)
        path = [f"{num(x)},{num(y)}"]
        for _ in range(steps):
            angle = math.pi * sum(
                size * math.sin(x * along + y * across + phase) for along, across, phase, size in waves
            )
            x += math.cos(angle) * length
            y += math.sin(angle) * length
            if not (-20 < x < width + 20 and -20 < y < height + 20):
                break
            path.append(f"{num(x)},{num(y)}")
        if len(path) > 2:
            groups[rng.choice(inks)].append("M" + "L".join(path))
    elements = []
    for index, color in enumerate(inks):
        if groups[color]:
            elements.append(
                f'<path d="{"".join(groups[color])}" fill="none" stroke="{color}" '
                f'stroke-width="{num(1.4 + index * 1.3)}" stroke-linecap="round" stroke-linejoin="round"/>'
            )
    return elements, [("lines", str(sum(len(group) for group in groups.values())))]


def art_facets(rng: Rng, palette: Palette, width: int, height: int):
    columns = rng.randint(6, 11)
    rows = max(3, round(columns * height / width))
    cell_x, cell_y = width / columns, height / rows
    grid = []
    for row in range(rows + 1):
        line = []
        for column in range(columns + 1):
            shift_x = 0.0 if column in (0, columns) else rng.uniform(-0.34, 0.34) * cell_x
            shift_y = 0.0 if row in (0, rows) else rng.uniform(-0.34, 0.34) * cell_y
            line.append((column * cell_x + shift_x, row * cell_y + shift_y))
        grid.append(line)
    stops = rng.sample(palette.colors, 3)
    lean = rng.uniform(0.2, 0.8)

    def shade(points) -> str:
        centre_x = sum(point[0] for point in points) / 3
        centre_y = sum(point[1] for point in points) / 3
        share = lean * centre_x / width + (1 - lean) * centre_y / height + rng.uniform(-0.1, 0.1)
        share = max(0.0, min(1.0, share))
        if share < 0.5:
            return mix(stops[0], stops[1], share * 2)
        return mix(stops[1], stops[2], (share - 0.5) * 2)

    elements = []
    for row in range(rows):
        for column in range(columns):
            a, b = grid[row][column], grid[row][column + 1]
            c, d = grid[row + 1][column], grid[row + 1][column + 1]
            pairs = ((a, b, c), (b, d, c)) if rng.chance(0.5) else ((a, b, d), (a, d, c))
            for triangle in pairs:
                color = shade(triangle)
                points = " ".join(f"{num(x)},{num(y)}" for x, y in triangle)
                elements.append(
                    f'<polygon points="{points}" fill="{color}" stroke="{color}" stroke-width="0.6"/>'
                )
    return elements, [("grid", f"{columns} × {rows}")]


def art_division(rng: Rng, palette: Palette, width: int, height: int):
    depth = rng.randint(3, 5)
    gap = width * rng.uniform(0.006, 0.016)
    smallest = width * 0.09
    leaves = []
    queue = [(0.0, 0.0, float(width), float(height), depth)]
    while queue:
        left, top, wide, tall, level = queue.pop()
        stop = level == 0 or min(wide, tall) < smallest * 2 or (level < depth - 1 and rng.chance(0.18))
        if stop:
            leaves.append((left, top, wide, tall))
            continue
        if wide > tall * 1.2:
            upright = True
        elif tall > wide * 1.2:
            upright = False
        else:
            upright = rng.chance(0.5)
        share = rng.uniform(0.3, 0.7)
        if upright:
            queue.append((left, top, wide * share, tall, level - 1))
            queue.append((left + wide * share, top, wide * (1 - share), tall, level - 1))
        else:
            queue.append((left, top, wide, tall * share, level - 1))
            queue.append((left, top + tall * share, wide, tall * (1 - share), level - 1))
    fills = palette.colors + (palette.background, palette.background)
    elements = []
    for left, top, wide, tall in leaves:
        fill = rng.choice(fills)
        elements.append(
            f'<rect x="{num(left + gap / 2)}" y="{num(top + gap / 2)}" width="{num(wide - gap)}" '
            f'height="{num(tall - gap)}" fill="{fill}" stroke="{palette.ink}" stroke-width="{num(gap / 2)}"/>'
        )
        if rng.chance(0.3):
            inner = rng.choice([color for color in palette.colors if color != fill])
            elements.append(
                f'<circle cx="{num(left + wide / 2)}" cy="{num(top + tall / 2)}" '
                f'r="{num(min(wide, tall) * 0.3)}" fill="{inner}"/>'
            )
    return elements, [("cells", str(len(leaves))), ("depth", str(depth))]


def art_halftone(rng: Rng, palette: Palette, width: int, height: int):
    columns = rng.randint(16, 26)
    cell_x = width / columns
    rows = max(2, round(height / cell_x))
    cell_y = height / rows
    centres = [
        (rng.uniform(0, width), rng.uniform(0, height), rng.uniform(0.006, 0.018), rng.uniform(0, math.tau))
        for _ in range(rng.randint(2, 3))
    ]
    first, second = rng.sample(palette.colors + (palette.ink,), 2)
    groups: dict[str, list[str]] = {first: [], second: []}
    for row in range(rows):
        for column in range(columns):
            x, y = (column + 0.5) * cell_x, (row + 0.5) * cell_y
            value = sum(
                math.sin(math.hypot(x - centre_x, y - centre_y) * rate + phase)
                for centre_x, centre_y, rate, phase in centres
            ) / len(centres)
            radius = min(cell_x, cell_y) * 0.5 * (0.12 + 0.82 * (0.5 + 0.5 * value))
            if radius < min(cell_x, cell_y) * 0.08:
                continue
            groups[first if value > 0 else second].append(
                f'<circle cx="{num(x)}" cy="{num(y)}" r="{num(radius)}"/>'
            )
    elements = [f'<g fill="{color}">{"".join(dots)}</g>' for color, dots in groups.items() if dots]
    return elements, [("grid", f"{columns} × {rows}")]


def art_pendulum(rng: Rng, palette: Palette, width: int, height: int):
    centre_x, centre_y = width / 2, height / 2
    reach = min(width, height) * 0.44
    base = rng.randint(2, 4)

    def pair() -> tuple[float, float, float, float]:
        other = base + rng.choice((-1, 1)) + rng.uniform(-0.012, 0.012)
        return float(base), other, rng.uniform(0, math.tau), rng.uniform(0, math.tau)

    along, across = pair(), pair()
    damping = rng.uniform(0.006, 0.02)
    duration = rng.uniform(40, 80)
    steps = 2000
    path = []
    for step in range(steps + 1):
        moment = duration * step / steps
        decay = math.exp(-damping * moment)
        x = centre_x + reach * decay * (
            0.6 * math.sin(along[0] * moment + along[2]) + 0.4 * math.sin(along[1] * moment + along[3])
        )
        y = centre_y + reach * decay * (
            0.6 * math.sin(across[0] * moment + across[2]) + 0.4 * math.sin(across[1] * moment + across[3])
        )
        path.append(f"{num(x)},{num(y)}")
    color = rng.choice((palette.ink, palette.colors[0]))
    element = (
        f'<path d="M{"L".join(path)}" fill="none" stroke="{color}" '
        f'stroke-width="{num(rng.uniform(1.2, 2.2))}" stroke-linejoin="round"/>'
    )
    return [element], [("points", str(steps))]


def art_honeycomb(rng: Rng, palette: Palette, width: int, height: int):
    across = rng.randint(7, 13)
    radius = width / (across * math.sqrt(3))
    wide = math.sqrt(3) * radius
    rows = int(height / (1.5 * radius)) + 2
    skip = rng.uniform(0.08, 0.3)

    def corners(centre_x: float, centre_y: float, size: float) -> str:
        return " ".join(
            f"{num(centre_x + size * math.cos(math.radians(60 * corner - 90)))},"
            f"{num(centre_y + size * math.sin(math.radians(60 * corner - 90)))}"
            for corner in range(6)
        )

    elements = []
    drawn = 0
    for row in range(-1, rows):
        for column in range(-1, across + 1):
            centre_x = column * wide + (wide / 2 if row % 2 else 0)
            centre_y = row * 1.5 * radius
            if rng.chance(skip):
                continue
            fill = rng.choice(palette.colors)
            elements.append(f'<polygon points="{corners(centre_x, centre_y, radius * 0.94)}" fill="{fill}"/>')
            drawn += 1
            if rng.chance(0.3):
                inner = rng.choice((palette.background, palette.ink))
                elements.append(
                    f'<polygon points="{corners(centre_x, centre_y, radius * 0.48)}" fill="{inner}"/>'
                )
    return elements, [("cells", str(drawn))]


def art_orbits(rng: Rng, palette: Palette, width: int, height: int):
    centre_x, centre_y = width / 2, height / 2
    count = rng.randint(14, 40)
    major = min(width, height) * rng.uniform(0.36, 0.46)
    minor = major * rng.uniform(0.18, 0.55)
    stroke = rng.uniform(1.4, 3.4)
    inks = rng.sample(palette.colors + (palette.ink,), 2)
    elements = []
    for index in range(count):
        angle = 180 * index / count
        elements.append(
            f'<ellipse cx="{num(centre_x)}" cy="{num(centre_y)}" rx="{num(major)}" ry="{num(minor)}" '
            f'transform="rotate({num(angle)} {num(centre_x)} {num(centre_y)})" fill="none" '
            f'stroke="{inks[index % 2]}" stroke-width="{num(stroke)}"/>'
        )
    if rng.chance(0.6):
        elements.append(
            f'<circle cx="{num(centre_x)}" cy="{num(centre_y)}" r="{num(minor * 0.5)}" fill="{inks[0]}"/>'
        )
    return elements, [("turns", str(count))]


# Серии: адрес, название и описание по-русски и по-английски, функция рисунка.
SERIES = (
    ("tiles", "Плитка", "Tiles", art_tiles,
     "Плитки Трюше: в каждой клетке две дуги и случайный поворот. Клетки не знают друг о друге, "
     "но дуги сами складываются в длинные петли.",
     "Truchet tiles: every cell holds two arcs and a random turn. The cells know nothing about "
     "each other, yet the arcs join into long loops."),
    ("maze", "Лабиринт", "Maze", art_maze,
     "Диагонали на сетке: один бросок монеты на клетку, и лист читается как лабиринт.",
     "Diagonals on a grid: one coin toss per cell, and the sheet reads as a maze."),
    ("rings", "Кольца", "Rings", art_rings,
     "Концентрические круги на сетке. Число колец и порядок цветов выбираются для каждой клетки "
     "отдельно.",
     "Concentric circles on a grid. The number of rings and the order of colours are chosen for "
     "every cell separately."),
    ("ridges", "Гряда", "Ridges", art_ridges,
     "Линии одна над другой, каждая заслоняет предыдущую. Высота складывается из нескольких "
     "синусоид.",
     "Lines stacked one above another, each hiding the one behind. The height is a sum of a few "
     "sine waves."),
    ("flow", "Поток", "Flow", art_flow,
     "Короткие линии идут вдоль поля направлений, которое задано суммой волн.",
     "Short strokes follow a field of directions defined by a sum of waves."),
    ("facets", "Грани", "Facets", art_facets,
     "Сетка точек со случайным сдвигом, разбитая на треугольники. Цвет меняется от края к краю "
     "листа.",
     "A grid of shifted points cut into triangles. The colour changes from one edge of the sheet "
     "to the other."),
    ("division", "Деление", "Division", art_division,
     "Прямоугольник делится на части, пока не кончится глубина. Некоторые клетки получают круг.",
     "A rectangle is split again and again until the depth runs out. Some cells receive a circle."),
    ("halftone", "Растр", "Halftone", art_halftone,
     "Точки на сетке: радиус зависит от расстояния до нескольких центров.",
     "Dots on a grid: the radius depends on the distance to several centres."),
    ("pendulum", "Маятник", "Pendulum", art_pendulum,
     "Кривая гармонографа: по каждой оси складываются два затухающих колебания.",
     "A harmonograph curve: two fading oscillations are added along each axis."),
    ("honeycomb", "Соты", "Honeycomb", art_honeycomb,
     "Шестиугольная сетка. Часть ячеек пропущена, часть получает вложенный шестиугольник.",
     "A hexagonal grid. Some cells are skipped, some receive a smaller hexagon inside."),
    ("orbits", "Орбиты", "Orbits", art_orbits,
     "Один эллипс, повёрнутый много раз вокруг общего центра.",
     "A single ellipse turned many times around a common centre."),
)


# --- тексты -----------------------------------------------------------------

TEXT = {
    "ru": {
        "titles": (
            "Тихая геометрия", "Линии и сетки", "Плоскость и шум", "Мерный шаг", "Растр и линия",
            "Чертёжная доска", "Малые узоры", "Параллели", "Сетка дня", "Поле и линия",
            "Ровный штрих", "Сорок линий",
        ),
        "taglines": (
            "Генеративная графика: один лист, один алгоритм.",
            "Альбом рисунков, которые чертит программа.",
            "Узоры, построенные по правилам и случайным числам.",
            "Листы, собранные из сеток, дуг и случайности.",
        ),
        "intro": (
            "Здесь собраны листы, которые рисует небольшая программа. У каждого листа есть "
            "правило, параметры и зерно случайных чисел: этого достаточно, чтобы повторить его "
            "в точности.",
            "На этом сайте лежат рисунки, построенные алгоритмами. Новый лист появляется, когда "
            "находится удачное сочетание правила, палитры и случайного зерна.",
            "Это альбом генеративной графики. Каждый лист - векторный файл: его можно открыть в "
            "любом редакторе, увеличить без потерь и распечатать.",
        ),
        "about": (
            (
                "Этот сайт - личный альбом. В нём нет ни одной картинки, нарисованной от руки: "
                "все листы построены программой по коротким правилам.",
                "Сайт начинался как папка с черновиками. Со временем удачных листов стало "
                "достаточно, чтобы разложить их по сериям и показать.",
                "Здесь собраны результаты одного увлечения: писать небольшие программы, которые "
                "рисуют.",
            ),
            (
                "Лист задаётся тремя вещами: правилом, параметрами и зерном случайных чисел. "
                "Одинаковые значения всегда дают одинаковый рисунок, поэтому под каждым листом "
                "они приведены полностью.",
                "Рисунки хранятся в формате SVG. Это текстовый векторный формат: файл занимает "
                "десятки килобайт, а печатать его можно в любом размере.",
                "Серии названы по способу построения. Внутри серии листы отличаются только "
                "параметрами и палитрой.",
            ),
            (
                "Листы можно скачивать и использовать как угодно: для печати, обоев, обложек. "
                "Ссылка на сайт приветствуется, но не обязательна.",
                "Новые листы появляются нерегулярно. Следить за ними удобнее всего через ленту.",
                "Рисунки свободны для любого использования. Если лист пригодился, этого "
                "достаточно.",
            ),
        ),
        "nav_home": "Листы",
        "nav_series": "Серии",
        "nav_archive": "Все листы",
        "nav_about": "О сайте",
        "latest": "Последние листы",
        "all_link": "Все листы и даты",
        "series_title": "Серии",
        "series_lead": "Листы сгруппированы по способу построения.",
        "archive_title": "Все листы",
        "about_title": "О сайте",
        "about_series": "Серии и число листов",
        "number": "№",
        "label_series": "Серия",
        "label_size": "Размер",
        "label_seed": "Зерно",
        "label_palette": "Палитра",
        "label_date": "Дата",
        "label_file": "Файл",
        "label_grid": "Сетка",
        "label_lines": "Линий",
        "label_cells": "Клеток",
        "label_depth": "Глубина",
        "label_points": "Точек",
        "label_turns": "Поворотов",
        "download": "Скачать SVG",
        "kilobytes": "КБ",
        "older": "Раньше",
        "newer": "Позже",
        "column_date": "Дата",
        "column_title": "Лист",
        "column_series": "Серия",
        "missing_title": "Страница не найдена",
        "missing_text": "Такой страницы здесь нет. Возможно, адрес набран с ошибкой или лист был "
                        "убран.",
        "missing_link": "Перейти к листам",
        "feed": "Лента",
        "count": ("лист", "листа", "листов"),
        "months": (
            "января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа",
            "сентября", "октября", "ноября", "декабря",
        ),
    },
    "en": {
        "titles": (
            "Quiet Geometry", "Lines and Grids", "Plane and Noise", "Measured Step",
            "Raster and Line", "Drawing Board", "Small Patterns", "Parallels", "Grid of the Day",
            "Field and Line", "Even Stroke", "Forty Lines",
        ),
        "taglines": (
            "Generative drawings: one sheet, one algorithm.",
            "An album of drawings made by a program.",
            "Patterns built from rules and random numbers.",
            "Sheets assembled from grids, arcs and chance.",
        ),
        "intro": (
            "These sheets are drawn by a small program. Every sheet has a rule, a few parameters "
            "and a random seed: that is enough to reproduce it exactly.",
            "This site keeps drawings built by algorithms. A new sheet appears when a rule, a "
            "palette and a random seed happen to work well together.",
            "This is an album of generative graphics. Every sheet is a vector file: open it in "
            "any editor, scale it without loss and print it.",
        ),
        "about": (
            (
                "This site is a personal album. Nothing here is drawn by hand: every sheet is "
                "built by a program from a short rule.",
                "The site began as a folder of drafts. In time there were enough good sheets to "
                "sort them into series and show them.",
                "This is what one hobby produces: writing small programs that draw.",
            ),
            (
                "A sheet is defined by three things: a rule, its parameters and a random seed. "
                "The same values always give the same drawing, so they are listed in full under "
                "every sheet.",
                "The drawings are stored as SVG, a plain-text vector format: a file takes tens "
                "of kilobytes and prints at any size.",
                "Series are named after the way they are built. Within a series the sheets "
                "differ only in parameters and palette.",
            ),
            (
                "Download the sheets and use them as you like: prints, wallpapers, covers. A "
                "link back is welcome but not required.",
                "New sheets appear irregularly. The feed is the easiest way to follow them.",
                "The drawings are free for any use. If a sheet came in handy, that is enough.",
            ),
        ),
        "nav_home": "Sheets",
        "nav_series": "Series",
        "nav_archive": "All sheets",
        "nav_about": "About",
        "latest": "Latest sheets",
        "all_link": "All sheets with dates",
        "series_title": "Series",
        "series_lead": "The sheets are grouped by the way they are built.",
        "archive_title": "All sheets",
        "about_title": "About",
        "about_series": "Series and number of sheets",
        "number": "No.",
        "label_series": "Series",
        "label_size": "Size",
        "label_seed": "Seed",
        "label_palette": "Palette",
        "label_date": "Date",
        "label_file": "File",
        "label_grid": "Grid",
        "label_lines": "Lines",
        "label_cells": "Cells",
        "label_depth": "Depth",
        "label_points": "Points",
        "label_turns": "Turns",
        "download": "Download SVG",
        "kilobytes": "KB",
        "older": "Earlier",
        "newer": "Later",
        "column_date": "Date",
        "column_title": "Sheet",
        "column_series": "Series",
        "missing_title": "Page not found",
        "missing_text": "There is no such page here. The address may be mistyped, or the sheet "
                        "has been removed.",
        "missing_link": "Go to the sheets",
        "feed": "Feed",
        "count": ("sheet", "sheets", "sheets"),
        "months": (
            "January", "February", "March", "April", "May", "June", "July", "August",
            "September", "October", "November", "December",
        ),
    },
}

# Имена классов: у каждой роли свой набор синонимов, наборы не пересекаются.
CLASS_NAMES = {
    "wrap": ("wrap", "container", "inner", "shell", "frame"),
    "header": ("site-header", "masthead", "topbar", "head"),
    "brand": ("brand", "site-title", "logo", "name"),
    "nav": ("nav", "menu", "site-nav", "links"),
    "main": ("content", "main", "page", "body"),
    "grid": ("grid", "gallery", "board", "tiles", "wall"),
    "card": ("card", "piece", "cell", "thumb", "entry"),
    "sheet": ("sheet", "plate", "work", "single"),
    "meta": ("meta", "facts", "details", "specs"),
    "pager": ("pager", "prevnext", "steps", "around"),
    "list": ("list", "index", "table", "register"),
    "note": ("note", "lead", "intro", "summary"),
    "footer": ("site-footer", "foot", "colophon", "bottom"),
}

FONTS = (
    'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    'Georgia, "Times New Roman", Times, serif',
    '"Helvetica Neue", Helvetica, Arial, sans-serif',
    'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
    '"Trebuchet MS", "Lucida Grande", Verdana, sans-serif',
    'Charter, "Bitstream Charter", "Iowan Old Style", Georgia, serif',
)

SHEET_SIZES = ((1200, 1200), (1200, 1200), (1200, 1200), (1200, 900), (900, 1200))

STYLE = Template("""\
:root {
  --bg: $bg;
  --fg: $fg;
  --muted: $muted;
  --line: $line;
  --accent: $accent;
}
* { box-sizing: border-box; }
html { font-size: ${font_size}px; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: $font;
  line-height: $line_height;
}
a { color: var(--accent); text-decoration: $link_decoration; }
a:hover { text-decoration: underline; }
img { display: block; max-width: 100%; height: auto; }
h1, h2 { font-family: $heading_font; font-weight: $heading_weight; line-height: 1.2; }
h1 { font-size: ${h1_size}rem; margin: 0 0 ${gap_small}px; }
h2 { font-size: 1.15rem; margin: ${gap}px 0 ${gap_small}px; }
.$wrap { max-width: ${max_width}px; margin: 0 auto; padding: 0 ${side}px; }
.$header { border-bottom: 1px solid var(--line); padding: ${gap_small}px 0; margin-bottom: ${gap}px; }
.$header .$wrap { display: flex; flex-wrap: wrap; gap: 8px ${gap}px; align-items: baseline; justify-content: $header_justify; $header_direction }
.$brand { color: var(--fg); font-family: $heading_font; font-weight: $heading_weight; font-size: 1.25rem; $brand_case }
.$nav { display: flex; flex-wrap: wrap; gap: 6px ${nav_gap}px; $nav_case }
.$nav a { color: var(--muted); }
.$nav a[aria-current] { color: var(--fg); }
.$note { color: var(--muted); max-width: 46em; margin: 0 0 ${gap}px; }
.$grid { display: grid; grid-template-columns: repeat($columns, minmax(0, 1fr)); gap: ${gap}px; list-style: none; margin: 0 0 ${gap}px; padding: 0; }
.$card a { display: block; color: inherit; text-decoration: none; }
.$card img { width: 100%; border: ${border}px solid var(--line); border-radius: ${radius}px; }
.$card span { display: block; margin-top: 8px; }
.$card time, .$card small { display: block; color: var(--muted); font-size: 0.85rem; }
.$sheet img { width: 100%; max-width: ${sheet_width}px; border: ${border}px solid var(--line); border-radius: ${radius}px; margin: 0 0 ${gap}px; }
.$meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px ${gap}px; margin: 0 0 ${gap}px; }
.$meta dt { color: var(--muted); }
.$meta dd { margin: 0; }
.$pager { display: flex; justify-content: space-between; gap: ${gap}px; border-top: 1px solid var(--line); padding-top: ${gap_small}px; }
.$list { width: 100%; border-collapse: collapse; margin: 0 0 ${gap}px; }
.$list th, .$list td { text-align: left; padding: 6px 12px 6px 0; border-bottom: 1px solid var(--line); }
.$list th { color: var(--muted); font-weight: normal; }
.$footer { border-top: 1px solid var(--line); color: var(--muted); font-size: 0.85rem; margin-top: ${gap_large}px; padding: ${gap}px 0; }
@media (max-width: 820px) { .$grid { grid-template-columns: repeat($columns_medium, minmax(0, 1fr)); } }
@media (max-width: 520px) { .$grid { grid-template-columns: repeat($columns_small, minmax(0, 1fr)); } }
""")

# Имена в сценарии и первая строка у каждой установки свои: иначе один и тот
# же файл с одним и тем же хешем в имени лежал бы на всех FRONT.
SCRIPT = Template("""\
/* $banner */
(function () {
  var $doc = document;
  $doc.documentElement.className += " $flag";
  function $follow(rel) {
    var link = $doc.querySelector('link[rel="' + rel + '"]');
    if (link) { window.location.href = link.getAttribute("href"); }
  }
  $doc.addEventListener("keydown", function ($event) {
    if ($event.altKey || $event.ctrlKey || $event.metaKey || $event.shiftKey) { return; }
    if ($event.key === "ArrowLeft") { $follow("prev"); }
    if ($event.key === "ArrowRight") { $follow("next"); }
  });
})();
""")


# --- настройки --------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    seed: str
    created: dt.date
    language: str
    title: str
    domain: str
    reserved: tuple[str, ...]


def parse_config(raw: object) -> Config:
    if not isinstance(raw, dict):
        raise SiteError("настройки сайта должны быть объектом JSON")
    seed = raw.get("seed")
    if not isinstance(seed, str) or not re.fullmatch(r"[0-9a-f]{32,64}", seed):
        raise SiteError("seed: нужно от 32 до 64 шестнадцатеричных символов")
    try:
        created = dt.date.fromisoformat(str(raw.get("created")))
    except ValueError as error:
        raise SiteError("created: нужна дата вида ГГГГ-ММ-ДД") from error
    language = raw.get("language", "ru")
    if language not in TEXT:
        raise SiteError("language: поддерживаются ru и en")
    title = raw.get("title", "")
    if not isinstance(title, str) or len(title) > 60 or re.search(r"[\x00-\x1f\x7f]", title):
        raise SiteError("title: не длиннее 60 символов и без управляющих символов")
    domain = raw.get("domain")
    if not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9.-]{3,253}", domain):
        raise SiteError("domain: нужно DNS-имя сайта")
    reserved = raw.get("reserved", [])
    if not isinstance(reserved, list) or not all(
        isinstance(item, str) and re.fullmatch(r"/[A-Za-z0-9/_-]+", item) for item in reserved
    ):
        raise SiteError("reserved: список путей вида /path")
    return Config(seed, created, language, title.strip(), domain.lower(), tuple(reserved))


def load_config(path: Path) -> Config:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SiteError(f"не удалось прочитать настройки сайта {path}: {error}") from error
    return parse_config(raw)


def config_digest(config: Config) -> str:
    document = {
        "revision": GENERATOR_REVISION,
        "seed": config.seed,
        "created": config.created.isoformat(),
        "language": config.language,
        "title": config.title,
        "domain": config.domain,
        "reserved": list(config.reserved),
    }
    canonical = json.dumps(document, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --- модель сайта -----------------------------------------------------------


@dataclass(frozen=True)
class Urls:
    works: str
    series: str
    about: str
    archive: str
    assets: str
    images: str
    feed: str
    folders: bool

    def top_level(self) -> tuple[str, ...]:
        return (self.works, self.series, self.about, self.archive, self.assets, self.images, self.feed)

    def page(self, *parts: str) -> str:
        """Адрес страницы: каталог с index.html либо файл .html."""
        joined = "/".join(parts)
        return f"/{joined}/" if self.folders else f"/{joined}.html"

    def file(self, address: str) -> str:
        """Путь файла внутри корня сайта для адреса страницы."""
        if address.endswith("/"):
            return address.lstrip("/") + "index.html"
        return address.lstrip("/")


FIXED_FILES = (
    "index.html", "404.html", "robots.txt", "sitemap.xml", "favicon.ico", "favicon.svg",
    "apple-touch-icon.png",
)


def conflicts(path: str, reserved: tuple[str, ...]) -> bool:
    """Nginx отдаёт Xray всё, что начинается с пути XHTTP: сайту туда нельзя."""
    return any(("/" + path).startswith(prefix) for prefix in reserved)


def pick_urls(config: Config) -> Urls:
    for name in FIXED_FILES:
        if conflicts(name, config.reserved):
            raise SiteError(
                f"путь XHTTP совпадает с началом обязательного адреса сайта /{name}: "
                "сайт в корне FRONT с таким путём невозможен"
            )
    for attempt in range(64):
        rng = Rng(config.seed, "urls", attempt)
        urls = Urls(
            works=rng.choice(("works", "sheets", "plates", "pieces", "w", "p")),
            series=rng.choice(("series", "sets", "cycles", "kinds")),
            about=rng.choice(("about", "info", "colophon")),
            archive=rng.choice(("archive", "all", "catalog", "register")),
            assets=rng.choice(("assets", "static", "media", "files", "res")),
            images=rng.choice(("img", "svg", "images", "art")),
            feed=rng.choice(("feed.xml", "atom.xml")),
            folders=rng.chance(0.6),
        )
        if not any(conflicts(name, config.reserved) for name in urls.top_level()):
            return urls
    raise SiteError("не удалось подобрать адреса сайта, не пересекающиеся с путём XHTTP")


@dataclass(frozen=True)
class Skin:
    names: dict
    values: dict
    columns: int
    flag: str


def pick_skin(config: Config, accent_source: Palette) -> Skin:
    rng = Rng(config.seed, "skin")
    names = {role: rng.choice(options) for role, options in CLASS_NAMES.items()}
    dark = rng.chance(0.25)
    tint = accent_source.colors[0]
    if dark:
        background = mix("#111316", tint, 0.06)
        foreground = "#e7e5e0"
        accent = max(accent_source.colors, key=luminance)
    else:
        background = mix("#ffffff", tint, rng.uniform(0.02, 0.07))
        foreground = mix("#161616", tint, 0.12)
        accent = min(accent_source.colors, key=luminance)
    font = rng.choice(FONTS)
    heading_font = font if rng.chance(0.6) else rng.choice(FONTS)
    columns = rng.choice((2, 3, 3, 4))
    gap = rng.choice((16, 20, 24, 28, 32))
    header = rng.choice(("row", "spread", "stack"))
    values = {
        "bg": background,
        "fg": foreground,
        "muted": mix(foreground, background, 0.45),
        "line": mix(foreground, background, 0.84),
        "accent": accent,
        "font": font,
        "heading_font": heading_font,
        "heading_weight": rng.choice(("400", "600", "700")),
        "font_size": rng.choice((16, 17, 18)),
        "line_height": rng.choice(("1.5", "1.55", "1.6", "1.65")),
        "link_decoration": rng.choice(("none", "underline")),
        "h1_size": rng.choice(("1.6", "1.8", "2", "2.2")),
        "max_width": rng.choice((960, 1040, 1100, 1180, 1280)),
        "side": rng.choice((16, 20, 24)),
        "gap": gap,
        "gap_small": gap // 2,
        "gap_large": gap * 2,
        "nav_gap": rng.choice((14, 18, 22)),
        "radius": rng.choice((0, 2, 4, 8, 12)),
        "border": rng.choice((0, 1, 1)),
        "sheet_width": rng.choice((720, 800, 880, 960)),
        "columns": columns,
        "columns_medium": 2,
        "columns_small": 1 if columns < 4 else 2,
        "header_justify": {"row": "flex-start", "spread": "space-between", "stack": "flex-start"}[header],
        "header_direction": "flex-direction: column;" if header == "stack" else "",
        "brand_case": rng.choice(("", "", "text-transform: uppercase; letter-spacing: 0.06em;")),
        "nav_case": rng.choice(("", "", "text-transform: lowercase;", "font-size: 0.92rem;")),
    }
    values.update(names)
    return Skin(names=names, values=values, columns=columns, flag=rng.choice(("js", "has-js", "ready")))


@dataclass
class Work:
    series: tuple
    moment: dt.datetime
    number: int = 0
    slug: str = ""
    title: str = ""
    seed: int = 0
    palette: Palette | None = None
    image: bytes = b""
    parameters: list | None = None


class Site:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.text = TEXT[config.language]
        self.urls = pick_urls(config)
        rng = Rng(config.seed, "site")
        self.title = config.title or rng.choice(self.text["titles"])
        self.tagline = rng.choice(self.text["taglines"])
        self.intro = rng.choice(self.text["intro"])
        self.about = [rng.choice(variants) for variants in self.text["about"]]
        self.width, self.height = rng.choice(SHEET_SIZES)
        shift = rng.uniform(-14, 14)
        chosen = rng.sample(PALETTES, rng.randint(4, 6))
        self.palettes = [palette_for(entry, config.language, shift) for entry in chosen]
        light = [palette for palette in self.palettes if luminance(palette.background) > 0.5]
        self.skin = pick_skin(config, rng.choice(light or self.palettes))
        self.works = self.plan_works()
        self.newest = self.works[0].moment
        self.oldest = self.works[-1].moment
        # Служебные файлы "старше" первого листа: сайт появился раньше него.
        self.founded = self.oldest - dt.timedelta(days=rng.randint(2, 9), minutes=rng.randint(0, 600))
        self.files: dict[str, tuple[bytes, int]] = {}

    # -- содержимое ----------------------------------------------------------

    def series_name(self, series: tuple) -> str:
        return series[1] if self.config.language == "ru" else series[2]

    def series_text(self, series: tuple) -> str:
        return series[4] if self.config.language == "ru" else series[5]

    def plan_works(self) -> list[Work]:
        rng = Rng(self.config.seed, "works")
        kinds = rng.sample(SERIES, rng.randint(5, 7))
        total = rng.randint(18, 28)
        sequence = kinds * 2 + [rng.choice(kinds) for _ in range(total - 2 * len(kinds))]
        rng.shuffle(sequence)
        day = self.config.created - dt.timedelta(days=rng.randint(2, 15))
        works = []
        for series in sequence:
            moment = dt.datetime(
                day.year, day.month, day.day, rng.randint(8, 22), rng.randint(0, 59), rng.randint(0, 59)
            )
            works.append(Work(series=series, moment=moment))
            day -= dt.timedelta(days=rng.randint(3, 16))
        counters: dict[str, int] = {}
        for work in reversed(works):
            key = work.series[0]
            counters[key] = counters.get(key, 0) + 1
            work.number = counters[key]
            work.slug = f"{key}-{work.number:02d}"
            work.title = f"{self.series_name(work.series)} {self.text['number']} {work.number}"
            art = Rng(self.config.seed, "art", work.slug)
            work.seed = art.randint(1000, 99999)
            work.palette = art.choice(self.palettes)
            elements, work.parameters = work.series[3](art, work.palette, self.width, self.height)
            work.image = self.svg(work.title, work.palette.background, elements)
        return works

    def svg(self, title: str, background: str, elements: list[str]) -> bytes:
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {self.height}" '
            f'width="{self.width}" height="{self.height}">',
            f"<title>{esc(title)}</title>",
            f'<rect width="{self.width}" height="{self.height}" fill="{background}"/>',
            *elements,
            "</svg>",
        ]
        return ("\n".join(lines) + "\n").encode("utf-8")

    def human_date(self, moment: dt.datetime) -> str:
        return f"{moment.day} {self.text['months'][moment.month - 1]} {moment.year}"

    def count_text(self, count: int) -> str:
        one, few, many = self.text["count"]
        if self.config.language == "ru":
            if count % 10 == 1 and count % 100 != 11:
                word = one
            elif count % 10 in (2, 3, 4) and count % 100 not in (12, 13, 14):
                word = few
            else:
                word = many
        else:
            word = one if count == 1 else few
        return f"{count} {word}"

    # -- адреса --------------------------------------------------------------

    def work_url(self, work: Work) -> str:
        return self.urls.page(self.urls.works, work.slug)

    def image_url(self, work: Work) -> str:
        return f"/{self.urls.images}/{work.slug}.svg"

    def series_url(self, series: tuple) -> str:
        return self.urls.page(self.urls.series, series[0])

    def series_index_url(self) -> str:
        return f"/{self.urls.series}/"

    def about_url(self) -> str:
        return self.urls.page(self.urls.about)

    def archive_url(self) -> str:
        return self.urls.page(self.urls.archive)

    def absolute(self, address: str) -> str:
        return f"https://{self.config.domain}{address}"

    # -- вёрстка -------------------------------------------------------------

    def add(self, path: str, content: bytes | str, moment: dt.datetime) -> None:
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.files[path] = (data, int(moment.replace(tzinfo=UTC).timestamp()))

    def document(
        self,
        address: str,
        title: str,
        description: str,
        body: list[str],
        section: str = "",
        previous: str = "",
        following: str = "",
        indexed: bool = True,
    ) -> str:
        names = self.skin.names
        text = self.text
        full_title = self.title if not title else f"{title} - {self.title}"
        head = [
            "<!doctype html>",
            f'<html lang="{self.config.language}">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{esc(full_title)}</title>",
            f'<meta name="description" content="{esc(description)}">',
        ]
        if indexed:
            head.append(f'<link rel="canonical" href="{esc(self.absolute(address))}">')
        else:
            head.append('<meta name="robots" content="noindex">')
        if previous:
            head.append(f'<link rel="prev" href="{esc(previous)}">')
        if following:
            head.append(f'<link rel="next" href="{esc(following)}">')
        head += [
            f'<link rel="alternate" type="application/atom+xml" title="{esc(self.title)}" '
            f'href="/{self.urls.feed}">',
            '<link rel="icon" href="/favicon.ico" sizes="32x32">',
            '<link rel="icon" href="/favicon.svg" type="image/svg+xml">',
            '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
            f'<meta property="og:site_name" content="{esc(self.title)}">',
            f'<meta property="og:title" content="{esc(title or self.title)}">',
            '<meta property="og:type" content="website">',
        ]
        if indexed:
            head.append(f'<meta property="og:url" content="{esc(self.absolute(address))}">')
        head += [
            f'<link rel="stylesheet" href="{self.style_url}">',
            f'<script src="{self.script_url}" defer></script>',
            "</head>",
            "<body>",
        ]
        links = (
            ("home", "/", text["nav_home"]),
            ("series", self.series_index_url(), text["nav_series"]),
            ("archive", self.archive_url(), text["nav_archive"]),
            ("about", self.about_url(), text["nav_about"]),
        )
        current = ' aria-current="page"'
        navigation = "".join(
            f'<a href="{link}"{current if key == section else ""}>{esc(label)}</a>'
            for key, link, label in links
        )
        header = [
            f'<header class="{names["header"]}">',
            f'<div class="{names["wrap"]}">',
            f'<a class="{names["brand"]}" href="/">{esc(self.title)}</a>',
            f'<nav class="{names["nav"]}">{navigation}</nav>',
            "</div>",
            "</header>",
        ]
        footer = [
            f'<footer class="{names["footer"]}">',
            f'<div class="{names["wrap"]}">',
            f"&copy; {self.newest.year} {esc(self.title)} &middot; {esc(self.count_text(len(self.works)))} "
            f'&middot; <a href="/{self.urls.feed}">{esc(text["feed"])}</a>',
            "</div>",
            "</footer>",
        ]
        main = [f'<main class="{names["main"]}">', f'<div class="{names["wrap"]}">', *body, "</div>", "</main>"]
        return "\n".join([*head, *header, *main, *footer, "</body>", "</html>"]) + "\n"

    def card(self, work: Work, eager: bool, with_series: bool = True) -> str:
        loading = "eager" if eager else "lazy"
        extra = f"<small>{esc(self.series_name(work.series))}</small>" if with_series else ""
        return (
            f'<li class="{self.skin.names["card"]}"><a href="{self.work_url(work)}">'
            f'<img src="{self.image_url(work)}" width="{self.width}" height="{self.height}" '
            f'alt="{esc(work.title)}" loading="{loading}">'
            f"<span>{esc(work.title)}</span>{extra}"
            f'<time datetime="{work.moment.date().isoformat()}">{esc(self.human_date(work.moment))}</time>'
            "</a></li>"
        )

    def grid(self, works: list[Work], with_series: bool = True) -> list[str]:
        cards = [self.card(work, index < self.skin.columns, with_series) for index, work in enumerate(works)]
        return [f'<ul class="{self.skin.names["grid"]}">', *cards, "</ul>"]

    # -- страницы ------------------------------------------------------------

    def build(self) -> dict[str, tuple[bytes, int]]:
        names = self.skin.names
        text = self.text
        style = STYLE.substitute(self.skin.values).encode("utf-8")
        naming = Rng(self.config.seed, "script")
        script = SCRIPT.substitute(
            # Номер сборки выводится из зерна, но само зерно не раскрывает.
            banner=f"{self.title.replace('*/', '')} {naming.next() & 0xFFFFFFF:07x}",
            flag=self.skin.flag,
            doc=naming.choice(("doc", "d", "root", "page")),
            follow=naming.choice(("follow", "go", "jump", "open", "visit")),
            event=naming.choice(("event", "e", "ev", "press")),
        ).encode("utf-8")
        style_name = Rng(self.config.seed, "style").choice(("site", "main", "style", "screen"))
        script_name = naming.choice(("app", "site", "main", "nav"))
        self.style_url = f"/{self.urls.assets}/{style_name}.{hashlib.sha256(style).hexdigest()[:8]}.css"
        self.script_url = f"/{self.urls.assets}/{script_name}.{hashlib.sha256(script).hexdigest()[:8]}.js"
        self.add(self.style_url.lstrip("/"), style, self.founded)
        self.add(self.script_url.lstrip("/"), script, self.founded)

        shown = self.skin.columns * (4 if self.skin.columns == 2 else 3)
        home = [
            f"<h1>{esc(self.tagline)}</h1>",
            f'<p class="{names["note"]}">{esc(self.intro)}</p>',
            f"<h2>{esc(text['latest'])}</h2>",
            *self.grid(self.works[:shown]),
            f'<p><a href="{self.archive_url()}">{esc(text["all_link"])}</a></p>',
        ]
        self.add("index.html", self.document("/", "", self.tagline, home, section="home"), self.newest)

        for index, work in enumerate(self.works):
            newer = self.works[index - 1] if index > 0 else None
            older = self.works[index + 1] if index + 1 < len(self.works) else None
            size = max(1, round(len(work.image) / 1024))
            facts = [
                (text["label_series"],
                 f'<a href="{self.series_url(work.series)}">{esc(self.series_name(work.series))}</a>'),
                (text["label_size"], f"{self.width} × {self.height}"),
                *((text[f"label_{key}"], esc(value)) for key, value in work.parameters or []),
                (text["label_seed"], str(work.seed)),
                (text["label_palette"], esc(work.palette.name)),
                (text["label_date"],
                 f'<time datetime="{work.moment.date().isoformat()}">{esc(self.human_date(work.moment))}</time>'),
                (text["label_file"],
                 f'<a href="{self.image_url(work)}" download>{esc(text["download"])}</a>, '
                 f"{size} {esc(text['kilobytes'])}"),
            ]
            pager = []
            if older:
                pager.append(
                    f'<a href="{self.work_url(older)}" rel="prev">&larr; {esc(text["older"])}: '
                    f"{esc(older.title)}</a>"
                )
            else:
                pager.append("<span></span>")
            if newer:
                pager.append(
                    f'<a href="{self.work_url(newer)}" rel="next">{esc(text["newer"])}: '
                    f"{esc(newer.title)} &rarr;</a>"
                )
            body = [
                f'<article class="{names["sheet"]}">',
                f"<h1>{esc(work.title)}</h1>",
                f'<img src="{self.image_url(work)}" width="{self.width}" height="{self.height}" '
                f'alt="{esc(work.title)}">',
                f'<dl class="{names["meta"]}">',
                *(f"<dt>{esc(label)}</dt><dd>{value}</dd>" for label, value in facts),
                "</dl>",
                f'<p class="{names["note"]}">{esc(self.series_text(work.series))}</p>',
                f'<nav class="{names["pager"]}">{"".join(pager)}</nav>',
                "</article>",
            ]
            address = self.work_url(work)
            page = self.document(
                address, work.title, self.series_text(work.series), body, section="home",
                previous=self.work_url(older) if older else "",
                following=self.work_url(newer) if newer else "",
            )
            self.add(self.urls.file(address), page, work.moment)
            self.add(self.image_url(work).lstrip("/"), work.image, work.moment)

        used = []
        for work in self.works:
            if work.series not in used:
                used.append(work.series)
        overview = [f"<h1>{esc(text['series_title'])}</h1>", f'<p class="{names["note"]}">{esc(text["series_lead"])}</p>',
                    f'<ul class="{names["grid"]}">']
        for series in used:
            members = [work for work in self.works if work.series is series]
            sample = members[0]
            overview.append(
                f'<li class="{names["card"]}"><a href="{self.series_url(series)}">'
                f'<img src="{self.image_url(sample)}" width="{self.width}" height="{self.height}" '
                f'alt="{esc(self.series_name(series))}" loading="lazy">'
                f"<span>{esc(self.series_name(series))}</span>"
                f"<small>{esc(self.count_text(len(members)))}</small></a></li>"
            )
            body = [
                f"<h1>{esc(self.series_name(series))}</h1>",
                f'<p class="{names["note"]}">{esc(self.series_text(series))}</p>',
                *self.grid(members, with_series=False),
            ]
            address = self.series_url(series)
            page = self.document(address, self.series_name(series), self.series_text(series), body, section="series")
            self.add(self.urls.file(address), page, members[0].moment)
        overview.append("</ul>")
        self.add(
            f"{self.urls.series}/index.html",
            self.document(self.series_index_url(), text["series_title"], text["series_lead"], overview, section="series"),
            self.newest,
        )

        rows = [
            f"<tr><td><time datetime=\"{work.moment.date().isoformat()}\">{esc(self.human_date(work.moment))}"
            f'</time></td><td><a href="{self.work_url(work)}">{esc(work.title)}</a></td>'
            f'<td><a href="{self.series_url(work.series)}">{esc(self.series_name(work.series))}</a></td></tr>'
            for work in self.works
        ]
        archive = [
            f"<h1>{esc(text['archive_title'])}</h1>",
            f'<p class="{names["note"]}">{esc(self.count_text(len(self.works)))}</p>',
            f'<table class="{names["list"]}">',
            f"<thead><tr><th>{esc(text['column_date'])}</th><th>{esc(text['column_title'])}</th>"
            f"<th>{esc(text['column_series'])}</th></tr></thead>",
            "<tbody>", *rows, "</tbody>", "</table>",
        ]
        address = self.archive_url()
        self.add(
            self.urls.file(address),
            self.document(address, text["archive_title"], self.tagline, archive, section="archive"),
            self.newest,
        )

        about = [f"<h1>{esc(text['about_title'])}</h1>"]
        about += [f"<p>{esc(paragraph)}</p>" for paragraph in self.about]
        about += [f"<h2>{esc(text['about_series'])}</h2>", "<ul>"]
        about += [
            f'<li><a href="{self.series_url(series)}">{esc(self.series_name(series))}</a> - '
            f"{esc(self.count_text(sum(1 for work in self.works if work.series is series)))}</li>"
            for series in used
        ]
        about.append("</ul>")
        address = self.about_url()
        self.add(
            self.urls.file(address),
            self.document(address, text["about_title"], self.about[0], about, section="about"),
            self.founded,
        )

        missing = [
            f"<h1>{esc(text['missing_title'])}</h1>",
            f'<p class="{names["note"]}">{esc(text["missing_text"])}</p>',
            f'<p><a href="/">{esc(text["missing_link"])}</a></p>',
        ]
        self.add(
            "404.html",
            self.document("/404.html", text["missing_title"], text["missing_text"], missing, indexed=False),
            self.founded,
        )

        self.add(self.urls.feed, self.feed(), self.newest)
        self.add("sitemap.xml", self.sitemap(used), self.newest)
        self.add("robots.txt", f"User-agent: *\nAllow: /\n\nSitemap: {self.absolute('/sitemap.xml')}\n", self.founded)
        motif = Rng(self.config.seed, "icon").choice(("disc", "ring", "split", "quarters"))
        ground, mark = self.skin.values["accent"], self.skin.values["bg"]
        self.add("favicon.svg", icon_svg(motif, ground, mark), self.founded)
        self.add("favicon.ico", icon_ico(motif, ground, mark), self.founded)
        self.add("apple-touch-icon.png", icon_png(motif, ground, mark, 180), self.founded)

        for path in self.files:
            if conflicts(path, self.config.reserved):
                raise SiteError(f"адрес сайта /{path} пересекается с путём XHTTP")
        return self.files

    def feed(self) -> str:
        stamp = "%Y-%m-%dT%H:%M:%SZ"
        lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<feed xmlns="http://www.w3.org/2005/Atom">',
            f"<title>{esc(self.title)}</title>",
            f"<subtitle>{esc(self.tagline)}</subtitle>",
            f'<link href="{esc(self.absolute("/"))}"/>',
            f'<link rel="self" href="{esc(self.absolute("/" + self.urls.feed))}"/>',
            f"<id>{esc(self.absolute('/'))}</id>",
            f"<updated>{self.newest.strftime(stamp)}</updated>",
            f"<author><name>{esc(self.title)}</name></author>",
        ]
        for work in self.works[:20]:
            link = self.absolute(self.work_url(work))
            lines += [
                "<entry>",
                f"<title>{esc(work.title)}</title>",
                f'<link href="{esc(link)}"/>',
                f"<id>{esc(link)}</id>",
                f"<updated>{work.moment.strftime(stamp)}</updated>",
                f"<summary>{esc(self.series_text(work.series))}</summary>",
                "</entry>",
            ]
        lines.append("</feed>")
        return "\n".join(lines) + "\n"

    def sitemap(self, used: list[tuple]) -> str:
        entries = [("/", self.newest), (self.series_index_url(), self.newest), (self.archive_url(), self.newest),
                   (self.about_url(), self.founded)]
        for series in used:
            newest = next(work.moment for work in self.works if work.series is series)
            entries.append((self.series_url(series), newest))
        entries += [(self.work_url(work), work.moment) for work in self.works]
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
        lines += [
            f"<url><loc>{esc(self.absolute(address))}</loc><lastmod>{moment.date().isoformat()}</lastmod></url>"
            for address, moment in entries
        ]
        lines.append("</urlset>")
        return "\n".join(lines) + "\n"


# --- значок -----------------------------------------------------------------


def icon_mark(motif: str, across: float, down: float) -> bool:
    """Точка значка в единичном квадрате относится к знаку, а не к фону."""
    distance = math.hypot(across - 0.5, down - 0.5)
    if motif == "disc":
        return distance < 0.3
    if motif == "ring":
        return 0.2 < distance < 0.36
    if motif == "split":
        return across + down > 1
    return (across < 0.5) != (down < 0.5)


def icon_svg(motif: str, ground: str, mark: str) -> str:
    shapes = {
        "disc": f'<circle cx="16" cy="16" r="9.6" fill="{mark}"/>',
        "ring": f'<circle cx="16" cy="16" r="9" fill="none" stroke="{mark}" stroke-width="5"/>',
        "split": f'<polygon points="32,0 32,32 0,32" fill="{mark}"/>',
        "quarters": f'<rect x="16" width="16" height="16" fill="{mark}"/>'
                    f'<rect y="16" width="16" height="16" fill="{mark}"/>',
    }
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        f'<rect width="32" height="32" fill="{ground}"/>{shapes[motif]}</svg>\n'
    )


def icon_png(motif: str, ground: str, mark: str, size: int) -> bytes:
    """PNG RGBA без сторонних библиотек: значок рисуется по точкам."""
    colors = {False: bytes((*rgb(ground), 255)), True: bytes((*rgb(mark), 255))}
    rows = []
    for row in range(size):
        line = bytearray(b"\x00")
        for column in range(size):
            line += colors[icon_mark(motif, (column + 0.5) / size, (row + 0.5) / size)]
        rows.append(bytes(line))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return b"".join((
        b"\x89PNG\r\n\x1a\n",
        chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)),
        chunk(b"IDAT", zlib.compress(b"".join(rows), 9)),
        chunk(b"IEND", b""),
    ))


def icon_ico(motif: str, ground: str, mark: str) -> bytes:
    image = icon_png(motif, ground, mark, 32)
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 32, 32, 0, 0, 1, 32, len(image), 22) + image


# --- сборка и проверка ------------------------------------------------------


def build_site(config: Config) -> dict[str, tuple[bytes, int]]:
    return Site(config).build()


def manifest_path(state: Path) -> Path:
    return state / "manifest.json"


def read_manifest(state: Path) -> dict | None:
    try:
        document = json.loads(manifest_path(state).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("files"), dict):
        return None
    return document


def tree_problems(root: Path, manifest: dict) -> list[str]:
    """Расхождения каталога сайта с тем, что было собрано."""
    problems = []
    expected = manifest["files"]
    for name, digest in sorted(expected.items()):
        path = root / name
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            problems.append(f"нет файла {name}")
            continue
        if actual != digest:
            problems.append(f"изменён файл {name}")
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or path.is_file():
                name = path.relative_to(root).as_posix()
                if name not in expected:
                    problems.append(f"лишний файл {name}")
    return problems


def remove_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def write_tree(root: Path, files: dict[str, tuple[bytes, int]]) -> None:
    root.mkdir(parents=True, mode=0o755)
    os.chmod(root, 0o755)
    for name, (data, moment) in sorted(files.items()):
        path = root / name
        if not path.parent.is_dir():
            path.parent.mkdir(parents=True, mode=0o755)
            folder = path.parent
            while folder != root:
                os.chmod(folder, 0o755)
                folder = folder.parent
        path.write_bytes(data)
        os.chmod(path, 0o644)
        os.utime(path, (moment, moment))


def build(config: Config, root: Path, state: Path) -> bool:
    """Собрать сайт, если его нет или он не соответствует настройкам."""
    digest = config_digest(config)
    manifest = read_manifest(state)
    if manifest and manifest.get("config") == digest and not tree_problems(root, manifest):
        return False
    files = build_site(config)
    staging = root.with_name(root.name + ".new")
    retired = root.with_name(root.name + ".old")
    remove_tree(staging)
    remove_tree(retired)
    write_tree(staging, files)
    if root.exists():
        os.replace(root, retired)
    os.replace(staging, root)
    remove_tree(retired)
    state.mkdir(parents=True, exist_ok=True)
    document = {
        "config": digest,
        "files": {name: hashlib.sha256(data).hexdigest() for name, (data, _) in sorted(files.items())},
    }
    temporary = manifest_path(state).with_suffix(".tmp")
    temporary.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, manifest_path(state))
    return True


def command_build(arguments: argparse.Namespace) -> int:
    changed = build(load_config(arguments.config), arguments.root, arguments.state)
    print("changed" if changed else "unchanged")
    return 0


def command_verify(arguments: argparse.Namespace) -> int:
    manifest = read_manifest(arguments.state)
    if manifest is None:
        print("Сайт FRONT не собран: нет описи файлов.", file=sys.stderr)
        return 1
    if arguments.config is not None and manifest.get("config") != config_digest(load_config(arguments.config)):
        print("Сайт FRONT собран с другими настройками.", file=sys.stderr)
        return 1
    problems = tree_problems(arguments.root, manifest)
    for problem in problems[:20]:
        print(f"Сайт FRONT: {problem}", file=sys.stderr)
    return 1 if problems else 0


def command_describe(arguments: argparse.Namespace) -> int:
    site = Site(load_config(arguments.config))
    files = site.build()
    pages = sum(1 for name in files if name.endswith(".html") and name != "404.html")
    size = sum(len(data) for data, _ in files.values())
    print(f"Название: {site.title}")
    print(f"Листов: {len(site.works)}, страниц: {pages}, файлов: {len(files)}, объём: {size // 1024} КБ")
    print(f"Адрес: {site.absolute('/')}")
    return 0


def command_remove(arguments: argparse.Namespace) -> int:
    for path in (arguments.root, arguments.root.with_name(arguments.root.name + ".new"),
                 arguments.root.with_name(arguments.root.name + ".old"), arguments.state):
        remove_tree(path)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Сайт в корне FRONT")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, handler, needs in (
        ("build", command_build, ("config", "root", "state")),
        ("verify", command_verify, ("root", "state")),
        ("describe", command_describe, ("config",)),
        ("remove", command_remove, ("root", "state")),
    ):
        sub = commands.add_parser(name)
        sub.set_defaults(handler=handler)
        for option in needs:
            sub.add_argument(f"--{option}", type=Path, required=True)
        if name == "verify":
            sub.add_argument("--config", type=Path, default=None)
    arguments = parser.parse_args(argv)
    try:
        return arguments.handler(arguments)
    except SiteError as error:
        print(f"Сайт FRONT: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
