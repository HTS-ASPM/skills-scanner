"""Drift trend chart — SVG sparkline of artifact_count over scan history.

Reads the SQLite store written by `skillscan scan --save-baseline` and
renders a small inline SVG suitable for embedding in the dashboard.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


def render_trend_svg(db_path: Path, scan_root: str, *, width: int = 480, height: int = 80) -> str:
    points = _load_points(db_path, scan_root)
    if not points:
        return _empty_svg(width, height)
    return _render(points, width=width, height=height)


def _load_points(db_path: Path, scan_root: str) -> list[tuple[int, int]]:
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.OperationalError:
        return []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT created_at, artifact_count FROM scans WHERE scan_root = ? ORDER BY created_at",
            (scan_root,),
        )
        return cursor.fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def _render(points: list[tuple[int, int]], *, width: int, height: int) -> str:
    pad_x, pad_y = 10, 10
    plot_w = width - pad_x * 2
    plot_h = height - pad_y * 2
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    x_min, x_max = min(xs), max(xs)
    y_min, y_max = min(ys), max(ys)
    if x_max == x_min:
        x_max = x_min + 1
    y_range = max(1, y_max - y_min)

    coords = []
    for i, (t, count) in enumerate(points):
        x = pad_x + (t - x_min) / (x_max - x_min) * plot_w
        y = pad_y + (1 - (count - y_min) / y_range) * plot_h
        coords.append((x, y))

    path_d = "M " + " L ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    last_x, last_y = coords[-1]
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' width='100%' height='{height}' "
        "role='img' aria-label='Drift trend (artifact count over time)'>"
        "<style>"
        ".trend-line { stroke: #1565c0; stroke-width: 1.5; fill: none; }"
        ".trend-area { fill: #1565c022; stroke: none; }"
        ".trend-dot  { fill: #1565c0; }"
        ".trend-axis { stroke: #ccc; stroke-width: 0.6; }"
        ".trend-label { font: 10px -apple-system, Segoe UI, sans-serif; fill: #555; }"
        "</style>"
        f"<line x1='{pad_x}' y1='{height - pad_y}' x2='{width - pad_x}' y2='{height - pad_y}' class='trend-axis'/>"
        f"<path d='{path_d} L {last_x:.1f},{height - pad_y} L {pad_x},{height - pad_y} Z' class='trend-area'/>"
        f"<path d='{path_d}' class='trend-line'/>"
        f"<circle cx='{last_x:.1f}' cy='{last_y:.1f}' r='2.5' class='trend-dot'/>"
        f"<text x='{last_x:.1f}' y='{last_y - 6:.1f}' class='trend-label' text-anchor='end'>{ys[-1]} artifacts</text>"
        "</svg>"
    )


def _empty_svg(width: int, height: int) -> str:
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' width='100%' height='{height}'>"
        "<style>.empty { font: 11px -apple-system, Segoe UI, sans-serif; fill: #999; font-style: italic; }</style>"
        f"<text x='{width // 2}' y='{height // 2 + 4}' class='empty' text-anchor='middle'>"
        "No baseline history — run scan --save-baseline to start tracking drift.</text>"
        "</svg>"
    )
