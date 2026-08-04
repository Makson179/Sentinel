#!/usr/bin/env python3
"""Generate publication-style ProgramBench figures using only the stdlib."""

from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "programbench_run_info.csv"
OUTPUT_DIR = ROOT / "docs" / "assets"

WIDTH = 960
HEIGHT = 390
OVERVIEW_WIDTH = 1120
OVERVIEW_HEIGHT = 500
RAW_COLOR = "#355F8A"
BELLO_COLOR = "#B24A33"
RAW_FILL = "#E7EEF5"
BELLO_FILL = "#C7654D"
INK = "#1B1B1B"
MUTED = "#5B5B5B"
GRID = "#D7D7D7"
PAIR_LINE = "#A8A8A8"
FONT = "Georgia, 'Times New Roman', serif"


@dataclass(frozen=True)
class Run:
    task: str
    agent: str
    model: str
    mode: str
    completion: float
    runtime_seconds: int
    runtime_label: str

    @property
    def runtime_hours(self) -> float:
        return self.runtime_seconds / 3600


def parse_runtime(value: str) -> int:
    hours, minutes, seconds = (int(part) for part in value.split(":"))
    return hours * 3600 + minutes * 60 + seconds


def load_runs() -> list[Run]:
    with INPUT.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))

    runs = [
        Run(
            task=row["task"],
            agent=row["agent"],
            model=row["model"],
            mode=row["mode"],
            completion=float(row["completion_pct"]),
            runtime_seconds=parse_runtime(row["runtime"]),
            runtime_label=row["runtime"],
        )
        for row in rows
    ]
    if not runs:
        raise ValueError(f"No rows found in {INPUT}")
    return runs


def line(x1: float, y1: float, x2: float, y2: float, **attrs: object) -> str:
    rendered = " ".join(f'{key.replace("_", "-")}="{value}"' for key, value in attrs.items())
    return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" {rendered}/>'


def text(
    x: float,
    y: float,
    value: str,
    *,
    size: int = 13,
    anchor: str = "start",
    weight: str = "normal",
    fill: str = INK,
    style: str = "normal",
) -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" '
        f'font-weight="{weight}" font-style="{style}" text-anchor="{anchor}" '
        f'fill="{fill}">{escape(value)}</text>'
    )


def rectangle(
    x: float, y: float, width: float, height: float, **attrs: object
) -> str:
    rendered = " ".join(
        f'{key.replace("_", "-")}="{value}"' for key, value in attrs.items()
    )
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" '
        f'height="{height:.1f}" {rendered}/>'
    )


def data_marker(x: float, y: float, agent: str, mode: str, size: float = 7) -> str:
    color = RAW_COLOR if agent == "Raw Codex" else BELLO_COLOR
    fill = "#FFFFFF" if agent == "Raw Codex" else BELLO_FILL
    if mode == "ultra":
        return (
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{size:.1f}" fill="{fill}" '
            f'stroke="{color}" stroke-width="2.2"/>'
        )
    return rectangle(
        x - size,
        y - size,
        size * 2,
        size * 2,
        fill=fill,
        stroke=color,
        stroke_width="2.2",
    )


def linear_scale(value: float, start: float, width: float) -> float:
    return start + (value / 100) * width


def log_scale(value: float, start: float, width: float) -> float:
    lower, upper = 0.25, 24.0
    return start + (math.log(value) - math.log(lower)) / (
        math.log(upper) - math.log(lower)
    ) * width


def completion_y(value: float, top: float, height: float) -> float:
    lower, upper = 30.0, 85.0
    return top + (upper - value) / (upper - lower) * height


def overview_figure(runs: list[Run]) -> str:
    plot_x, plot_width = 95.0, 675.0
    plot_top, plot_height = 102.0, 292.0
    plot_bottom = plot_top + plot_height
    legend_x = 835.0
    indexed = {(run.task, run.mode, run.agent): run for run in runs}

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{OVERVIEW_WIDTH}" '
        f'height="{OVERVIEW_HEIGHT}" viewBox="0 0 {OVERVIEW_WIDTH} '
        f'{OVERVIEW_HEIGHT}" role="img" aria-labelledby="overview-title overview-desc">',
        '<title id="overview-title">ProgramBench completion versus wall-clock time</title>',
        '<desc id="overview-desc">All recorded Raw Codex and Bello runs. '
        'Wall-clock time is shown on a logarithmic axis.</desc>',
        f'<rect width="{OVERVIEW_WIDTH}" height="{OVERVIEW_HEIGHT}" fill="#FFFFFF"/>',
        text(52, 38, "ProgramBench: completion versus wall-clock time", size=22, weight="bold"),
        text(
            52,
            62,
            "gpt-5.6-sol · 11 observed runs · one observation per configuration",
            size=12,
            fill=MUTED,
        ),
        text(plot_x, 89, "Completion score (%)", size=14, weight="bold"),
    ]

    for tick in (30, 40, 50, 60, 70, 80):
        y = completion_y(tick, plot_top, plot_height)
        svg.append(line(plot_x, y, plot_x + plot_width, y, stroke=GRID, stroke_width="1", stroke_dasharray="3 4"))
        svg.append(text(plot_x - 13, y + 4, str(tick), size=11, anchor="end", fill=MUTED))

    for tick in (0.25, 0.5, 1, 2, 4, 8, 16):
        x = log_scale(tick, plot_x, plot_width)
        svg.append(line(x, plot_top, x, plot_bottom, stroke=GRID, stroke_width="1", stroke_dasharray="3 4"))
        svg.append(text(x, plot_bottom + 23, f"{tick:g}", size=11, anchor="middle", fill=MUTED))

    svg.extend(
        [
            line(plot_x, plot_top, plot_x, plot_bottom, stroke=INK, stroke_width="1.2"),
            line(plot_x, plot_bottom, plot_x + plot_width, plot_bottom, stroke=INK, stroke_width="1.2"),
            text(
                plot_x + plot_width / 2,
                plot_bottom + 52,
                "Wall-clock time (hours, log scale)",
                size=14,
                anchor="middle",
                weight="bold",
            ),
        ]
    )

    label_layout = {
        ("Solar", "ultra"): (10, -12, "start"),
        ("Samtools", "ultra"): (-10, 20, "end"),
        ("Rumdl", "ultra"): (-10, -12, "end"),
        ("Solar", "xhigh"): (10, -12, "start"),
        ("Samtools", "xhigh"): (10, 20, "start"),
    }
    for task in ("Solar", "Samtools", "Rumdl"):
        for mode in ("ultra", "xhigh"):
            raw = indexed.get((task, mode, "Raw Codex"))
            bello = indexed.get((task, mode, "Bello"))
            if raw and bello:
                raw_x = log_scale(raw.runtime_hours, plot_x, plot_width)
                raw_y = completion_y(raw.completion, plot_top, plot_height)
                bello_x = log_scale(bello.runtime_hours, plot_x, plot_width)
                bello_y = completion_y(bello.completion, plot_top, plot_height)
                svg.append(
                    line(
                        raw_x,
                        raw_y,
                        bello_x,
                        bello_y,
                        stroke=PAIR_LINE,
                        stroke_width="1.5",
                    )
                )
                dx, dy, anchor = label_layout[(task, mode)]
                svg.append(
                    text(
                        bello_x + dx,
                        bello_y + dy,
                        f"{task} · {mode}",
                        size=11,
                        anchor=anchor,
                        weight="bold",
                    )
                )

    for run in runs:
        x = log_scale(run.runtime_hours, plot_x, plot_width)
        y = completion_y(run.completion, plot_top, plot_height)
        svg.append(data_marker(x, y, run.agent, run.mode))
        if run.task == "Rumdl" and run.mode == "xhigh" and run.agent == "Raw Codex":
            svg.append(
                text(
                    x + 10,
                    y + 20,
                    "Rumdl · xhigh (unpaired)",
                    size=11,
                    weight="bold",
                )
            )

    svg.extend(
        [
            text(legend_x, 111, "Encoding", size=15, weight="bold"),
            text(legend_x, 143, "Method", size=12, weight="bold", fill=MUTED),
            data_marker(legend_x + 8, 170, "Raw Codex", "ultra"),
            text(legend_x + 26, 174, "Raw Codex", size=12),
            data_marker(legend_x + 8, 200, "Bello", "ultra"),
            text(legend_x + 26, 204, "Bello", size=12),
            text(legend_x, 247, "Reasoning mode", size=12, weight="bold", fill=MUTED),
            data_marker(legend_x + 8, 274, "Raw Codex", "ultra"),
            text(legend_x + 26, 278, "ultra (circle)", size=12),
            data_marker(legend_x + 8, 304, "Raw Codex", "xhigh"),
            text(legend_x + 26, 308, "xhigh (square)", size=12),
            line(legend_x, 337, legend_x + 40, 337, stroke=PAIR_LINE, stroke_width="1.5"),
            text(legend_x + 49, 341, "matched pair", size=12),
            text(
                52,
                482,
                "Lines connect Raw Codex and Bello runs for the same task and reasoning mode.",
                size=11,
                fill=MUTED,
            ),
            "</svg>",
        ]
    )
    return "\n".join(svg) + "\n"


def task_bar_figure(task: str, runs: list[Run], panel_letter: str) -> str:
    task_runs = [run for run in runs if run.task == task]
    indexed = {(run.mode, run.agent): run for run in task_runs}
    plot_x, plot_width = 105.0, 565.0
    plot_top, plot_bottom = 95.0, 306.0
    plot_height = plot_bottom - plot_top
    group_centers = {"ultra": 260.0, "xhigh": 515.0}
    bar_width = 70.0
    bar_offset = 44.0
    legend_x = 750.0

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" role="img" '
        f'aria-labelledby="title-{task.lower()} desc-{task.lower()}">',
        f'<title id="title-{task.lower()}">{escape(task)} completion scores</title>',
        f'<desc id="desc-{task.lower()}">Grouped bars compare Raw Codex and '
        f'Bello completion percentages in ultra and xhigh modes.</desc>',
        f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#FFFFFF"/>',
        text(48, 38, f"({panel_letter})  {task}", size=21, weight="bold"),
        text(
            48,
            62,
            "ProgramBench completion score · gpt-5.6-sol",
            size=12,
            fill=MUTED,
        ),
        text(plot_x, 85, "Completion (%)", size=13, weight="bold"),
    ]

    for tick in range(0, 101, 20):
        y = plot_bottom - (tick / 100) * plot_height
        svg.append(line(plot_x, y, plot_x + plot_width, y, stroke=GRID, stroke_width="1", stroke_dasharray="3 4"))
        svg.append(text(plot_x - 12, y + 4, str(tick), size=11, anchor="end", fill=MUTED))

    svg.extend(
        [
            line(plot_x, plot_top, plot_x, plot_bottom, stroke=INK, stroke_width="1.2"),
            line(plot_x, plot_bottom, plot_x + plot_width, plot_bottom, stroke=INK, stroke_width="1.2"),
        ]
    )

    for mode, center in group_centers.items():
        svg.append(text(center, plot_bottom + 27, mode, size=13, anchor="middle", weight="bold"))
        for agent, x_center in (
            ("Raw Codex", center - bar_offset),
            ("Bello", center + bar_offset),
        ):
            run = indexed.get((mode, agent))
            if run is None:
                svg.append(
                    line(
                        x_center - bar_width / 2,
                        plot_bottom - 2,
                        x_center + bar_width / 2,
                        plot_bottom - 2,
                        stroke=BELLO_COLOR,
                        stroke_width="2",
                        stroke_dasharray="5 4",
                    )
                )
                svg.append(text(x_center, plot_bottom - 12, "n/a", size=11, anchor="middle", fill=MUTED, style="italic"))
                continue

            height = (run.completion / 100) * plot_height
            y = plot_bottom - height
            fill = RAW_FILL if agent == "Raw Codex" else BELLO_FILL
            stroke = RAW_COLOR if agent == "Raw Codex" else BELLO_COLOR
            svg.append(
                rectangle(
                    x_center - bar_width / 2,
                    y,
                    bar_width,
                    height,
                    fill=fill,
                    stroke=stroke,
                    stroke_width="1.8",
                )
            )
            svg.append(
                text(
                    x_center,
                    y - 9,
                    f"{run.completion:g}%",
                    size=12,
                    anchor="middle",
                    fill=stroke,
                    weight="bold",
                )
            )

    svg.extend(
        [
            text(legend_x, 113, "Method", size=14, weight="bold"),
            rectangle(legend_x, 137, 26, 18, fill=RAW_FILL, stroke=RAW_COLOR, stroke_width="1.5"),
            text(legend_x + 38, 151, "Raw Codex", size=12),
            rectangle(legend_x, 174, 26, 18, fill=BELLO_FILL, stroke=BELLO_COLOR, stroke_width="1.5"),
            text(legend_x + 38, 188, "Bello", size=12),
            text(
                48,
                369,
                "Bars report observed completion percentages; a missing run is shown as n/a, not zero.",
                size=11,
                fill=MUTED,
            ),
            "</svg>",
        ]
    )
    return "\n".join(svg) + "\n"


def mode_summary_figure(
    runs: list[Run], mode: str, tasks: tuple[str, ...]
) -> str:
    width, height = 1040, 420
    plot_x, plot_width = 95.0, 680.0
    plot_top, plot_bottom = 92.0, 326.0
    plot_height = plot_bottom - plot_top
    legend_x = 835.0
    indexed = {(run.task, run.mode, run.agent): run for run in runs}

    raw_values = [
        indexed[(task, mode, "Raw Codex")].completion
        for task in tasks
    ]
    bello_values = [
        indexed[(task, mode, "Bello")].completion
        for task in tasks
    ]
    categories = [
        (task, raw_value, bello_value)
        for task, raw_value, bello_value in zip(
            tasks, raw_values, bello_values, strict=True
        )
    ] + [
        (
            "Macro mean",
            sum(raw_values) / len(raw_values),
            sum(bello_values) / len(bello_values),
        ),
    ]
    centers = (
        (180.0, 350.0, 520.0, 690.0)
        if len(categories) == 4
        else (220.0, 445.0, 670.0)
    )
    bar_width, bar_offset = 48.0, 29.0

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        f'aria-labelledby="{mode}-title {mode}-desc">',
        f'<title id="{mode}-title">ProgramBench {mode} completion scores</title>',
        f'<desc id="{mode}-desc">Grouped bars compare Raw Codex and Bello '
        f'completion percentages for {len(tasks)} tasks and their macro mean.</desc>',
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
        text(
            48,
            38,
            f"{'Primary' if mode == 'ultra' else 'Secondary'} comparison: {mode}",
            size=21,
            weight="bold",
        ),
        text(
            48,
            62,
            "Task-level completion scores and unweighted macro mean",
            size=12,
            fill=MUTED,
        ),
        text(plot_x, 83, "Completion (%)", size=13, weight="bold"),
    ]

    for tick in range(0, 101, 20):
        y = plot_bottom - (tick / 100) * plot_height
        svg.append(
            line(
                plot_x,
                y,
                plot_x + plot_width,
                y,
                stroke=GRID,
                stroke_width="1",
                stroke_dasharray="3 4",
            )
        )
        svg.append(
            text(plot_x - 12, y + 4, str(tick), size=11, anchor="end", fill=MUTED)
        )
    svg.extend(
        [
            line(plot_x, plot_top, plot_x, plot_bottom, stroke=INK, stroke_width="1.2"),
            line(
                plot_x,
                plot_bottom,
                plot_x + plot_width,
                plot_bottom,
                stroke=INK,
                stroke_width="1.2",
            ),
        ]
    )

    for center, (label, raw_value, bello_value) in zip(
        centers, categories, strict=True
    ):
        svg.append(
            text(center, plot_bottom + 26, label, size=12, anchor="middle", weight="bold")
        )
        for value, agent, x_center in (
            (raw_value, "Raw Codex", center - bar_offset),
            (bello_value, "Bello", center + bar_offset),
        ):
            bar_height = (value / 100) * plot_height
            y = plot_bottom - bar_height
            fill = RAW_FILL if agent == "Raw Codex" else BELLO_FILL
            stroke = RAW_COLOR if agent == "Raw Codex" else BELLO_COLOR
            value_label = f"{value:.1f}%" if label == "Macro mean" else f"{value:g}%"
            svg.append(
                rectangle(
                    x_center - bar_width / 2,
                    y,
                    bar_width,
                    bar_height,
                    fill=fill,
                    stroke=stroke,
                    stroke_width="1.7",
                )
            )
            svg.append(
                text(
                    x_center,
                    y - 8,
                    value_label,
                    size=11,
                    anchor="middle",
                    fill=stroke,
                    weight="bold",
                )
            )

    svg.extend(
        [
            text(legend_x, 116, "Method", size=14, weight="bold"),
            rectangle(
                legend_x,
                140,
                26,
                18,
                fill=RAW_FILL,
                stroke=RAW_COLOR,
                stroke_width="1.5",
            ),
            text(legend_x + 38, 154, "Raw Codex", size=12),
            rectangle(
                legend_x,
                177,
                26,
                18,
                fill=BELLO_FILL,
                stroke=BELLO_COLOR,
                stroke_width="1.5",
            ),
            text(legend_x + 38, 191, "Bello", size=12),
            text(
                48,
                399,
                "One observed run per task and method; no uncertainty intervals are estimated.",
                size=11,
                fill=MUTED,
            ),
            "</svg>",
        ]
    )
    return "\n".join(svg) + "\n"


def matched_effect_figure(runs: list[Run]) -> str:
    width, height = 1000, 445
    plot_x, plot_width = 245.0, 560.0
    plot_top, plot_bottom = 93.0, 365.0
    indexed = {(run.task, run.mode, run.agent): run for run in runs}
    pairs = [
        ("Solar — ultra", "Solar", "ultra"),
        ("Samtools — ultra", "Samtools", "ultra"),
        ("Rumdl — ultra", "Rumdl", "ultra"),
        ("Solar — xhigh", "Solar", "xhigh"),
        ("Samtools — xhigh", "Samtools", "xhigh"),
    ]
    effects = []
    for label, task, mode in pairs:
        raw = indexed[(task, mode, "Raw Codex")]
        bello = indexed[(task, mode, "Bello")]
        effects.append((label, mode, bello.completion - raw.completion))
    mean_effect = sum(effect for _, _, effect in effects) / len(effects)
    row_y = (112.0, 157.0, 202.0, 257.0, 302.0)

    def effect_x(value: float) -> float:
        return plot_x + (value / 27.0) * plot_width

    svg: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" '
        'aria-labelledby="effect-title effect-desc">',
        '<title id="effect-title">Matched completion-score differences</title>',
        '<desc id="effect-desc">Five paired comparisons all favor Bello, '
        'with an unweighted mean difference of 17.4 percentage points.</desc>',
        f'<rect width="{width}" height="{height}" fill="#FFFFFF"/>',
        text(48, 38, "Matched completion-score differences", size=21, weight="bold"),
        text(
            48,
            62,
            "Bello minus Raw Codex · positive values favor Bello",
            size=12,
            fill=MUTED,
        ),
    ]

    for tick in (0, 5, 10, 15, 20, 25):
        x = effect_x(tick)
        if tick == 0:
            svg.append(
                line(
                    x,
                    plot_top,
                    x,
                    plot_bottom,
                    stroke=INK,
                    stroke_width="1.3",
                )
            )
        else:
            svg.append(
                line(
                    x,
                    plot_top,
                    x,
                    plot_bottom,
                    stroke=GRID,
                    stroke_width="1",
                    stroke_dasharray="3 4",
                )
            )
        svg.append(
            text(x, plot_bottom + 23, f"{tick:+d}", size=11, anchor="middle", fill=MUTED)
        )

    for y, (label, mode, effect) in zip(row_y, effects, strict=True):
        svg.append(text(plot_x - 18, y + 4, label, size=12, anchor="end"))
        svg.append(
            line(
                effect_x(0),
                y,
                effect_x(effect),
                y,
                stroke=PAIR_LINE,
                stroke_width="2",
            )
        )
        color = BELLO_COLOR if mode == "ultra" else RAW_COLOR
        if mode == "ultra":
            svg.append(
                f'<circle cx="{effect_x(effect):.1f}" cy="{y:.1f}" r="7" '
                f'fill="{color}" stroke="{color}" stroke-width="1.5"/>'
            )
        else:
            svg.append(
                rectangle(
                    effect_x(effect) - 7,
                    y - 7,
                    14,
                    14,
                    fill=color,
                    stroke=color,
                    stroke_width="1.5",
                )
            )
        svg.append(
            text(
                effect_x(effect) + 13,
                y + 4,
                f"+{effect:g} pp",
                size=12,
                fill=color,
                weight="bold",
            )
        )

    summary_y = 344.0
    svg.append(
        line(
            plot_x - 150,
            326,
            plot_x + plot_width,
            326,
            stroke=GRID,
            stroke_width="1",
        )
    )
    svg.append(
        text(plot_x - 18, summary_y + 4, "Matched mean", size=12, anchor="end", weight="bold")
    )
    diamond_x = effect_x(mean_effect)
    diamond_points = (
        f"{diamond_x:.1f},{summary_y - 8:.1f} "
        f"{diamond_x + 9:.1f},{summary_y:.1f} "
        f"{diamond_x:.1f},{summary_y + 8:.1f} "
        f"{diamond_x - 9:.1f},{summary_y:.1f}"
    )
    svg.extend(
        [
            line(
                effect_x(0),
                summary_y,
                diamond_x,
                summary_y,
                stroke=INK,
                stroke_width="2.2",
            ),
            f'<polygon points="{diamond_points}" fill="{INK}" stroke="{INK}"/>',
            text(
                diamond_x + 14,
                summary_y + 4,
                f"+{mean_effect:.1f} pp",
                size=12,
                weight="bold",
            ),
            text(
                plot_x + plot_width / 2,
                413,
                "Completion-score difference (percentage points)",
                size=13,
                anchor="middle",
                weight="bold",
            ),
            f'<circle cx="844" cy="113" r="6.5" fill="{BELLO_COLOR}" '
            f'stroke="{BELLO_COLOR}" stroke-width="1.5"/>',
            text(860, 118, "ultra", size=12, fill=BELLO_COLOR, weight="bold"),
            rectangle(
                837.5,
                136.5,
                13,
                13,
                fill=RAW_COLOR,
                stroke=RAW_COLOR,
                stroke_width="1.5",
            ),
            text(860, 148, "xhigh", size=12, fill=RAW_COLOR, weight="bold"),
            "</svg>",
        ]
    )
    return "\n".join(svg) + "\n"


def main() -> None:
    runs = load_runs()
    tasks = ("Solar", "Samtools", "Rumdl")
    observed_tasks = {run.task for run in runs}
    missing = set(tasks) - observed_tasks
    if missing:
        raise ValueError(f"Missing expected tasks: {', '.join(sorted(missing))}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ultra_output = OUTPUT_DIR / "programbench-ultra-completion.svg"
    ultra_output.write_text(
        mode_summary_figure(runs, "ultra", ("Solar", "Samtools", "Rumdl")),
        encoding="utf-8",
    )
    print(ultra_output.relative_to(ROOT))

    xhigh_output = OUTPUT_DIR / "programbench-xhigh-completion.svg"
    xhigh_output.write_text(
        mode_summary_figure(runs, "xhigh", ("Solar", "Samtools")),
        encoding="utf-8",
    )
    print(xhigh_output.relative_to(ROOT))

    effect_output = OUTPUT_DIR / "programbench-matched-differences.svg"
    effect_output.write_text(matched_effect_figure(runs), encoding="utf-8")
    print(effect_output.relative_to(ROOT))

    overview_output = OUTPUT_DIR / "programbench-completion-vs-runtime.svg"
    overview_output.write_text(overview_figure(runs), encoding="utf-8")
    print(overview_output.relative_to(ROOT))

    for letter, task in zip(("a", "b", "c"), tasks, strict=True):
        output = OUTPUT_DIR / f"programbench-{task.lower()}.svg"
        output.write_text(task_bar_figure(task, runs, letter), encoding="utf-8")
        print(output.relative_to(ROOT))


if __name__ == "__main__":
    main()
