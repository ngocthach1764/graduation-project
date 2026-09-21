#!/usr/bin/env python3
"""Print screenshot-friendly summaries for one QoS run or a full audit."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


SCENARIOS = ("normal", "high_load", "emergency")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def phase(t: float, scene: float) -> str:
    if t < 1.0 + scene:
        return "normal"
    if t < 1.0 + 2.0 * scene:
        return "high_load"
    return "emergency"


def print_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [len(value) for value in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    line = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    render = lambda row: "| " + " | ".join(
        value.ljust(widths[index]) for index, value in enumerate(row)
    ) + " |"
    print(line)
    print(render(headers))
    print(line)
    for row in rows:
        print(render(row))
    print(line)


def run_summary(directory: Path, scene: float, budget: float) -> None:
    deliveries = read_csv(directory / "rl_deliveries.csv")
    control = read_csv(directory / "qos_control.csv")
    print(f"DYNAMIC QOS RUN: {directory}")
    print(f"deliveries={len(deliveries)}  control_rows={len(control)}")

    rows = []
    for sc in SCENARIOS:
        selected = [row for row in deliveries
                    if phase(float(row["t"]), scene) == sc]
        values = []
        for cls in ("TIME_CRITICAL", "OPERATIONAL"):
            subset = [row for row in selected if row["true_class"] == cls]
            miss = 100.0 * sum(row["true_deadline_met"] == "0"
                                for row in subset) / max(1, len(subset))
            values.extend((str(len(subset)), f"{miss:.2f}"))
        cost = 3.0 * float(values[1]) + 1.5 * float(values[3])
        rows.append((sc, *values, f"{cost:.2f}"))
    print("\nEND-TO-END DEADLINE RESULTS (true class)")
    print_table(("scenario", "TC n", "TC miss%", "OP n", "OP miss%", "J"), rows)

    ctrl_rows = []
    for sc in SCENARIOS:
        selected = [row for row in control
                    if phase(float(row["t"]), scene) == sc]
        by_class = {
            cls: [row for row in selected if row["class"] == cls]
            for cls in ("TIME_CRITICAL", "OPERATIONAL")
        }
        mean = lambda cls, key: statistics.mean(
            float(row[key]) for row in by_class[cls]
        )
        ctrl_rows.append((
            sc,
            f"{mean('TIME_CRITICAL', 'rate_kbps'):.3f}",
            f"{mean('OPERATIONAL', 'rate_kbps'):.3f}",
            f"{statistics.mean(float(row['total_rate_kbps']) for row in selected):.3f}",
            f"{mean('TIME_CRITICAL', 'lambda_kbps'):.3f}",
            f"{mean('OPERATIONAL', 'lambda_kbps'):.3f}",
        ))
    print("\nCONTROLLER PROFILE AND ASSIGNED LOAD")
    print_table(("scenario", "rTC", "rOP", "total", "lambdaTC", "lambdaOP"),
                ctrl_rows)

    by_time: dict[str, list[float]] = defaultdict(list)
    for row in control:
        by_time[row["t"]].append(float(row["rate_kbps"]))
    actual_error = max(abs(sum(rates) - budget) for rates in by_time.values())
    logged_error = max(abs(float(row["budget_error_kbps"])) for row in control)
    print(f"\nBUDGET CONTRACT: C={budget:.3f} kbps  "
          f"max_actual_error={actual_error:.8f} kbps  "
          f"max_logged_error={logged_error:.8f} kbps")


def audit_summary(directory: Path) -> None:
    rows = [row for row in read_csv(directory / "qos_metrics.csv")
            if row["scope"] == "pooled" and row["scenario"] == "all"]
    print(f"QOS AUDIT SUMMARY: {directory}")
    for mode, title in (("rf_", "RANDOM FOREST"),
                        ("oracle_", "ORACLE REFERENCE")):
        selected = [row for row in rows if row["arm"].startswith(mode)]
        if not selected:
            continue
        table_rows = []
        for row in selected:
            arm = row["arm"].removeprefix(mode)
            table_rows.append((arm, row["runs"], row["TC_miss_pct"],
                               row["OP_miss_pct"], row["weighted_cost"]))
        print(f"\n{title}")
        print_table(("arm", "runs", "TC miss%", "OP miss%", "J"), table_rows)
    print("\nREPORT FIGURES")
    for path in sorted((directory / "figures").glob("*.pdf")):
        print(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("run", help="summarize one dynamic run")
    one.add_argument("directory", type=Path)
    one.add_argument("--scene-dur", type=float, default=40.0)
    one.add_argument("--budget-kbps", type=float, default=100.0)
    audit = sub.add_parser("audit", help="summarize a completed audit")
    audit.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "run":
        run_summary(args.directory, args.scene_dur, args.budget_kbps)
    else:
        audit_summary(args.directory)


if __name__ == "__main__":
    main()
