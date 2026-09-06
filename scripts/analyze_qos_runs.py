#!/usr/bin/env python3
"""Pool paired QoS runs and report per-class deadline/demotion metrics."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


def scenario(t: float, scene: float) -> str:
    if t < 1.0 + scene:
        return "normal"
    if t < 1.0 + 2.0 * scene:
        return "high_load"
    return "emergency"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def summarize(rows: list[dict[str, str]], sc: str, scene_dur: float) -> dict:
    selected = rows if sc == "all" else [
        row for row in rows if scenario(float(row["t"]), scene_dur) == sc
    ]
    result: dict[str, dict[str, float] | float] = {}
    for cls in ("EMERGENCY", "IMPORTANT", "NORMAL"):
        subset = [row for row in selected if row["true_class"] == cls]
        count = len(subset)
        result[cls] = {
            "n": count,
            "miss": 100.0 * sum(row["true_deadline_met"] == "0"
                                  for row in subset) / max(1, count),
            "demote": 100.0 * sum(row["meter_demoted"] == "1"
                                    for row in subset) / max(1, count),
            "borrow": 100.0 * sum(row.get("meter_borrowed", "0") == "1"
                                    for row in subset) / max(1, count),
        }
    result["cost"] = (3.0 * result["EMERGENCY"]["miss"]
                      + 1.5 * result["IMPORTANT"]["miss"])
    return result


def control_summary(paths: list[Path]) -> tuple[str, str, str]:
    rows = []
    for path in paths:
        control = path / "qos_control.csv"
        if control.exists():
            rows.extend(read_csv(control))
    if not rows:
        return "", "", ""
    required = {"total_rate_kbps", "budget_error_kbps"}
    missing = required - set(rows[0])
    if missing:
        raise SystemExit(f"qos_control.csv misses columns: {sorted(missing)}")
    errors = [abs(float(row["budget_error_kbps"])) for row in rows]
    rates = [float(row["total_rate_kbps"]) for row in rows]
    return (str(len(rows)), f"{max(errors):.8f}",
            f"{statistics.mean(rates):.4f}")


def emit(label: str, scope: str, paths: list[Path], scene_dur: float) -> None:
    runs = []
    for path in paths:
        deliveries = path / "rl_deliveries.csv"
        if not deliveries.is_file():
            raise SystemExit(f"missing {deliveries}")
        runs.append(read_csv(deliveries))
    ctrl_n, ctrl_error, ctrl_rate = control_summary(paths)
    for sc in ("all", "normal", "high_load", "emergency"):
        per_run = [summarize(rows, sc, scene_dur) for rows in runs]
        total = lambda cls: sum(item[cls]["n"] for item in per_run)
        mean = lambda cls, key: statistics.mean(
            item[cls][key] for item in per_run)
        cost = statistics.mean(item["cost"] for item in per_run)
        print(f"{label},{scope},{len(paths)},{sc},"
              f"{total('EMERGENCY')},{mean('EMERGENCY', 'miss'):.4f},"
              f"{total('IMPORTANT')},{mean('IMPORTANT', 'miss'):.4f},"
              f"{mean('NORMAL', 'miss'):.4f},"
              f"{mean('EMERGENCY', 'demote'):.4f},"
              f"{mean('IMPORTANT', 'demote'):.4f},"
              f"{mean('EMERGENCY', 'borrow'):.4f},{cost:.4f},"
              f"{ctrl_n},{ctrl_error},{ctrl_rate}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", required=True,
                        help="label=run_directory; repeat a label to pool seeds")
    parser.add_argument("--scene-dur", type=float, default=40.0)
    parser.add_argument("--per-run", action="store_true",
                        help="also print one set of rows per input directory")
    args = parser.parse_args()

    groups: dict[str, list[Path]] = defaultdict(list)
    for item in args.input:
        if "=" not in item:
            raise SystemExit(f"invalid --input (expected label=dir): {item}")
        label, raw = item.split("=", 1)
        groups[label].append(Path(raw))

    print("arm,scope,runs,scenario,E_n,E_miss_pct,I_n,I_miss_pct,"
          "N_miss_pct,E_demote_pct,I_demote_pct,E_borrow_pct,weighted_cost,"
          "control_samples,max_budget_error_kbps,total_rate_mean_kbps")
    for label, paths in groups.items():
        emit(label, "pooled", paths, args.scene_dur)
        if args.per_run:
            for path in paths:
                emit(label, path.name, [path], args.scene_dur)


if __name__ == "__main__":
    main()
