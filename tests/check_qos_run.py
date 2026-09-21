#!/usr/bin/env python3
"""Fail fast when a dynamic QoS run violates controller invariants."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--budget-kbps", type=float, required=True)
    parser.add_argument("--tolerance-kbps", type=float, default=0.0002)
    args = parser.parse_args()

    path = args.run_dir / "qos_control.csv"
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise SystemExit("qos_control.csv has no samples")
    required = {"feedback_mass", "total_rate_kbps", "budget_error_kbps"}
    if not required.issubset(rows[0]):
        raise SystemExit(f"qos_control.csv misses columns: {required-set(rows[0])}")
    maximum = 0.0
    by_time: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_time[row["t"]].append(row)
        total = float(row["total_rate_kbps"])
        error = max(abs(total - args.budget_kbps),
                    abs(float(row["budget_error_kbps"])))
        maximum = max(maximum, error)
        if float(row["rate_kbps"]) < 0.0 or float(row["feedback_mass"]) < 0.0:
            raise SystemExit("negative rate or feedback mass")
    for timestamp, samples in by_time.items():
        classes = {row["class"] for row in samples}
        if classes != {"OPERATIONAL", "TIME_CRITICAL"} or len(samples) != 2:
            raise SystemExit(f"invalid class rows at t={timestamp}: {classes}")
        actual = sum(float(row["rate_kbps"]) for row in samples)
        maximum = max(maximum, abs(actual - args.budget_kbps))
    if maximum > args.tolerance_kbps:
        raise SystemExit(f"budget conservation failed: max error={maximum}")
    print(f"QoS controller contract passed: {len(rows)} rows, "
          f"max budget error={maximum:.8f} kbps")


if __name__ == "__main__":
    main()
