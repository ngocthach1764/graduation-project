#!/usr/bin/env python3
"""Compare the offline Python and runtime C++ 20-feature vectors."""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path


FEATURES = [
    "pkt_count_1s", "current_pkt_size", "avg_pkt_size", "max_pkt_size",
    "pkt_size_std", "pkt_size_entropy", "inter_arrival_mean",
    "inter_arrival_min", "inter_arrival_std", "current_size_baseline_ratio",
    "time_since_last_pkt", "silent_gap_ratio", "pkt_rate_delta",
    "current_size_zscore", "burst_count_100ms", "burst_count_500ms",
    "short_long_rate_ratio", "baseline_pkt_rate_zscore",
    "baseline_size_zscore", "uplink_downlink_ratio",
]


def key(row: dict[str, str], time_name: str) -> tuple[str, ...]:
    return (
        f"{float(row[time_name]):.6f}", row["device_id"], row["protocol_id"],
        row["protocol"], row["message_kind"],
    )


def load(path: Path, time_name: str) -> dict[tuple[str, ...], list[dict[str, str]]]:
    rows: dict[tuple[str, ...], list[dict[str, str]]] = {}
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            rows.setdefault(key(row, time_name), []).append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--atol", type=float, default=2e-5)
    parser.add_argument("--rtol", type=float, default=2e-5)
    args = parser.parse_args()

    offline = load(args.offline, "packet_t")
    runtime = load(args.runtime, "t")
    compared = 0
    failures: list[str] = []
    for match_key in sorted(set(offline) & set(runtime)):
        left_rows, right_rows = offline[match_key], runtime[match_key]
        for left, right in zip(left_rows, right_rows):
            if right.get("evaluated") != "1":
                continue
            compared += 1
            for feature in FEATURES:
                expected, actual = float(left[feature]), float(right[feature])
                if not math.isclose(expected, actual,
                                    abs_tol=args.atol, rel_tol=args.rtol):
                    failures.append(
                        f"{match_key} {feature}: offline={expected:.9g}, "
                        f"runtime={actual:.9g}"
                    )
                    if len(failures) >= 20:
                        break
            if len(failures) >= 20:
                break
        if len(failures) >= 20:
            break

    if compared == 0:
        raise SystemExit("No evaluated rows matched between the two CSV files")
    if failures:
        raise SystemExit("Feature parity failed:\n" + "\n".join(failures))
    print(f"Feature parity passed: {compared} evaluated messages, {len(FEATURES)} features")


if __name__ == "__main__":
    main()
