#!/usr/bin/env python3
"""Summarize the six-scenario, four-arm paired-seed SCADA benchmark."""

from __future__ import annotations

import argparse
import csv
import math
import re
import statistics
import sys
from pathlib import Path


ARMS = ("baseline", "qos", "rl", "qos_rl")
RUN_TYPES = ("clean", "udp", "poison", "mixed")
RUN_DIR_RE = re.compile(
    r"^(baseline|qos|rl|qos_rl)_(clean|udp|poison|mixed)_seed(\d+)$"
)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def detect_complete_seeds(root: Path) -> list[int]:
    combinations: dict[int, set[tuple[str, str]]] = {}
    for path in root.iterdir():
        if not path.is_dir():
            continue
        match = RUN_DIR_RE.match(path.name)
        if not match:
            continue
        arm, run_type, raw_seed = match.groups()
        seed = int(raw_seed)
        combinations.setdefault(seed, set()).add((arm, run_type))

    expected = {(arm, run_type) for arm in ARMS for run_type in RUN_TYPES}
    return sorted(seed for seed, found in combinations.items() if found == expected)


def miss_metrics(rows: list[dict[str, str]], class_name: str) -> tuple[int, float]:
    selected = [row for row in rows if row["true_class"] == class_name]
    count = len(selected)
    misses = sum(row["true_deadline_met"] == "0" for row in selected)
    # Match scripts/analyze_qos_runs.py: a seed with no samples contributes
    # zero misses, while zero-support counts remain visible in the output.
    return count, 100.0 * misses / max(1, count)


def t_critical_95(sample_count: int) -> float:
    # Two-sided Student-t 95% critical values for common small sample sizes.
    table = {
        2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776,
        6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306,
        10: 2.262, 11: 2.228, 12: 2.201, 13: 2.179,
        14: 2.160, 15: 2.145, 16: 2.131, 17: 2.120,
        18: 2.110, 19: 2.101, 20: 2.093,
    }
    return table.get(sample_count, 1.96)


def mean_ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.mean(values)
    if len(values) < 2:
        return mean, 0.0
    ci = (t_critical_95(len(values)) * statistics.stdev(values)
          / math.sqrt(len(values)))
    return mean, ci


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({
                key: f"{value:.6f}" if isinstance(value, float) else value
                for key, value in row.items()
            })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--scene-dur", type=float, default=40.0)
    parser.add_argument("--seed-start", type=int)
    parser.add_argument("--seed-count", type=int)
    args = parser.parse_args()

    root = args.directory
    if not root.is_dir():
        raise SystemExit(f"Directory does not exist: {root}")

    if (args.seed_start is None) != (args.seed_count is None):
        raise SystemExit("--seed-start and --seed-count must be used together")
    if args.seed_start is not None:
        seeds = list(range(args.seed_start, args.seed_start + args.seed_count))
    else:
        seeds = detect_complete_seeds(root)
    if not seeds:
        raise SystemExit("No complete paired seeds were found")

    print(
        f"Reading {len(seeds)} paired seeds from {root} ...",
        file=sys.stderr,
        flush=True,
    )

    scene = args.scene_dur
    attack_start = 1.0 + 1.25 * scene
    attack_end = attack_start + 0.5 * scene
    scenario_specs = (
        ("normal", "clean", 1.0, 1.0 + scene),
        ("high_load", "clean", 1.0 + scene, 1.0 + 2.0 * scene),
        ("emergency", "clean", 1.0 + 2.0 * scene, 1.0 + 3.0 * scene),
        ("udp_flood", "udp", attack_start, attack_end),
        ("routing_poison", "poison", attack_start, attack_end),
        ("mixed", "mixed", attack_start, attack_end),
    )

    per_seed: dict[tuple[str, str, int], dict[str, float | int]] = {}
    missing: list[Path] = []

    for scenario_index, (scenario, run_type, begin, end) in enumerate(
            scenario_specs, start=1):
        print(
            f"[{scenario_index}/{len(scenario_specs)}] {scenario}",
            file=sys.stderr,
            flush=True,
        )
        for arm in ARMS:
            for seed in seeds:
                run_dir = root / f"{arm}_{run_type}_seed{seed}"
                deliveries = run_dir / "rl_deliveries.csv"
                transitions = run_dir / "rl_transitions.csv"
                if not deliveries.is_file():
                    missing.append(deliveries)
                    continue

                rows = [
                    row for row in read_csv(deliveries)
                    if begin <= float(row["t"]) < end
                ]
                tc_n, tc_miss = miss_metrics(rows, "TIME_CRITICAL")
                op_n, op_miss = miss_metrics(rows, "OPERATIONAL")
                switches = 0
                if transitions.is_file():
                    switches = sum(
                        int(row.get("path_switched", "0"))
                        for row in read_csv(transitions)
                        if begin <= float(row["t"]) < end
                    )
                per_seed[(scenario, arm, seed)] = {
                    "tc_n": tc_n,
                    "tc_miss": tc_miss,
                    "op_n": op_n,
                    "op_miss": op_miss,
                    "J": 3.0 * tc_miss + 1.5 * op_miss,
                    "switches": switches,
                }

    if missing:
        print(f"Missing {len(missing)} delivery files; first entries:")
        for path in missing[:10]:
            print(path)
        raise SystemExit(1)

    per_seed_rows: list[dict[str, object]] = []
    summary_rows: list[dict[str, object]] = []
    paired_rows: list[dict[str, object]] = []

    for scenario, _, _, _ in scenario_specs:
        for arm in ARMS:
            values = [per_seed[(scenario, arm, seed)] for seed in seeds]
            for seed, value in zip(seeds, values):
                per_seed_rows.append({
                    "scenario": scenario,
                    "arm": arm,
                    "seed": seed,
                    "TC_n": value["tc_n"],
                    "TC_miss_pct": value["tc_miss"],
                    "OP_n": value["op_n"],
                    "OP_miss_pct": value["op_miss"],
                    "J": value["J"],
                    "route_switches": value["switches"],
                })

            tc_mean, tc_ci = mean_ci95([float(v["tc_miss"]) for v in values])
            op_mean, op_ci = mean_ci95([float(v["op_miss"]) for v in values])
            j_mean, j_ci = mean_ci95([float(v["J"]) for v in values])
            sw_mean, sw_ci = mean_ci95([float(v["switches"]) for v in values])
            summary_rows.append({
                "scenario": scenario,
                "arm": arm,
                "runs": len(values),
                "TC_n": sum(int(v["tc_n"]) for v in values),
                "TC_zero_support_seeds": sum(int(v["tc_n"]) == 0 for v in values),
                "TC_miss_mean_pct": tc_mean,
                "TC_ci95": tc_ci,
                "OP_n": sum(int(v["op_n"]) for v in values),
                "OP_zero_support_seeds": sum(int(v["op_n"]) == 0 for v in values),
                "OP_miss_mean_pct": op_mean,
                "OP_ci95": op_ci,
                "J_mean": j_mean,
                "J_ci95": j_ci,
                "switch_mean": sw_mean,
                "switch_ci95": sw_ci,
            })

        baseline = [float(per_seed[(scenario, "baseline", seed)]["J"])
                    for seed in seeds]
        for arm in ("qos", "rl", "qos_rl"):
            candidate = [float(per_seed[(scenario, arm, seed)]["J"])
                         for seed in seeds]
            delta = [base - test for base, test in zip(baseline, candidate)]
            delta_mean, delta_ci = mean_ci95(delta)
            baseline_mean = statistics.mean(baseline)
            arm_mean = statistics.mean(candidate)
            paired_rows.append({
                "scenario": scenario,
                "arm_vs_baseline": arm,
                "runs": len(seeds),
                "baseline_J": baseline_mean,
                "arm_J": arm_mean,
                "paired_improvement_J": delta_mean,
                "paired_ci95": delta_ci,
                "reduction_pct": (100.0 * (baseline_mean - arm_mean)
                                  / baseline_mean
                                  if baseline_mean > 0.0 else 0.0),
            })

    write_csv(root / "per_seed_15.csv", per_seed_rows)
    write_csv(root / "summary_15seed.csv", summary_rows)
    write_csv(root / "paired_15seed.csv", paired_rows)

    print(f"PAIRED SEEDS: {seeds[0]}--{seeds[-1]} ({len(seeds)} seeds)")
    print("\nSIX-SCENARIO SUMMARY")
    print(f"{'scenario':<18} {'arm':<10} {'TC miss% ±CI':>17} "
          f"{'OP miss% ±CI':>17} {'J ±CI':>15} {'switch':>9}")
    print("-" * 91)
    for row in summary_rows:
        tc = f"{row['TC_miss_mean_pct']:.2f}±{row['TC_ci95']:.2f}"
        op = f"{row['OP_miss_mean_pct']:.2f}±{row['OP_ci95']:.2f}"
        cost = f"{row['J_mean']:.2f}±{row['J_ci95']:.2f}"
        print(f"{row['scenario']:<18} {row['arm']:<10} {tc:>17} "
              f"{op:>17} {cost:>15} {row['switch_mean']:>9.2f}")

    print("\nPAIRED COMPARISON AGAINST BASELINE")
    print(f"{'scenario':<18} {'arm':<10} {'base J':>9} {'arm J':>9} "
          f"{'improvement ±CI':>18} {'reduction%':>11}")
    print("-" * 82)
    for row in paired_rows:
        improvement = (f"{row['paired_improvement_J']:.2f}"
                       f"±{row['paired_ci95']:.2f}")
        print(f"{row['scenario']:<18} {row['arm_vs_baseline']:<10} "
              f"{row['baseline_J']:>9.2f} {row['arm_J']:>9.2f} "
              f"{improvement:>18} {row['reduction_pct']:>11.2f}")

    zero_support = [row for row in summary_rows
                    if row["TC_zero_support_seeds"]
                    or row["OP_zero_support_seeds"]]
    if zero_support:
        print("\nNOTE: Some seed/class windows have zero support; their miss rate "
              "is defined as 0, matching analyze_qos_runs.py.")
        for row in zero_support:
            print(f"  {row['scenario']}/{row['arm']}: "
                  f"TC zero={row['TC_zero_support_seeds']}, "
                  f"OP zero={row['OP_zero_support_seeds']}")

    print(f"\nCSV files written under: {root}")


if __name__ == "__main__":
    main()
