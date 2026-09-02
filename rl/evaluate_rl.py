#!/usr/bin/env python3
"""Compare RL runtime outputs from off, heuristic, train, or qtable runs."""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


CLASS_BY_ID = {0: "NORMAL", 1: "IMPORTANT", 2: "EMERGENCY"}


def parse_input(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected LABEL=OUTPUT_DIRECTORY")
    label, path = value.split("=", 1)
    return label.strip(), Path(path).expanduser()


def read_mode(label, directories):
    deliveries = []
    transitions = []
    for directory in directories:
        delivery_path = directory / "rl_deliveries.csv"
        transition_path = directory / "rl_transitions.csv"
        if not delivery_path.exists() or not transition_path.exists():
            raise SystemExit(f"Missing RL CSV files under {directory}")
        d = pd.read_csv(delivery_path)
        t = pd.read_csv(transition_path)
        d["run_dir"] = str(directory)
        t["run_dir"] = str(directory)
        deliveries.append(d)
        transitions.append(t)
    return pd.concat(deliveries, ignore_index=True), pd.concat(
        transitions, ignore_index=True)


def summarize(label, deliveries, transitions):
    rows = []
    transitions = transitions.copy()
    transitions["traffic_class"] = transitions["traffic_class_id"].map(CLASS_BY_ID)
    for traffic_class in ["EMERGENCY", "IMPORTANT", "NORMAL"]:
        d = deliveries[deliveries["traffic_class"] == traffic_class]
        t = transitions[transitions["traffic_class"] == traffic_class]
        total = int(t["total"].sum()) if not t.empty else 0
        lost = int(t["lost"].sum()) if not t.empty else 0
        missed = int(t["deadline_misses"].sum()) if not t.empty else 0
        arrived = len(d)
        on_time = int(d["deadline_met"].sum()) if "deadline_met" in d else 0
        non_min_health = (
            (t["action_health"] > t["min_health"]).mean()
            if {"action_health", "min_health"}.issubset(t.columns) and len(t)
            else np.nan
        )
        degraded_fallback = (
            t["degraded_fallback"].mean()
            if "degraded_fallback" in t and len(t) else np.nan
        )
        rows.append({
            "model": label,
            "traffic_class": traffic_class,
            "sent": total,
            "delivered_before_timeout": total - lost,
            "eventual_arrivals": arrived,
            "on_time_delivered": on_time,
            "loss_rate": lost / total if total else np.nan,
            "deadline_miss_rate": missed / total if total else np.nan,
            "delay_mean_ms": d["delay_ms"].mean() if arrived else np.nan,
            "delay_p95_ms": d["delay_ms"].quantile(0.95) if arrived else np.nan,
            "delay_p99_ms": d["delay_ms"].quantile(0.99) if arrived else np.nan,
            "reward_mean": t["reward"].mean() if len(t) else np.nan,
            "path_switch_rate": t["path_switched"].mean() if len(t) else np.nan,
            "non_min_health_action_rate": non_min_health,
            "degraded_fallback_rate": degraded_fallback,
        })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", action="append", required=True, type=parse_input,
        metavar="LABEL=DIR",
        help="May be repeated; repeated labels are aggregated across runs")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    grouped = {}
    for label, directory in args.input:
        grouped.setdefault(label, []).append(directory.resolve())

    rows = []
    for label, directories in grouped.items():
        deliveries, transitions = read_mode(label, directories)
        rows.extend(summarize(label, deliveries, transitions))

    summary = pd.DataFrame(rows)
    ordered = summary.sort_values(["traffic_class", "model"])
    with pd.option_context("display.max_columns", None, "display.width", 180):
        print(ordered.to_string(index=False, float_format=lambda x: f"{x:.6f}"))

    if args.out:
        out = Path(args.out).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        ordered.to_csv(out, index=False)
        print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
