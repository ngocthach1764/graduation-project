#!/usr/bin/env python3
"""Create report-ready QoS figures from a run_qos_audit.sh output."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


SCENARIOS = ("normal", "high_load", "emergency")
ARM_ORDER = ("priority_only", "static15_45", "static30_30",
             "static45_15", "dynamic")
ARM_LABELS = ("Priority\nonly", "Static\n1.5/4.5", "Static\n3/3",
              "Static\n4.5/1.5", "Dynamic")
ARM_COLORS = ("#4daf4a", "#7aa6c2", "#7aa6c2", "#7aa6c2", "#d95f02")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def dynamic_dirs(root: Path, prefix: str) -> list[Path]:
    found = sorted(root.glob(f"{prefix}_dynamic_run*"))
    if found:
        return found
    if prefix == "rf":
        return sorted(root.glob("dynamic_miss_run*"))
    return sorted(root.glob("dynamic_miss_run*"))


def save(fig: plt.Figure, out_dir: Path, stem: str) -> None:
    fig.tight_layout()
    for suffix in ("pdf", "png"):
        fig.savefig(out_dir / f"{stem}.{suffix}", dpi=220, bbox_inches="tight")
    plt.close(fig)


def plot_cost(metrics_path: Path, out_dir: Path) -> None:
    rows = [row for row in read_csv(metrics_path)
            if row["scope"] == "pooled" and row["scenario"] == "all"]
    by_arm = {row["arm"]: float(row["weighted_cost"]) for row in rows}
    modes = [mode for mode in ("rf", "oracle")
             if any(f"{mode}_{arm}" in by_arm for arm in ARM_ORDER)]
    if not modes:
        raise SystemExit("qos_metrics.csv has no pooled RF/oracle arms")
    fig, axes = plt.subplots(1, len(modes), figsize=(5.2 * len(modes), 4.2),
                             squeeze=False)
    for ax, mode in zip(axes[0], modes):
        values = [by_arm.get(f"{mode}_{arm}", np.nan) for arm in ARM_ORDER]
        bars = ax.bar(ARM_LABELS, values, color=ARM_COLORS)
        ax.set_title("Random Forest" if mode == "rf" else "Oracle")
        ax.set_ylabel(r"Weighted deadline cost $J$")
        ax.grid(axis="y", alpha=0.25)
        for bar, value in zip(bars, values):
            if np.isfinite(value):
                ax.text(bar.get_x() + bar.get_width() / 2, value,
                        f"{value:.2f}", ha="center", va="bottom", fontsize=9)
    save(fig, out_dir, "qos-cost-comparison")


def averaged_rates(paths: list[Path]) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    values: dict[str, dict[float, list[float]]] = {
        "EMERGENCY": defaultdict(list), "IMPORTANT": defaultdict(list)
    }
    for path in paths:
        for row in read_csv(path / "qos_control.csv"):
            values[row["class"]][round(float(row["t"]), 4)].append(
                float(row["rate_kbps"])
            )
    result = {}
    for cls, by_time in values.items():
        times = np.array(sorted(by_time))
        means = np.array([np.mean(by_time[t]) for t in times])
        result[cls] = (times, means)
    return result


def plot_rates(rf_root: Path, oracle_root: Path, out_dir: Path) -> None:
    panels = []
    for label, root, prefix in (("Random Forest", rf_root, "rf"),
                                ("Oracle", oracle_root, "oracle")):
        paths = dynamic_dirs(root, prefix)
        if paths:
            panels.append((label, paths))
    if not panels:
        raise SystemExit("no dynamic qos_control.csv directories found")
    fig, axes = plt.subplots(len(panels), 1, figsize=(9.0, 3.2 * len(panels)),
                             sharex=True, squeeze=False)
    for ax, (label, paths) in zip(axes[:, 0], panels):
        rates = averaged_rates(paths)
        for cls, color in (("EMERGENCY", "#d73027"),
                           ("IMPORTANT", "#4575b4")):
            times, means = rates[cls]
            ax.plot(times, means, color=color, linewidth=1.5, label=cls)
        ax.axvline(41, color="black", linestyle="--", linewidth=0.8)
        ax.axvline(81, color="black", linestyle="--", linewidth=0.8)
        ax.set_ylabel("Profile rate (kbps)")
        ax.set_title(f"{label}: mean of {len(paths)} paired runs")
        ax.grid(alpha=0.25)
        ax.legend(loc="best")
    axes[-1, 0].set_xlabel("Simulation time (s)")
    save(fig, out_dir, "qos-rate-trajectory")


def phase(t: float, scene: float) -> str:
    if t < 1 + scene:
        return "normal"
    if t < 1 + 2 * scene:
        return "high_load"
    return "emergency"


def plot_class_mix(rf_root: Path, out_dir: Path, scene: float) -> None:
    paths = dynamic_dirs(rf_root, "rf")
    counts = {sc: {"true": defaultdict(int), "assigned": defaultdict(int)}
              for sc in SCENARIOS}
    for path in paths:
        for row in read_csv(path / "rl_deliveries.csv"):
            sc = phase(float(row["t"]), scene)
            if row["true_class"] in ("EMERGENCY", "IMPORTANT"):
                counts[sc]["true"][row["true_class"]] += 1
            if row["traffic_class"] in ("EMERGENCY", "IMPORTANT"):
                counts[sc]["assigned"][row["traffic_class"]] += 1

    x = np.arange(len(SCENARIOS))
    width = 0.34
    fig, ax = plt.subplots(figsize=(8.2, 4.5))
    for offset, kind, color in ((-width / 2, "true", "#4daf4a"),
                                (width / 2, "assigned", "#984ea3")):
        shares = []
        for sc in SCENARIOS:
            e = counts[sc][kind]["EMERGENCY"]
            i = counts[sc][kind]["IMPORTANT"]
            shares.append(100.0 * e / max(1, e + i))
        bars = ax.bar(x + offset, shares, width, label=kind.capitalize(),
                      color=color)
        for bar, value in zip(bars, shares):
            ax.text(bar.get_x() + bar.get_width() / 2, value,
                    f"{value:.1f}%", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x, ("normal", "high load", "emergency"))
    ax.set_ylabel("Emergency share among urgent messages (%)")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    save(fig, out_dir, "qos-rf-class-mix")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path,
                        help="qos_audit directory containing qos_metrics.csv")
    parser.add_argument("--metrics", type=Path)
    parser.add_argument("--rf-root", type=Path)
    parser.add_argument("--oracle-root", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--scene-dur", type=float, default=40.0)
    args = parser.parse_args()

    metrics = args.metrics or args.root / "qos_metrics.csv"
    rf_root = args.rf_root or args.root
    oracle_root = args.oracle_root or args.root
    out_dir = args.out_dir or args.root / "figures"
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_cost(metrics, out_dir)
    plot_rates(rf_root, oracle_root, out_dir)
    plot_class_mix(rf_root, out_dir, args.scene_dur)
    print(out_dir)


if __name__ == "__main__":
    main()
