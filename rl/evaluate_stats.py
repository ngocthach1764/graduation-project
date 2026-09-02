#!/usr/bin/env python3
"""Per-run comparison of the three routing modes, plus Q-table coverage.

evaluate_rl.py pools every run into one number, which hides the run-to-run
spread.  This script computes each metric once per run and reports
mean +/- 95% confidence interval across runs, then prints the Q-table state
coverage so the whole evaluation fits in one screenshot.

Tail quantiles need care: at ~140 messages per run, P99 lands next to the
maximum, so the per-run value is really "the second worst message of the run"
and averaging it across runs overstates the tail.  Those cells are computed on
the pooled data with a bootstrap interval over runs and marked (bs).

Standard library only.

Usage:
    python3 rl/evaluate_stats.py --root output/rl_eval_v5 \
                                 --qtable rl/outputs/qtable_v5.csv
"""

import argparse
import csv
import glob
import math
import os
import random
from collections import defaultdict

CLASS_BY_ID = {0: "NORMAL", 1: "IMPORTANT", 2: "EMERGENCY"}
CLASS_ORDER = ["EMERGENCY", "IMPORTANT", "NORMAL"]

# (key, label)
METRICS = [
    ("loss_rate", "Ti le mat"),
    ("deadline_miss_rate", "Ti le tre han"),
    ("delay_mean_ms", "Do tre TB (ms)"),
    ("delay_p95_ms", "Do tre P95 (ms)"),
    ("delay_p99_ms", "Do tre P99 (ms)"),
    ("reward_mean", "Phan thuong TB"),
    ("path_switch_rate", "Ti le chuyen duong"),
]

SAFETY_METRICS = [
    ("non_min_health_action_rate", "non_min_health_action"),
    ("degraded_fallback_rate", "degraded_fallback"),
]

LABEL_W = 22
VALUE_W = 21
TABLE_W = LABEL_W + 3 * VALUE_W          # 85

SCHEMA = "health_best_v4_sev"
CLASS_STRIDE = 27 * 3                     # 27 to hop suc khoe x 3 duong tot nhat
STATES_PER_CLASS = CLASS_STRIDE
N_GATEWAYS = 3

# Quantiles that may be unreliable per run, and the tail-sample floor.  Verified
# on rl_eval_v5: at ~141 EMERGENCY messages per run, P95 leaves ~7 samples in the
# tail and the per-run mean matches the pooled value to 0.02 ms, while P99 leaves
# ~1.4 and the two diverge by more than a factor of two.
QUANTILE_KEYS = {"delay_p95_ms": 0.95, "delay_p99_ms": 0.99}
MIN_TAIL_SAMPLES = 5

T95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160,
    14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093,
    20: 2.086, 21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}


def t_critical(df):
    if df <= 0:
        return float("nan")
    if df in T95:
        return T95[df]
    return 1.96 if df > 30 else T95[30]


def percentile(values, q):
    """Linear-interpolation percentile, matching pandas' default quantile."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = q * (len(ordered) - 1)
    low = int(math.floor(position))
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def mean(values):
    return sum(values) / len(values) if values else float("nan")


def stdev(values):
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / (len(values) - 1))


def mean_ci(values):
    if not values:
        return float("nan"), float("nan")
    if len(values) < 2:
        return values[0], 0.0
    return mean(values), t_critical(len(values) - 1) * stdev(values) / math.sqrt(len(values))


def quantile_reliable(data, order, cls, q):
    """True only if every run keeps at least MIN_TAIL_SAMPLES above the quantile."""
    for mode in order:
        for runs in data[mode].values():
            if len(runs[cls]["_delays"]) * (1.0 - q) < MIN_TAIL_SAMPLES:
                return False
    return True


def pooled_quantile(data, mode, cls, q):
    merged = []
    for runs in data[mode].values():
        merged.extend(runs[cls]["_delays"])
    return percentile(merged, q)


def bootstrap_pooled_quantile(data, mode, cls, q, reps, seed):
    """Pooled quantile plus a bootstrap interval obtained by resampling runs.

    Pooling gives a good point estimate but destroys the independent per-run
    observations an interval needs.  Resampling run ids with replacement puts
    that variability back.  Returns (estimate, low, high).
    """
    per_run = [runs[cls]["_delays"] for runs in data[mode].values()]
    n = len(per_run)
    est = pooled_quantile(data, mode, cls, q)
    if n < 2:
        return est, est, est
    rng = random.Random(seed)
    replicates = []
    for _ in range(reps):
        merged = []
        for _ in range(n):
            merged.extend(per_run[rng.randrange(n)])
        replicates.append(percentile(merged, q))
    return est, percentile(replicates, 0.025), percentile(replicates, 0.975)


def read_run(run_dir):
    transitions_path = os.path.join(run_dir, "rl_transitions.csv")
    deliveries_path = os.path.join(run_dir, "rl_deliveries.csv")
    if not (os.path.exists(transitions_path) and os.path.exists(deliveries_path)):
        raise SystemExit("Thieu file CSV trong %s" % run_dir)

    totals = defaultdict(float)
    lost = defaultdict(float)
    misses = defaultdict(float)
    rewards = defaultdict(list)
    switches = defaultdict(list)
    non_min = defaultdict(list)
    fallback = defaultdict(list)

    with open(transitions_path) as handle:
        for row in csv.DictReader(handle):
            cls = CLASS_BY_ID[int(row["traffic_class_id"])]
            totals[cls] += float(row["total"])
            lost[cls] += float(row["lost"])
            misses[cls] += float(row["deadline_misses"])
            rewards[cls].append(float(row["reward"]))
            switches[cls].append(float(row["path_switched"]))
            non_min[cls].append(
                1.0 if int(row["action_health"]) > int(row["min_health"]) else 0.0)
            fallback[cls].append(float(row["degraded_fallback"]))

    delays = defaultdict(list)
    with open(deliveries_path) as handle:
        for row in csv.DictReader(handle):
            delays[row["traffic_class"]].append(float(row["delay_ms"]))

    out = {}
    for cls in CLASS_ORDER:
        total = totals[cls]
        d = delays[cls]
        out[cls] = {
            "_delays": d,
            "sent": total,
            "loss_rate": lost[cls] / total if total else float("nan"),
            "deadline_miss_rate": misses[cls] / total if total else float("nan"),
            "delay_mean_ms": mean(d),
            "delay_p95_ms": percentile(d, 0.95),
            "delay_p99_ms": percentile(d, 0.99),
            "reward_mean": mean(rewards[cls]),
            "path_switch_rate": mean(switches[cls]),
            "non_min_health_action_rate": mean(non_min[cls]),
            "degraded_fallback_rate": mean(fallback[cls]),
        }
    return out


def discover(root, modes):
    found = {}
    for mode_dir in sorted(glob.glob(os.path.join(root, "*"))):
        mode = os.path.basename(mode_dir)
        if not os.path.isdir(mode_dir) or (modes and mode not in modes):
            continue
        runs = {}
        for run_dir in sorted(glob.glob(os.path.join(mode_dir, "run*"))):
            if os.path.isdir(run_dir):
                runs[os.path.basename(run_dir)] = read_run(run_dir)
        if runs:
            found[mode] = runs
    return found


def fmt(value, decimals):
    return "-" if value != value else "%.*f" % (decimals, value)


def fmt_ci(values, decimals):
    m, half = mean_ci(values)
    return "-" if m != m else "%s +/- %s" % (fmt(m, decimals), fmt(half, decimals))


def decimals_for(key):
    return 2 if key.startswith("delay") else 4


def qtable_coverage(path, min_visits):
    """Visited-state counts per traffic class, summed over the three gateways."""
    table = defaultdict(dict)
    with open(path) as handle:
        for row in csv.reader(handle):
            if len(row) < 6 or row[5] != SCHEMA:
                continue
            table[(int(row[0]), int(row[1]))][int(row[2])] = int(row[4])

    seen = defaultdict(int)
    deep = defaultdict(int)
    for (_, state), actions in table.items():
        cls = CLASS_BY_ID[min(state // CLASS_STRIDE, 2)]
        visits = sum(actions.values())
        if visits > 0:
            seen[cls] += 1
        if visits >= min_visits:
            deep[cls] += 1

    total = STATES_PER_CLASS * N_GATEWAYS
    print("=" * TABLE_W)
    print("DO PHU BANG Q (%s)" % os.path.basename(path))
    print("=" * TABLE_W)
    print("%-12s %16s %10s %22s"
          % ("Lop", "Da ghe tham", "Do phu", "So dong >= %d luot" % min_visits))
    print("-" * TABLE_W)
    for cls in CLASS_ORDER:
        print("%-12s %10d /%4d %9.1f%% %22d"
              % (cls, seen[cls], total, 100.0 * seen[cls] / total, deep[cls]))
    print("-" * TABLE_W)
    print("Moi gateway co %d trang thai cho mot lop; bang tinh gop %d gateway."
          % (STATES_PER_CLASS, N_GATEWAYS))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True,
                        help="Thu muc chua cac che do, vi du output/rl_eval_v5")
    parser.add_argument("--modes", default=None,
                        help="Danh sach che do, phan cach bang dau phay")
    parser.add_argument("--qtable", default="rl/outputs/qtable_v5.csv",
                        help="File bang Q de tinh do phu")
    parser.add_argument("--min-visits", type=int, default=20)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=12345)
    args = parser.parse_args()

    modes = [m.strip() for m in args.modes.split(",")] if args.modes else None
    data = discover(args.root, modes)
    if not data:
        raise SystemExit("Khong tim thay lan chay nao trong %s" % args.root)

    order = [m for m in ("off", "heuristic", "train", "qtable") if m in data]
    order += [m for m in sorted(data) if m not in order]

    print("=" * TABLE_W)
    print("SO SANH BA CHE DO DINH TUYEN -- %s" % args.root)
    print("=" * TABLE_W)
    for mode in order:
        runs = sorted(data[mode])
        span = runs[0] if len(runs) == 1 else "%s .. %s" % (runs[0], runs[-1])
        print("  %-12s %3d lan chay  (%s)" % (mode, len(runs), span))
    print("  Gia tri: trung binh +/- nua khoang tin cay 95%% tren %d lan chay"
          % len(data[order[0]]))

    for cls in CLASS_ORDER:
        sent = [runs[cls]["sent"] for runs in data[order[0]].values()]
        print()
        print("=" * TABLE_W)
        print("LOP %s  --  %s ban tin moi lan chay" % (cls, fmt_ci(sent, 0)))
        print("-" * TABLE_W)
        header = "%-*s" % (LABEL_W, "Chi so")
        for mode in order:
            header += "%*s" % (VALUE_W, mode)
        print(header)
        print("-" * TABLE_W)

        for key, label in METRICS:
            q = QUANTILE_KEYS.get(key)
            per_run_ok = q is None or quantile_reliable(data, order, cls, q)
            if not per_run_ok:
                # Marker only.  What (bs) means is documented in the report text,
                # not reprinted under every table.
                label += " (bs)"
            line = "%-*s" % (LABEL_W, label)
            for mode in order:
                if per_run_ok:
                    values = [runs[cls][key] for runs in data[mode].values()]
                    cell = fmt_ci([v for v in values if v == v], decimals_for(key))
                else:
                    est, low, high = bootstrap_pooled_quantile(
                        data, mode, cls, q, args.bootstrap, args.seed)
                    dec = 0 if abs(est) >= 1000 else 2
                    cell = "%s [%s-%s]" % (fmt(est, dec), fmt(low, dec),
                                           fmt(high, dec))
                line += "%*s" % (VALUE_W, cell)
            print(line)

        print("-" * TABLE_W)
        for key, label in SAFETY_METRICS:
            line = "%-*s" % (LABEL_W, label)
            for mode in order:
                values = [runs[cls][key] for runs in data[mode].values()]
                line += "%*s" % (VALUE_W, fmt_ci(values, 4))
            print(line)

    print()
    if os.path.exists(args.qtable):
        qtable_coverage(args.qtable, args.min_visits)
    else:
        print("Bo qua do phu bang Q: khong tim thay %s" % args.qtable)


if __name__ == "__main__":
    main()
