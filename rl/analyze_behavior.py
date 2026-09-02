#!/usr/bin/env python3
"""Behaviour diagnostics for the trained gateway policy.

evaluate_stats.py compares the three routing modes on service-quality metrics.
This script answers the follow-up questions those metrics raise: how often the
network is actually degraded, which reward term drives the policy, why control
falls back to the heuristic, and how much of the Q-table was ever learned.

Standard library only.

Usage:
    python3 rl/analyze_behavior.py --root output/rl_eval_v5 \
                                   --qtable rl/outputs/qtable_v5.csv
"""

import argparse
import csv
import glob
import os
from collections import defaultdict

CLASS_BY_ID = {0: "NORMAL", 1: "IMPORTANT", 2: "EMERGENCY"}
CLASS_ORDER = ["EMERGENCY", "IMPORTANT", "NORMAL"]
SEVERITY = {"EMERGENCY": 3.0, "IMPORTANT": 1.5, "NORMAL": 1.0}
SCHEMA = "health_best_v4_sev"
CLASS_STRIDE = 27 * 3          # 27 to hop suc khoe x 3 duong tot nhat
STATES_PER_CLASS = CLASS_STRIDE
WIDTH = 78

TERMS = [
    ("delay", "Do tre TB"),
    ("loss", "Mat ban tin"),
    ("miss", "Tre han"),
    ("tail", "Duoi tre"),
    ("queue", "Hang doi"),
    ("switch", "Chuyen duong"),
]


def banner(title):
    print("=" * WIDTH)
    print(title)
    print("=" * WIDTH)


def load(root, mode):
    rows = []
    pattern = os.path.join(root, mode, "run*", "rl_transitions.csv")
    for path in sorted(glob.glob(pattern)):
        with open(path) as handle:
            rows.extend(list(csv.DictReader(handle)))
    if not rows:
        raise SystemExit("Khong doc duoc %s" % pattern)
    return rows


def health_distribution(rows):
    banner("1. PHAN BO BIN SUC KHOE (bin tot nhat hien co, che do qtable)")
    counts = defaultdict(int)
    for row in rows:
        counts[int(row["min_health"])] += 1
    total = sum(counts.values())
    names = {0: "bin 0 - binh thuong", 1: "bin 1 - suy giam nhe",
             2: "bin 2 - suy giam nang"}
    print("%-26s %10s %10s" % ("Bin", "So cua so", "Ti le"))
    print("-" * WIDTH)
    for bin_id in (0, 1, 2):
        print("%-26s %10d %9.2f%%"
              % (names[bin_id], counts[bin_id], 100.0 * counts[bin_id] / total))
    print("-" * WIDTH)
    print("%-26s %10d" % ("Tong so cua so", total))
    print()


def reward_decomposition(rows):
    banner("2. PHAN RA HAM THUONG (che do qtable)")
    acc = {c: defaultdict(float) for c in CLASS_ORDER}
    count = defaultdict(int)
    reward = defaultdict(float)
    for row in rows:
        cls = CLASS_BY_ID[int(row["traffic_class_id"])]
        sev = SEVERITY[cls]
        total = float(row["total"]) or 1.0
        a = acc[cls]
        a["delay"] += 0.75 * float(row["avg_norm_delay"])
        a["loss"] += 3.00 * sev * float(row["lost"]) / total
        a["miss"] += 2.00 * sev * float(row["deadline_misses"]) / total
        a["tail"] += 0.75 * max(0.0, float(row["max_norm_delay"]) - 0.50)
        a["queue"] += 0.25 * float(row["queue_at_start"])
        a["switch"] += 0.15 * float(row["path_switched"])
        reward[cls] += float(row["reward"])
        count[cls] += 1

    header = "%-12s" % "Lop"
    for _, label in TERMS:
        header += "%13s" % label
    print(header)
    print("-" * WIDTH)
    for cls in CLASS_ORDER:
        n = count[cls]
        means = {k: acc[cls][k] / n for k, _ in TERMS}
        penalty = sum(means.values())
        line = "%-12s" % cls
        for key, _ in TERMS:
            line += "%12.1f%%" % (100.0 * means[key] / penalty)
        print(line)
    print("-" * WIDTH)
    print("%-12s %12s %12s %12s" % ("Lop", "Tong phat", "1 - phat", "Thuong TB"))
    for cls in CLASS_ORDER:
        n = count[cls]
        penalty = sum(acc[cls][k] / n for k, _ in TERMS)
        print("%-12s %12.4f %12.4f %12.4f"
              % (cls, penalty, 1.0 - penalty, reward[cls] / n))
    print("Chenh lech giua 'Thuong TB' va '1 - phat' la do san -2*severity.")
    print()


def fallback_breakdown(rows):
    banner("3. NGUYEN NHAN TRA QUYEN DIEU KHIEN VE HEURISTIC (qtable)")
    stats = {c: [0, 0, 0] for c in CLASS_ORDER}   # n, fallback, all-degraded
    for row in rows:
        cls = CLASS_BY_ID[int(row["traffic_class_id"])]
        s = stats[cls]
        s[0] += 1
        s[1] += int(row["degraded_fallback"])
        if int(row["min_health"]) == 2:
            s[2] += 1
    print("%-12s %11s %13s %14s %13s"
          % ("Lop", "Tong", "Ca 3 duong", "Chot chan +", "Do bang Q"))
    print("%-12s %11s %13s %14s %13s"
          % ("", "fallback", "suy giam", "trang thai moi", "quyet dinh"))
    print("-" * WIDTH)
    for cls in CLASS_ORDER:
        n, fb, deg = stats[cls]
        print("%-12s %10.2f%% %12.2f%% %13.2f%% %12.2f%%"
              % (cls, 100.0 * fb / n, 100.0 * deg / n,
                 100.0 * (fb - deg) / n, 100.0 * (n - fb) / n))
    print()


def queue_occupancy(rows):
    banner("4. CHIEM DUNG HANG DOI q_p (qtable)")
    values = sorted(float(row["queue_at_start"]) for row in rows)
    n = len(values)
    print("So mau                  : %d" % n)
    print("Trung binh              : %.5f" % (sum(values) / n))
    for pct in (50, 90, 99, 99.9):
        print("Phan vi P%-14s : %.5f" % (pct, values[min(int(n * pct / 100), n - 1)]))
    print("Gia tri lon nhat        : %.4f" % values[-1])
    over30 = sum(1 for v in values if v >= 0.30)
    over70 = sum(1 for v in values if v >= 0.70)
    print("Ti le q_p >= 0.30 (bin 1): %.3f%%" % (100.0 * over30 / n))
    print("Ti le q_p >= 0.70 (bin 2): %.3f%%" % (100.0 * over70 / n))
    print()


def qtable_coverage(path, min_visits):
    banner("5. DO PHU BANG Q (%s)" % os.path.basename(path))
    table = defaultdict(dict)
    with open(path) as handle:
        for row in csv.reader(handle):
            if len(row) < 6 or row[5] != SCHEMA:
                continue
            gateway, state, action = int(row[0]), int(row[1]), int(row[2])
            table[(gateway, state)][action] = int(row[4])

    seen = defaultdict(int)
    deep = defaultdict(int)
    for (_, state), actions in table.items():
        cls = CLASS_BY_ID[min(state // CLASS_STRIDE, 2)]
        visits = sum(actions.values())
        if visits > 0:
            seen[cls] += 1
        if visits >= min_visits:
            deep[cls] += 1

    total = STATES_PER_CLASS * 3   # ba gateway
    print("%-12s %14s %10s %20s" % ("Lop", "Da ghe tham", "Do phu",
                                    "So dong >= %d luot" % min_visits))
    print("-" * WIDTH)
    for cls in CLASS_ORDER:
        print("%-12s %8d /%4d %9.1f%% %20d"
              % (cls, seen[cls], total, 100.0 * seen[cls] / total, deep[cls]))
    print("-" * WIDTH)
    print("Moi gateway co %d trang thai cho mot lop; bang tinh gop ba gateway."
          % STATES_PER_CLASS)
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True,
                        help="Thu muc chua cac che do, vi du output/rl_eval_v5")
    parser.add_argument("--mode", default="qtable")
    parser.add_argument("--qtable", default="rl/outputs/qtable_v5.csv")
    parser.add_argument("--min-visits", type=int, default=20)
    args = parser.parse_args()

    rows = load(args.root, args.mode)
    print()
    health_distribution(rows)
    reward_decomposition(rows)
    fallback_breakdown(rows)
    queue_occupancy(rows)
    if os.path.exists(args.qtable):
        qtable_coverage(args.qtable, args.min_visits)
    else:
        print("Bo qua do phu bang Q: khong tim thay %s" % args.qtable)


if __name__ == "__main__":
    main()
