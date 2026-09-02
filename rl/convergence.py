#!/usr/bin/env python3
"""Learning curve for the gateway Q-policy.

Reads every training episode directory produced by train_qlearning.py, averages
the per-window reward inside each episode, then groups episodes into bins so the
trend is readable in one table.  The epsilon column is printed alongside because
part of any early reward increase comes from exploration decaying, not from the
policy improving -- the two must not be confused.

Standard library only.

Usage:
    python3 rl/convergence.py --root output/rl_train_v5
    python3 rl/convergence.py --root output/rl_train_v5 --bins 10
"""

import argparse
import csv
import glob
import os
from collections import defaultdict

CLASS_BY_ID = {0: "NORMAL", 1: "IMPORTANT", 2: "EMERGENCY"}
CLASS_ORDER = ["EMERGENCY", "IMPORTANT", "NORMAL"]
WIDTH = 76
BAR_WIDTH = 34


def episode_reward(path):
    """Mean reward per traffic class for one episode."""
    total = defaultdict(float)
    count = defaultdict(int)
    with open(path) as handle:
        for row in csv.DictReader(handle):
            cls = CLASS_BY_ID[int(row["traffic_class_id"])]
            total[cls] += float(row["reward"])
            count[cls] += 1
    return {c: (total[c] / count[c] if count[c] else None) for c in CLASS_ORDER}


def epsilon_at(index, episodes, start=1.0, end=0.05):
    """Same linear schedule train_qlearning.py uses."""
    if episodes <= 1:
        return end
    return start + (end - start) * (index / (episodes - 1))


def bar(value, low, high):
    if value is None or high <= low:
        return ""
    filled = int(round(BAR_WIDTH * (value - low) / (high - low)))
    return "#" * max(1, filled)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True,
                        help="Thu muc huan luyen, vi du output/rl_train_v5")
    parser.add_argument("--bins", type=int, default=20,
                        help="So moc gom episode (mac dinh 20)")
    args = parser.parse_args()

    dirs = sorted(d for d in glob.glob(os.path.join(args.root, "episode_*"))
                  if os.path.isdir(d))
    if not dirs:
        raise SystemExit("Khong tim thay episode nao trong %s" % args.root)

    per_episode = []
    for directory in dirs:
        path = os.path.join(directory, "rl_transitions.csv")
        if os.path.exists(path):
            per_episode.append(episode_reward(path))

    episodes = len(per_episode)
    bins = max(1, min(args.bins, episodes))
    size = episodes / bins

    print("=" * WIDTH)
    print("DUONG CONG HOI TU (%s, %d episode)" % (args.root, episodes))
    print("=" * WIDTH)
    print("%-5s %-11s %9s %11s %11s %11s"
          % ("Moc", "Episode", "Epsilon", "EMERGENCY", "IMPORTANT", "NORMAL"))
    print("-" * WIDTH)

    rows = []
    for b in range(bins):
        lo = int(round(b * size))
        hi = int(round((b + 1) * size))
        chunk = per_episode[lo:hi]
        if not chunk:
            continue
        means = {}
        for cls in CLASS_ORDER:
            values = [e[cls] for e in chunk if e[cls] is not None]
            means[cls] = sum(values) / len(values) if values else None
        eps = epsilon_at((lo + hi - 1) / 2.0, episodes)
        rows.append((b + 1, lo + 1, hi, eps, means))
        print("%-5d %-11s %9.3f %11s %11s %11s"
              % (b + 1, "%03d-%03d" % (lo + 1, hi), eps,
                 "-" if means["EMERGENCY"] is None else "%.4f" % means["EMERGENCY"],
                 "-" if means["IMPORTANT"] is None else "%.4f" % means["IMPORTANT"],
                 "-" if means["NORMAL"] is None else "%.4f" % means["NORMAL"]))

    for cls in CLASS_ORDER:
        values = [r[4][cls] for r in rows if r[4][cls] is not None]
        if not values:
            continue
        low, high = min(values), max(values)
        print()
        print("-" * WIDTH)
        print("Phan thuong TB theo moc -- lop %s  (thang %.4f .. %.4f)"
              % (cls, low, high))
        print("-" * WIDTH)
        for index, lo, hi, _, means in rows:
            value = means[cls]
            print("%-11s %8s  %s" % ("%03d-%03d" % (lo, hi),
                                     "-" if value is None else "%.4f" % value,
                                     bar(value, low, high)))

    print()
    print("=" * WIDTH)
    print("Epsilon giam tuyen tinh 1.00 -> 0.05 theo episode. Phan thuong tang")
    print("o giai doan dau mot phan do tham do giam, khong hoan toan do chinh")
    print("sach tot len; can doc hai cot cung nhau.")
    print("=" * WIDTH)


if __name__ == "__main__":
    main()
