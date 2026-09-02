#!/usr/bin/env python3
"""Train the ns-3 gateway tabular Q-policy over independent episodes."""

import argparse
import csv
import math
import subprocess
from pathlib import Path


N_PATHS = 3
N_HEALTH_COMBINATIONS = 27
# Must mirror GatewayRlAgent in scratch/scada/rl_agent.h: state is
# (class, health, best_current_path); previous_path was dropped in v4.
CLASS_STRIDE = N_HEALTH_COMBINATIONS * N_PATHS
N_STATES = 3 * CLASS_STRIDE


def epsilon_at(index, episodes, start, end):
    if episodes <= 1:
        return start
    if start <= 0 or end <= 0:
        return end
    fraction = index / (episodes - 1)
    return start * math.pow(end / start, fraction)


def allowed_actions(state):
    health = (state % CLASS_STRIDE) // N_PATHS
    bins = (health // 9, (health // 3) % 3, health % 3)
    minimum = min(bins)
    return tuple(i for i, value in enumerate(bins) if value == minimum)


def report_coverage(qtable, out_root):
    if not qtable.exists():
        return
    rows = list(csv.DictReader(qtable.open(newline="")))
    visited = [row for row in rows if int(row["visits"]) > 0]
    emergency = [
        row for row in visited
        if int(row["state"]) // CLASS_STRIDE == 2
    ]
    emergency_ready = [row for row in emergency if int(row["visits"]) >= 20]
    safe_total_per_gateway = sum(
        len(allowed_actions(state)) for state in range(N_STATES))
    emergency_total_per_gateway = sum(
        len(allowed_actions(state))
        for state in range(2 * CLASS_STRIDE, 3 * CLASS_STRIDE))
    print(
        "Coverage: "
        f"visited safe state-actions={len(visited)}/{3 * safe_total_per_gateway}; "
        f"EMERGENCY visited={len(emergency)}/{3 * emergency_total_per_gateway}; "
        f"EMERGENCY visits>=20={len(emergency_ready)}/"
        f"{3 * emergency_total_per_gateway}"
    )

    observed = {0: set(), 1: set(), 2: set()}
    for path in sorted(out_root.glob("episode_*/rl_transitions.csv")):
        with path.open(newline="") as stream:
            for row in csv.DictReader(stream):
                cls = int(row["traffic_class_id"])
                observed[cls].add((int(row["gateway"]), int(row["state"])))

    class_names = {0: "NORMAL", 1: "IMPORTANT", 2: "EMERGENCY"}
    for cls in range(3):
        states = observed[cls]
        matching = [
            row for row in visited
            if int(row["state"]) // CLASS_STRIDE == cls
            and (int(row["gateway"]), int(row["state"])) in states
            and int(row["action"]) in allowed_actions(int(row["state"]))
        ]
        ready = [row for row in matching if int(row["visits"]) >= 20]
        possible = sum(len(allowed_actions(state)) for _, state in states)
        print(
            f"  {class_names[cls]:>9}: observed_states={len(states)}, "
            f"covered_actions={len(matching)}/{possible}, "
            f"visits>=20={len(ready)}/{possible}"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=None,
                        help="ns-3 root; defaults to parent of rl/")
    parser.add_argument("--episodes", type=int, default=50)
    parser.add_argument("--run-start", type=int, default=100)
    parser.add_argument("--scene-dur", type=float, default=60.0)
    parser.add_argument("--qtable", default="rl/outputs/qtable.csv")
    parser.add_argument("--out", default="output/rl_train")
    parser.add_argument("--epsilon-start", type=float, default=1.0)
    parser.add_argument("--epsilon-end", type=float, default=0.05)
    parser.add_argument("--alpha", type=float, default=0.10)
    parser.add_argument("--gamma", type=float, default=0.90)
    parser.add_argument("--decision-ms", type=float, default=100.0)
    parser.add_argument("--timeout-ms", type=float, default=1500.0)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.episodes < 1:
        raise SystemExit("--episodes must be positive")
    repo = (Path(args.repo) if args.repo else Path(__file__).resolve().parents[1])
    repo = repo.resolve()
    ns3 = repo / "ns3"
    if not ns3.exists():
        raise SystemExit(f"ns3 launcher not found: {ns3}")

    qtable = Path(args.qtable)
    if not qtable.is_absolute():
        qtable = repo / qtable
    qtable.parent.mkdir(parents=True, exist_ok=True)
    if qtable.exists() and not args.resume and not args.dry_run:
        raise SystemExit(
            f"Q-table already exists: {qtable}\n"
            "Use --resume to continue it, or choose a new --qtable path."
        )

    out_root = Path(args.out)
    if not out_root.is_absolute():
        out_root = repo / out_root
    out_root.mkdir(parents=True, exist_ok=True)

    for episode in range(args.episodes):
        run_id = args.run_start + episode
        epsilon = epsilon_at(
            episode, args.episodes, args.epsilon_start, args.epsilon_end)
        episode_dir = out_root / f"episode_{episode + 1:03d}_run{run_id}"
        simulation = (
            "scratch/scada/scada "
            f"--mode=dt --qosMode=private --rlMode=train "
            f"--rlQTable={qtable} --rlAlpha={args.alpha} "
            f"--rlGamma={args.gamma} --rlEpsilon={epsilon:.8f} "
            f"--rlDecisionMs={args.decision_ms} "
            f"--rlTimeoutMs={args.timeout_ms} "
            "--rlSafeMask=true "
            f"--sceneDur={args.scene_dur} --run={run_id} "
            f"--outDir={episode_dir}/ --stress=true --rlCongestion=true "
            "--anim=false --packetCsv=false --featureCsv=false "
            "--runtimeMlCsv=false "
            "--flowXml=false"
        )
        command = [str(ns3), "run", simulation]
        print(
            f"[{episode + 1:03d}/{args.episodes:03d}] run={run_id} "
            f"epsilon={epsilon:.4f}"
        )
        if args.dry_run:
            print(" ".join(command))
            continue
        subprocess.run(command, cwd=repo, check=True)

    print(f"\nQ-table: {qtable}")
    if not args.dry_run:
        report_coverage(qtable, out_root)
    print("Evaluate with rlMode=qtable and epsilon=0 on unseen run ids.")


if __name__ == "__main__":
    main()
