#!/usr/bin/env python3
"""Train per-protocol DT/RF models for the downstream dynamic-QoS objective.

The split is run-safe and explicit: base models fit on train runs, sigmoid
calibration fits on separate calibration runs, and all model/threshold choices
use validation runs.  Test runs are deliberately not accepted by this script.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).parent))
import train_and_export as trainlib


PROTOCOLS = ("DNP3", "IEC104", "OPC-UA")
STEMS = {"DNP3": "dnp3", "IEC104": "iec104", "OPC-UA": "opcua"}
DEPLOYED_TAU = {"DNP3": 0.01, "IEC104": 0.01, "OPC-UA": 0.21}
FEATURES = list(trainlib.FEATURES_BEHAVIOR20)


def parse_range(values: list[int]) -> list[int]:
    if len(values) != 2 or values[1] < values[0]:
        raise SystemExit("Run range must be START END")
    return list(range(values[0], values[1] + 1))


def load_runs(dataset: Path, runs: list[int], title: str) -> pd.DataFrame:
    frames = []
    for run in runs:
        path = dataset / f"run{run}" / "scada_runtime_ml.csv"
        if not path.is_file():
            raise SystemExit(f"Missing {title} run: {path}")
        frame = pd.read_csv(path)
        frame = frame[
            (frame["baseline_ready"] == 1)
            & (frame["message_kind"] != "PROTOCOL")
            & frame["protocol"].isin(PROTOCOLS)
        ].copy()
        frame["run_id"] = run
        frame["traffic_class"] = frame["true_traffic_class"].astype(str)
        frame["urgent"] = (frame["traffic_class"] != "NORMAL").astype(int)
        for feature in FEATURES:
            frame[feature] = pd.to_numeric(frame[feature], errors="coerce")
        frame[FEATURES] = frame[FEATURES].replace(
            [np.inf, -np.inf], np.nan).fillna(0.0)
        frames.append(frame)
    result = pd.concat(frames, ignore_index=True)
    print(f"{title}: {len(result)} rows, runs {runs[0]}-{runs[-1]}")
    return result


def hard_negative_sample(frame: pd.DataFrame, ratio: int, seed: int) -> pd.DataFrame:
    urgent = frame[frame["urgent"] == 1]
    normal = frame[frame["urgent"] == 0]
    budget = min(len(normal), max(ratio * len(urgent), 1))
    if budget == len(normal):
        return frame.sample(frac=1.0, random_state=seed)

    # Half the budget is reserved for NORMAL rows the deployed model finds
    # most urgent; the other half is a run-stratified random sample so ordinary
    # behavior is not forgotten.
    hard_budget = min(budget // 2, len(normal))
    hard = normal.nlargest(hard_budget, "urgent_probability")
    remainder = normal.drop(index=hard.index)
    random_budget = min(budget - len(hard), len(remainder))
    random = remainder.groupby("run_id", group_keys=False).apply(
        lambda group: group.sample(
            n=min(len(group), max(1, math.ceil(random_budget * len(group) / len(remainder)))),
            random_state=seed),
        include_groups=False,
    ) if random_budget else remainder.iloc[0:0]
    if len(random) > random_budget:
        random = random.sample(n=random_budget, random_state=seed)
    sampled = pd.concat([urgent, hard, random], ignore_index=True)
    return sampled.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def candidate_configs(family: str):
    if family == "dt":
        for depth in (3, 5, 8, 12):
            for leaf in (10, 30, 100):
                yield {"family": family, "depth": depth, "leaf": leaf,
                       "trees": 1, "max_features": None}
    else:
        for trees in (50, 100):
            for depth in (5, 8, 12):
                for leaf in (10, 30):
                    for max_features in ("sqrt", 0.5):
                        yield {"family": family, "depth": depth, "leaf": leaf,
                               "trees": trees, "max_features": max_features}


def make_model(config: dict):
    common = dict(
        max_depth=config["depth"], min_samples_leaf=config["leaf"],
        random_state=42,
    )
    if config["family"] == "dt":
        return DecisionTreeClassifier(class_weight="balanced", **common)
    return RandomForestClassifier(
        n_estimators=config["trees"], max_features=config["max_features"],
        class_weight="balanced_subsample", bootstrap=True, n_jobs=-1,
        **common,
    )


def urgent_probability(model, frame: pd.DataFrame) -> np.ndarray:
    index = list(model.classes_).index(1)
    return model.predict_proba(frame[FEATURES].to_numpy(dtype=np.float64))[:, index]


def logit(probability: np.ndarray) -> np.ndarray:
    clipped = np.clip(probability, 1e-6, 1 - 1e-6)
    return np.log(clipped / (1 - clipped)).reshape(-1, 1)


def sigmoid(value: np.ndarray) -> np.ndarray:
    value = np.clip(value, -60, 60)
    return 1 / (1 + np.exp(-value))


def fit_calibrator(probability: np.ndarray, truth: np.ndarray) -> tuple[float, float]:
    model = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000)
    model.fit(logit(probability), truth)
    return float(model.coef_[0, 0]), float(model.intercept_[0])


def calibrated(probability: np.ndarray, slope: float, intercept: float) -> np.ndarray:
    return sigmoid(slope * logit(probability).ravel() + intercept)


def raw_threshold(threshold: float, slope: float, intercept: float) -> float:
    if slope <= 0:
        return threshold
    target = math.log(threshold / (1 - threshold))
    return float(sigmoid(np.array([(target - intercept) / slope]))[0])


def metric_row(frame: pd.DataFrame, probability: np.ndarray,
               threshold: float, scene_duration: float) -> dict:
    predicted = probability >= threshold
    truth = frame["urgent"].to_numpy(dtype=bool)
    classes = frame["traffic_class"].to_numpy(dtype=str)
    e = classes == "EMERGENCY"
    i = classes == "IMPORTANT"
    normal = classes == "NORMAL"

    def recall(mask):
        return float(predicted[mask].mean()) if mask.any() else 0.0

    tp = int(np.sum(predicted & truth))
    positives = int(np.sum(predicted))
    precision = tp / positives if positives else 0.0
    seconds = frame["run_id"].nunique() * scene_duration * 3
    fp_kbps = float(frame.loc[predicted & normal, "current_pkt_size"].sum() * 8
                    / seconds / 1000)
    assigned_kbps = float(frame.loc[predicted, "current_pkt_size"].sum() * 8
                          / seconds / 1000)
    e_recall = recall(e)
    i_recall = recall(i)
    e_miss = 100 * (1 - e_recall)
    i_miss = 100 * (1 - i_recall)
    score = 3.0 * e_miss + 1.5 * i_miss + 2.0 * fp_kbps
    feasible = e_recall >= 0.95 and i_recall >= 0.95 and precision >= 0.40
    if not feasible:
        score += (max(0.0, 0.95 - e_recall) * 100 * 30
                  + max(0.0, 0.95 - i_recall) * 100 * 15
                  + max(0.0, 0.40 - precision) * 100 * 5)
    return {
        "threshold": threshold, "score": score, "feasible": feasible,
        "e_recall": e_recall, "i_recall": i_recall,
        "urgent_precision": precision, "fp_kbps": fp_kbps,
        "assigned_kbps": assigned_kbps,
    }


def select_protocol(family: str, protocol: str, train: pd.DataFrame,
                    calibration: pd.DataFrame, validation: pd.DataFrame,
                    args, rows: list[dict]):
    train_group = hard_negative_sample(
        train[train["protocol"] == protocol], args.normal_ratio, 42)
    cal_group = calibration[calibration["protocol"] == protocol]
    val_group = validation[validation["protocol"] == protocol]
    best = None
    for config in candidate_configs(family):
        model = make_model(config)
        model.fit(train_group[FEATURES].to_numpy(dtype=np.float64),
                  train_group["urgent"].to_numpy(dtype=int))
        cal_raw = urgent_probability(model, cal_group)
        val_raw = urgent_probability(model, val_group)
        slope, intercept = fit_calibrator(
            cal_raw, cal_group["urgent"].to_numpy(dtype=int))
        variants = (("raw", val_raw, 1.0, 0.0),
                    ("sigmoid", calibrated(val_raw, slope, intercept),
                     slope, intercept))
        for calibration_name, probability, a, b in variants:
            for threshold in np.arange(0.01, 1.0, 0.01):
                metric = metric_row(
                    val_group, probability, float(threshold),
                    args.scene_duration)
                entry = {
                    "family": family, "protocol": protocol,
                    **config, "calibration": calibration_name,
                    "calibration_slope": a, "calibration_intercept": b,
                    **metric,
                }
                entry["raw_threshold"] = (
                    raw_threshold(float(threshold), a, b)
                    if calibration_name == "sigmoid" else float(threshold))
                rows.append(entry)
                key = (not entry["feasible"], entry["score"],
                       config["trees"] * config["depth"], config["leaf"])
                if best is None or key < best[0]:
                    best = (key, entry)
    choice = best[1]
    print(
        f"{family.upper():2s} {protocol:7s}: depth={choice['depth']} "
        f"trees={choice['trees']} leaf={choice['leaf']} "
        f"maxfeat={choice['max_features']} cal={choice['calibration']} "
        f"tau(raw)={choice['raw_threshold']:.4f} "
        f"Erec={choice['e_recall']:.4f} Irec={choice['i_recall']:.4f} "
        f"prec={choice['urgent_precision']:.4f} FP={choice['fp_kbps']:.3f}kbps")
    return choice


def export_selected(selected: dict, train: pd.DataFrame,
                    calibration: pd.DataFrame, validation: pd.DataFrame,
                    out_dir: Path, normal_ratio: int,
                    refit_validation: bool):
    manifest = {
        "feature_names": FEATURES,
        "training_policy": {
            "hard_negative_normal_ratio": normal_ratio,
            "refit_validation": refit_validation,
            "calibration_runs_are_never_used_to_fit_the_base_model": True,
        },
        "models": {"dt": {}, "rf": {}},
    }
    config_lines = ["#pragma once", "", "// AUTO-GENERATED by ml/train_qos_aware.py.",
                    "namespace scada_binary_config {"]
    for family in ("dt", "rf"):
        for protocol in PROTOCOLS:
            choice = selected[(family, protocol)]
            # Keep calibration runs independent for the probability mapping;
            # the base learner is refit on train + validation only.
            fit = (pd.concat([train, validation], ignore_index=True)
                   if refit_validation else train)
            fit = hard_negative_sample(
                fit[fit["protocol"] == protocol], normal_ratio, 84)
            model = make_model(choice)
            model.fit(fit[FEATURES].to_numpy(dtype=np.float64),
                      fit["urgent"].to_numpy(dtype=int))
            stem = STEMS[protocol]
            function = f"score_binary_{family}_{stem}"
            header = out_dir / f"scada_binary_{family}_{stem}.h"
            trainlib.export_model(model, function, header, 2)
            if family == "rf":
                code = header.read_text(encoding="utf-8")
                code = code.replace("add_vectors", f"add_vectors_{function}")
                code = code.replace(
                    "mul_vector_number", f"mul_vector_number_{function}")
                header.write_text(code, encoding="utf-8")
            urgent_index = list(model.classes_).index(1)
            threshold = float(choice["raw_threshold"])
            prefix = f"{family.upper()}_{stem.upper()}"
            config_lines.append(
                f"inline constexpr int {prefix}_URGENT_INDEX = {urgent_index};")
            config_lines.append(
                f"inline constexpr double {prefix}_THRESHOLD = {threshold:.17g};")
            manifest["models"][family][protocol] = {
                "function": function, "urgent_index": urgent_index,
                "threshold": threshold, "depth": int(choice["depth"]),
                "trees": int(choice["trees"]), "leaf": int(choice["leaf"]),
                "max_features": choice["max_features"],
                "selected_calibration": choice["calibration"],
                "validation_threshold": float(choice["threshold"]),
                "calibration_slope": float(choice["calibration_slope"]),
                "calibration_intercept": float(choice["calibration_intercept"]),
            }
    config_lines.extend(["}", ""])
    (out_dir / "scada_binary_config.h").write_text(
        "\n".join(config_lines), encoding="utf-8")
    feature_lines = [
        "#pragma once", "", "// AUTO-GENERATED by ml/train_qos_aware.py.",
        "#include <string_view>", "", "namespace scada_binary_config {",
        f"inline constexpr int TRAINED_N_FEATURES = {len(FEATURES)};",
        "inline constexpr std::string_view TRAINED_FEATURE_NAMES[TRAINED_N_FEATURES] = {",
        *[f'    "{name}",' for name in FEATURES], "};", "}", "",
    ]
    (out_dir / "scada_binary_features.h").write_text(
        "\n".join(feature_lines), encoding="utf-8")
    (out_dir / "scada_binary_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")


def print_baseline(validation: pd.DataFrame, scene_duration: float):
    print("\nDEPLOYED RF THRESHOLD BASELINE ON VALIDATION FEATURES")
    for protocol in PROTOCOLS:
        group = validation[validation["protocol"] == protocol]
        metric = metric_row(
            group, group["urgent_probability"].to_numpy(dtype=float),
            DEPLOYED_TAU[protocol], scene_duration)
        print(
            f"RF {protocol:7s}: tau={DEPLOYED_TAU[protocol]:.2f} "
            f"Erec={metric['e_recall']:.4f} Irec={metric['i_recall']:.4f} "
            f"prec={metric['urgent_precision']:.4f} "
            f"FP={metric['fp_kbps']:.3f}kbps")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--train-runs", nargs=2, type=int, default=[60, 79])
    parser.add_argument("--calibration-runs", nargs=2, type=int, default=[80, 84])
    parser.add_argument("--validation-runs", nargs=2, type=int, default=[85, 89])
    parser.add_argument("--normal-ratio", type=int, default=12)
    parser.add_argument("--scene-duration", type=float, default=40.0)
    parser.add_argument(
        "--refit-validation", action="store_true",
        help="Refit locked base models on train+validation before final test")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)

    train = load_runs(args.dataset, parse_range(args.train_runs), "train")
    calibration = load_runs(
        args.dataset, parse_range(args.calibration_runs), "calibration")
    validation = load_runs(
        args.dataset, parse_range(args.validation_runs), "validation")
    print_baseline(validation, args.scene_duration)

    rows = []
    selected = {}
    for family in ("dt", "rf"):
        for protocol in PROTOCOLS:
            selected[(family, protocol)] = select_protocol(
                family, protocol, train, calibration, validation, args, rows)
    pd.DataFrame(rows).to_csv(args.out / "candidate_sweep.csv", index=False)
    export_selected(
        selected, train, calibration, validation, args.out, args.normal_ratio,
        args.refit_validation)
    selection = {
        f"{family}/{protocol}": choice
        for (family, protocol), choice in selected.items()
    }
    (args.out / "selection.json").write_text(
        json.dumps(selection, indent=2), encoding="utf-8")
    print(f"\nExported locked candidates to {args.out}")
    print("Test runs were not read.")


if __name__ == "__main__":
    main()
