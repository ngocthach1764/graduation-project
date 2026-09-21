#!/usr/bin/env python3
"""Train one pooled DT and RF to classify QoS service requirements.

Each row represents the observable state of one device flow in a causal
one-second sliding window.  Protocol identity is an input feature.  The target
is never the protocol or exact message meaning; it is one of:
TIME_CRITICAL, OPERATIONAL, MONITORING.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.tree import DecisionTreeClassifier

try:
    import m2cgen as m2c
except ImportError as exc:
    raise SystemExit("m2cgen is required: pip install m2cgen") from exc

FEATURES = [
    "pkt_count_1s", "current_pkt_size", "avg_pkt_size", "max_pkt_size",
    "pkt_size_std", "pkt_size_entropy", "inter_arrival_mean",
    "inter_arrival_min", "inter_arrival_std",
    "current_size_baseline_ratio", "time_since_last_pkt",
    "silent_gap_ratio", "pkt_rate_delta", "current_size_zscore",
    "burst_count_100ms", "burst_count_500ms", "short_long_rate_ratio",
    "baseline_pkt_rate_zscore", "baseline_size_zscore",
    "uplink_downlink_ratio", "protocol_id",
]
CLASSES = ["TIME_CRITICAL", "OPERATIONAL", "MONITORING"]
PROTOCOL_IDS = {"Modbus": 1, "DNP3": 2, "IEC104": 3, "OPC-UA": 4}
LEGACY = {
    "EMERGENCY": "TIME_CRITICAL",
    "IMPORTANT": "OPERATIONAL",
    "NORMAL": "MONITORING",
}


def load_group(paths: list[str], run_offset: int, title: str) -> pd.DataFrame:
    frames = []
    for index, raw_path in enumerate(paths):
        path = Path(raw_path).expanduser().resolve()
        frame = pd.read_csv(path)
        if "service_class" not in frame and "traffic_class" in frame:
            frame["service_class"] = frame["traffic_class"].astype(str).replace(LEGACY)
        required = set(FEATURES + ["service_class", "protocol"])
        missing = sorted(required - set(frame.columns))
        if missing:
            raise SystemExit(f"{path}: missing columns {missing}")
        if "train_usable" in frame:
            frame = frame[frame["train_usable"] == 1]
        if "message_kind" in frame:
            frame = frame[frame["message_kind"].isin(["TELEMETRY", "EVENT"])]
        frame = frame[frame["service_class"].isin(CLASSES)].copy()
        frame["run_id"] = run_offset + index
        frames.append(frame)
        print(f"  {title:10s} {path}: {len(frame):,} rows")
    result = pd.concat(frames, ignore_index=True)
    result[FEATURES] = result[FEATURES].replace(
        [np.inf, -np.inf], np.nan).fillna(0.0)
    return result


def balance_training(frame: pd.DataFrame, normal_ratio: int) -> pd.DataFrame:
    minority = frame[frame.service_class != "MONITORING"]
    monitoring = frame[frame.service_class == "MONITORING"]
    cap = min(len(monitoring), normal_ratio * max(len(minority), 1))
    monitoring = monitoring.sample(n=cap, random_state=42) if cap < len(monitoring) else monitoring
    return pd.concat([minority, monitoring], ignore_index=True).sample(
        frac=1.0, random_state=42).reset_index(drop=True)


def candidates(family: str):
    if family == "dt":
        grid = ((depth, leaf, 1)
                for depth in (12, 16, 20)
                for leaf in (5, 10, 30))
    else:
        # Priority windows are rare.  The original depth<=12/leaf>=10 grid
        # underfit their short-lived boundaries, so RF gets more trees and
        # smaller leaves while remaining bounded for C++ export size.
        grid = ((depth, leaf, 100)
                for depth in (12, 16, 20)
                for leaf in (2, 5, 10))
    for depth, leaf, trees in grid:
        if family == "dt":
            yield DecisionTreeClassifier(
                max_depth=depth, min_samples_leaf=leaf,
                class_weight="balanced", random_state=42), {
                    "depth": depth, "leaf": leaf, "trees": 1}
        else:
            yield RandomForestClassifier(
                n_estimators=trees, max_depth=depth, min_samples_leaf=leaf,
                max_features="sqrt", class_weight="balanced_subsample",
                n_jobs=-1, random_state=42), {
                    "depth": depth, "leaf": leaf, "trees": trees}


def threshold_prediction(model, frame: pd.DataFrame,
                         time_threshold: float,
                         operational_threshold: float) -> np.ndarray:
    probability = model.predict_proba(
        frame[FEATURES].to_numpy(dtype=np.float64))
    indices = {name: list(model.classes_).index(name) for name in CLASSES}
    return threshold_prediction_from_probability(
        probability[:, indices["TIME_CRITICAL"]],
        probability[:, indices["OPERATIONAL"]],
        time_threshold, operational_threshold)


def threshold_prediction_from_probability(
        p_time: np.ndarray, p_operational: np.ndarray,
        time_threshold: float,
        operational_threshold: float) -> np.ndarray:
    prediction = np.full(len(p_time), "MONITORING", dtype=object)
    time_pass = p_time >= time_threshold
    operational_pass = p_operational >= operational_threshold
    # If both pass, select the class with the greater normalized confidence.
    choose_time = time_pass & (~operational_pass | (
        p_time / time_threshold >= p_operational / operational_threshold))
    choose_operational = operational_pass & ~choose_time
    prediction[choose_time] = "TIME_CRITICAL"
    prediction[choose_operational] = "OPERATIONAL"
    return prediction


def compact_metrics(truth: np.ndarray, prediction: np.ndarray) -> dict:
    result = {}
    f1_values = []
    for service_class in CLASSES:
        actual = truth == service_class
        predicted = prediction == service_class
        tp = int(np.sum(actual & predicted))
        precision = tp / max(int(np.sum(predicted)), 1)
        recall = tp / max(int(np.sum(actual)), 1)
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        result[service_class] = {
            "precision": precision, "recall": recall, "f1-score": f1,
        }
        f1_values.append(f1)
    result["macro_f1"] = float(np.mean(f1_values))
    return result


def metrics_from_confusion(matrix: np.ndarray) -> dict:
    result = {}
    f1_values = []
    for index, service_class in enumerate(CLASSES):
        tp = int(matrix[index, index])
        precision = tp / max(int(matrix[:, index].sum()), 1)
        recall = tp / max(int(matrix[index, :].sum()), 1)
        f1 = (2 * precision * recall / (precision + recall)
              if precision + recall else 0.0)
        result[service_class] = {
            "precision": precision, "recall": recall, "f1-score": f1,
        }
        f1_values.append(f1)
    result["macro_f1"] = float(np.mean(f1_values))
    return result


def tune_thresholds(model, validation: pd.DataFrame,
                    min_precision: float, min_recall: float) -> tuple[dict, dict]:
    truth = validation.service_class.to_numpy(dtype=str)
    class_index = {name: index for index, name in enumerate(CLASSES)}
    truth_index = np.fromiter(
        (class_index[value] for value in truth), dtype=np.int8, count=len(truth))
    probability = model.predict_proba(
        validation[FEATURES].to_numpy(dtype=np.float64))
    indices = {name: list(model.classes_).index(name) for name in CLASSES}
    p_time = probability[:, indices["TIME_CRITICAL"]]
    p_operational = probability[:, indices["OPERATIONAL"]]
    best = None
    values = np.arange(0.05, 0.951, 0.05)
    for time_threshold in values:
        for operational_threshold in values:
            time_pass = p_time >= time_threshold
            operational_pass = p_operational >= operational_threshold
            choose_time = time_pass & (~operational_pass | (
                p_time / time_threshold >=
                p_operational / operational_threshold))
            choose_operational = operational_pass & ~choose_time
            prediction_index = np.full(len(truth), 2, dtype=np.int8)
            prediction_index[choose_time] = 0
            prediction_index[choose_operational] = 1
            matrix = np.bincount(
                truth_index * len(CLASSES) + prediction_index,
                minlength=len(CLASSES) ** 2).reshape(
                    len(CLASSES), len(CLASSES))
            report = metrics_from_confusion(matrix)
            macro = report["macro_f1"]
            tc = report["TIME_CRITICAL"]
            op = report["OPERATIONAL"]
            feasible = (tc["precision"] >= min_precision
                        and op["precision"] >= min_precision
                        and tc["recall"] >= min_recall
                        and op["recall"] >= min_recall)
            shortfall = (
                max(0.0, min_precision - tc["precision"])
                + max(0.0, min_precision - op["precision"])
                + max(0.0, min_recall - tc["recall"])
                + max(0.0, min_recall - op["recall"]))
            key = (feasible, -shortfall, macro,
                   tc["precision"] + op["precision"])
            if best is None or key > best[0]:
                best = (key, {
                    "time_critical": float(time_threshold),
                    "operational": float(operational_threshold),
                }, report)
    return best[1], best[2]


def metric_key(report: dict, min_precision: float,
               min_recall: float) -> tuple:
    """Rank a configuration by the two deployable priority-class contracts."""
    tc = report["TIME_CRITICAL"]
    op = report["OPERATIONAL"]
    feasible = (tc["precision"] >= min_precision
                and op["precision"] >= min_precision
                and tc["recall"] >= min_recall
                and op["recall"] >= min_recall)
    shortfall = (max(0.0, min_precision - tc["precision"])
                 + max(0.0, min_precision - op["precision"])
                 + max(0.0, min_recall - tc["recall"])
                 + max(0.0, min_recall - op["recall"]))
    return (feasible, -shortfall, report["macro_f1"],
            tc["precision"] + op["precision"])


def tune_protocol_thresholds(model, validation: pd.DataFrame,
                             min_precision: float,
                             min_recall: float) -> dict:
    """Tune per-protocol thresholds against the global service contract.

    A threshold pair is still allowed for each protocol because their traffic
    distributions differ.  Selection, however, is based on aggregate
    TIME_CRITICAL/OPERATIONAL metrics.  Optimizing every protocol in isolation
    can reject a useful precision/recall trade-off and does not represent the
    end-to-end classifier contract reported by the experiment.
    """
    protocols = sorted(validation.protocol.astype(str).unique())
    truth = validation.service_class.to_numpy(dtype=str)
    protocol_values = validation.protocol.astype(str).to_numpy()
    probability = model.predict_proba(
        validation[FEATURES].to_numpy(dtype=np.float64))
    indices = {name: list(model.classes_).index(name) for name in CLASSES}
    p_time = probability[:, indices["TIME_CRITICAL"]]
    p_operational = probability[:, indices["OPERATIONAL"]]
    values = np.arange(0.05, 0.951, 0.05)

    thresholds = {}
    for protocol in protocols:
        group = validation[validation.protocol.astype(str) == protocol]
        if int(np.sum(group.service_class != "MONITORING")) == 0:
            thresholds[protocol] = {
                "time_critical": 0.95, "operational": 0.95}
        else:
            thresholds[protocol], _ = tune_thresholds(
                model, group, min_precision, min_recall)

    class_index = {name: index for index, name in enumerate(CLASSES)}
    candidate_counts = {}
    for protocol in protocols:
        mask = protocol_values == protocol
        protocol_truth = truth[mask]
        protocol_truth_index = np.fromiter(
            (class_index[value] for value in protocol_truth),
            dtype=np.int8, count=len(protocol_truth))
        protocol_p_time = p_time[mask]
        protocol_p_operational = p_operational[mask]
        counts = {}
        for time_threshold in values:
            for operational_threshold in values:
                choice = (round(float(time_threshold), 10),
                          round(float(operational_threshold), 10))
                time_pass = protocol_p_time >= time_threshold
                operational_pass = (
                    protocol_p_operational >= operational_threshold)
                choose_time = time_pass & (~operational_pass | (
                    protocol_p_time / time_threshold >=
                    protocol_p_operational / operational_threshold))
                choose_operational = operational_pass & ~choose_time
                prediction_index = np.full(
                    len(protocol_truth), 2, dtype=np.int8)
                prediction_index[choose_time] = 0
                prediction_index[choose_operational] = 1
                matrix = np.bincount(
                    protocol_truth_index * len(CLASSES) + prediction_index,
                    minlength=len(CLASSES) ** 2).reshape(
                        len(CLASSES), len(CLASSES))
                counts[choice] = matrix
        candidate_counts[protocol] = counts

    def choice_tuple(protocol: str) -> tuple[float, float]:
        choice = thresholds[protocol]
        return (round(choice["time_critical"], 10),
                round(choice["operational"], 10))

    total = sum((candidate_counts[protocol][choice_tuple(protocol)]
                 for protocol in protocols),
                start=np.zeros((len(CLASSES), len(CLASSES)), dtype=np.int64))

    # Coordinate descent operates on 3x3 confusion counts rather than copying
    # every validation row for every candidate threshold pair.
    for _ in range(4):
        changed = False
        for protocol in protocols:
            mask = protocol_values == protocol
            if not np.any((truth != "MONITORING") & mask):
                continue
            old_tuple = choice_tuple(protocol)
            base_counts = total - candidate_counts[protocol][old_tuple]
            best_choice = thresholds[protocol]
            best_key = metric_key(
                metrics_from_confusion(total),
                min_precision, min_recall)
            best_tuple = old_tuple
            for candidate_tuple, counts in candidate_counts[protocol].items():
                report = metrics_from_confusion(base_counts + counts)
                key = metric_key(report, min_precision, min_recall)
                if key > best_key:
                    best_key = key
                    best_tuple = candidate_tuple
                    best_choice = {
                        "time_critical": candidate_tuple[0],
                        "operational": candidate_tuple[1],
                    }
            if best_choice != thresholds[protocol]:
                thresholds[protocol] = best_choice
                total = base_counts + candidate_counts[protocol][best_tuple]
                changed = True
        if not changed:
            break
    return thresholds


def protocol_threshold_prediction(model, frame: pd.DataFrame,
                                  thresholds: dict) -> np.ndarray:
    prediction = np.full(len(frame), "MONITORING", dtype=object)
    protocols = frame.protocol.astype(str).to_numpy()
    for protocol in sorted(set(protocols)):
        mask = protocols == protocol
        group = frame.loc[mask]
        choice = thresholds.get(
            protocol, {"time_critical": 0.95, "operational": 0.95})
        prediction[mask] = threshold_prediction(
            model, group, choice["time_critical"], choice["operational"])
    return prediction


def select_model(family: str, train: pd.DataFrame,
                 validation: pd.DataFrame, min_precision: float,
                 min_recall: float):
    best = None
    x_train = train[FEATURES].to_numpy(dtype=np.float64)
    y_train = train.service_class.to_numpy(dtype=str)
    x_val = validation[FEATURES].to_numpy(dtype=np.float64)
    y_val = validation.service_class.to_numpy(dtype=str)
    for model, config in candidates(family):
        model.fit(x_train, y_train)
        thresholds = tune_protocol_thresholds(
            model, validation, min_precision, min_recall)
        prediction = protocol_threshold_prediction(
            model, validation, thresholds)
        report = compact_metrics(y_val, prediction)
        macro = f1_score(y_val, prediction, labels=CLASSES,
                         average="macro", zero_division=0)
        tc, op = report["TIME_CRITICAL"], report["OPERATIONAL"]
        feasible = (tc["precision"] >= min_precision
                    and op["precision"] >= min_precision
                    and tc["recall"] >= min_recall
                    and op["recall"] >= min_recall)
        shortfall = (max(0.0, min_precision - tc["precision"])
                     + max(0.0, min_precision - op["precision"])
                     + max(0.0, min_recall - tc["recall"])
                     + max(0.0, min_recall - op["recall"]))
        config = {**config, "thresholds": thresholds,
                  "validation_macro_f1": macro,
                  "validation_feasible": feasible}
        key = (feasible, -shortfall, macro,
               -config["depth"], -config["leaf"])
        if best is None or key > best[0]:
            best = (key, config)
    print(f"Selected {family.upper()}: {best[1]}")
    return best[1]


def make_model(family: str, config: dict):
    if family == "dt":
        return DecisionTreeClassifier(
            max_depth=config["depth"], min_samples_leaf=config["leaf"],
            class_weight="balanced", random_state=42)
    return RandomForestClassifier(
        n_estimators=config["trees"], max_depth=config["depth"],
        min_samples_leaf=config["leaf"], max_features="sqrt",
        class_weight="balanced_subsample", n_jobs=-1, random_state=42)


def evaluate_thresholded(family: str, model, test: pd.DataFrame,
                         out_dir: Path, thresholds: dict):
    truth = test.service_class.to_numpy(dtype=str)
    prediction = protocol_threshold_prediction(model, test, thresholds)
    print(f"\n{family.upper()} held-out test")
    print(classification_report(
        truth, prediction, labels=CLASSES, digits=4, zero_division=0))
    matrix = confusion_matrix(truth, prediction, labels=CLASSES)
    pd.DataFrame(matrix, index=CLASSES, columns=CLASSES).to_csv(
        out_dir / f"{family}_confusion_matrix.csv")
    rows = []
    for protocol, group in test.assign(prediction=prediction).groupby("protocol"):
        report = classification_report(
            group.service_class, group.prediction, labels=CLASSES,
            output_dict=True, zero_division=0)
        for service_class in CLASSES:
            row = report[service_class]
            rows.append({
                "model": family, "protocol": protocol,
                "service_class": service_class,
                "precision": row["precision"], "recall": row["recall"],
                "f1": row["f1-score"], "support": int(row["support"]),
            })
    pd.DataFrame(rows).to_csv(
        out_dir / f"{family}_metrics_by_protocol.csv", index=False)
    return classification_report(
        truth, prediction, labels=CLASSES, output_dict=True, zero_division=0)


def export_model(model, function: str, path: Path, n_classes: int) -> None:
    """Export a sklearn tree ensemble as a C++-compatible header."""
    code = m2c.export_to_c(model, function_name=function)

    def replace_compound_literal(match: re.Match) -> str:
        variable = match.group(1)
        values = [value.strip() for value in match.group(2).split(",")]
        return "; ".join(
            f"{variable}[{index}] = {value}"
            for index, value in enumerate(values)) + ";"

    code = re.sub(
        r"memcpy\((\w+), \(double\[\]\)\{([^}]+)\}, "
        r"\d+ \* sizeof\(double\)\);",
        replace_compound_literal,
        code,
    )
    guard = f"SCADA_MODEL_{function.upper().replace('SCORE_', '')}_TRAINED"
    header = (
        "// AUTO-GENERATED by ml/train_service_classifier.py.\n"
        f"// {function}(double* input, double* output): "
        f"{len(FEATURES)} features -> {n_classes} service scores.\n"
        "#pragma once\n\n"
        f"#define {guard}\n\n"
    )
    path.write_text(header + code + "\n", encoding="utf-8")
    print(f"  -> {path.name} ({path.stat().st_size / 1024:.1f} KiB)")


def export_models(models: dict, out_dir: Path, configs: dict):
    for family, model in models.items():
        path = out_dir / f"scada_service_{family}.h"
        function = f"score_service_{family}"
        export_model(model, function, path, len(CLASSES))
        if family == "rf":
            code = path.read_text(encoding="utf-8")
            code = code.replace("add_vectors", f"add_vectors_{function}")
            code = code.replace("mul_vector_number", f"mul_vector_number_{function}")
            path.write_text(code, encoding="utf-8")

    classes = list(models["rf"].classes_)
    def threshold_array(family: str, service: str) -> str:
        values = [0.95] * 5
        for protocol, protocol_id in PROTOCOL_IDS.items():
            values[protocol_id] = configs[family]["thresholds"].get(
                protocol, {}).get(service, 0.95)
        return "{" + ", ".join(f"{value:.17g}" for value in values) + "}"

    config = [
        "#pragma once", "", "// AUTO-GENERATED by ml/train_service_classifier.py.",
        "namespace scada_service_config {",
        f"inline constexpr int TIME_CRITICAL_INDEX = {classes.index('TIME_CRITICAL')};",
        f"inline constexpr int OPERATIONAL_INDEX = {classes.index('OPERATIONAL')};",
        f"inline constexpr int MONITORING_INDEX = {classes.index('MONITORING')};",
        "inline constexpr int N_PROTOCOL_IDS = 5;",
        f"inline constexpr double DT_TIME_CRITICAL_THRESHOLD[N_PROTOCOL_IDS] = {threshold_array('dt', 'time_critical')};",
        f"inline constexpr double DT_OPERATIONAL_THRESHOLD[N_PROTOCOL_IDS] = {threshold_array('dt', 'operational')};",
        f"inline constexpr double RF_TIME_CRITICAL_THRESHOLD[N_PROTOCOL_IDS] = {threshold_array('rf', 'time_critical')};",
        f"inline constexpr double RF_OPERATIONAL_THRESHOLD[N_PROTOCOL_IDS] = {threshold_array('rf', 'operational')};",
        "}", "",
    ]
    (out_dir / "scada_service_config.h").write_text(
        "\n".join(config), encoding="utf-8")

    feature_header = [
        "#pragma once", "", "// AUTO-GENERATED by ml/train_service_classifier.py.",
        "#include <string_view>", "", "namespace scada_service_config {",
        f"inline constexpr int TRAINED_N_FEATURES = {len(FEATURES)};",
        "inline constexpr std::string_view TRAINED_FEATURE_NAMES[TRAINED_N_FEATURES] = {",
        *[f'    "{name}",' for name in FEATURES], "};", "}", "",
    ]
    (out_dir / "scada_service_features.h").write_text(
        "\n".join(feature_header), encoding="utf-8")
    manifest = {
        "target": "service_class", "classes": CLASSES,
        "features": FEATURES, "models": configs,
        "mapping": {
            "TIME_CRITICAL": "EF", "OPERATIONAL": "AF31",
            "MONITORING": "BE",
        },
    }
    (out_dir / "scada_service_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv-train", nargs="+", required=True)
    parser.add_argument("--csv-validation", nargs="+", required=True)
    parser.add_argument("--csv-test", nargs="+", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--normal-ratio", type=int, default=12)
    parser.add_argument("--min-priority-precision", type=float, default=0.80)
    parser.add_argument("--min-priority-recall", type=float, default=0.96)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    train = load_group(args.csv_train, 1, "train")
    validation = load_group(args.csv_validation, 100, "validation")
    test = load_group(args.csv_test, 200, "test")
    train_balanced = balance_training(train, args.normal_ratio)

    configs = {}
    models = {}
    reports = {}
    for family in ("dt", "rf"):
        configs[family] = select_model(
            family, train_balanced, validation,
            args.min_priority_precision, args.min_priority_recall)
        models[family] = make_model(family, configs[family])
        models[family].fit(
            train_balanced[FEATURES].to_numpy(dtype=np.float64),
            train_balanced.service_class.to_numpy(dtype=str))
        reports[family] = evaluate_thresholded(
            family, models[family], test, args.out,
            configs[family]["thresholds"])
    export_models(models, args.out, configs)
    (args.out / "service_test_summary.json").write_text(
        json.dumps(reports, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
