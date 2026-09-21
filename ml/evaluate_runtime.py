#!/usr/bin/env python3
"""Evaluate the deployed C++ DT/RF service classifier runtime CSV."""

import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


CLASSES = ["TIME_CRITICAL", "OPERATIONAL", "MONITORING"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    frame = pd.read_csv(args.csv)
    required = {"pred_service_class", "true_service_class", "evaluated",
                "protocol"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise SystemExit(f"Runtime CSV has an old schema; missing {missing}")
    frame = frame[(frame.evaluated == 1)
                  & frame.true_service_class.isin(CLASSES)].copy()
    if frame.empty:
        raise SystemExit(
            "Runtime CSV contains no evaluated service-class rows. "
            "Run a longer scenario or inspect the CSV schema/filter flags.")
    truth = frame.true_service_class.astype(str)
    prediction = frame.pred_service_class.astype(str)

    print("SERVICE-CLASS RUNTIME RESULTS")
    print(classification_report(
        truth, prediction, labels=CLASSES, digits=4, zero_division=0))
    matrix = confusion_matrix(truth, prediction, labels=CLASSES)
    print(pd.DataFrame(matrix, index=CLASSES, columns=CLASSES))

    rows = []
    for protocol, group in frame.groupby("protocol"):
        report = classification_report(
            group.true_service_class, group.pred_service_class,
            labels=CLASSES, output_dict=True, zero_division=0)
        for service_class in CLASSES:
            values = report[service_class]
            rows.append({
                "protocol": protocol, "service_class": service_class,
                "precision": values["precision"],
                "recall": values["recall"],
                "f1": values["f1-score"],
                "support": int(values["support"]),
            })
    details = pd.DataFrame(rows)
    print("\nBY PROTOCOL")
    print(details.to_string(index=False))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        details.to_csv(args.out / "runtime_metrics_by_protocol.csv", index=False)
        pd.DataFrame(matrix, index=CLASSES, columns=CLASSES).to_csv(
            args.out / "runtime_confusion_matrix.csv")


if __name__ == "__main__":
    main()
