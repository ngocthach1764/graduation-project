#!/usr/bin/env python3
"""Tune the binary ML stage for the ML+semantic-rule architecture.

ML predicts NORMAL versus URGENT from behavior-only features. Protocol
semantics are deliberately excluded from this model and are used later by a
deterministic gateway rule to split URGENT into IMPORTANT or EMERGENCY.
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)

import tune_hierarchical as hier
import train_and_export as trainlib


BINARY_CLASSES = ['URGENT', 'NORMAL']


def binary_truth(df):
    labels = df[trainlib.TARGET].astype(str).to_numpy()
    return np.where(labels == 'NORMAL', 'NORMAL', 'URGENT')


def tune_binary_threshold(train_df, validation_df, model_config, thresholds,
                          min_urgent_recall, prefix, out_dir, cv_folds=0,
                          min_urgent_precision=0.80):
    if cv_folds > 0:
        # Quet nguong tren xac suat out-of-fold: moi mau duoc cho diem boi mo
        # hinh khong nhin thay lan chay cua no, nen khong thien vi lac quan.
        pooled = pd.concat([train_df, validation_df], ignore_index=True)
        folds = hier.run_folds(pooled, cv_folds)
        probability = hier.oof_probability(pooled, 1, model_config, folds,
                                           'URGENT')
        truth = binary_truth(pooled)
    else:
        model = hier.fit_stage(train_df, 1, model_config)
        probability = hier.class_probability(
            model, hier.feature_matrix(validation_df), 'URGENT')
        truth = binary_truth(validation_df)
    rows = []
    for threshold in thresholds:
        prediction = np.where(probability >= threshold, 'URGENT', 'NORMAL')
        rows.append({
            'urgent_threshold': float(threshold),
            'f1_macro': float(f1_score(
                truth, prediction, labels=BINARY_CLASSES,
                average='macro', zero_division=0)),
            'f1_urgent': float(f1_score(
                truth, prediction, labels=['URGENT'],
                average='macro', zero_division=0)),
            'urgent_recall': float(recall_score(
                truth, prediction, labels=['URGENT'],
                average='macro', zero_division=0)),
            'urgent_precision': float(precision_score(
                truth, prediction, labels=['URGENT'],
                average='macro', zero_division=0)),
            'normal_recall': float(recall_score(
                truth, prediction, labels=['NORMAL'],
                average='macro', zero_division=0)),
        })

    sweep = pd.DataFrame(rows)
    sweep.to_csv(out_dir / f'{prefix}_binary_threshold_sweep.csv', index=False)
    eligible = sweep[sweep['urgent_recall'] >= min_urgent_recall]
    feasible = not eligible.empty
    if feasible:
        # Rang buoc bao phu da thoa: trong so cac diem lam viec dat yeu cau,
        # chon diem co chat luong tong the tot nhat.
        order = ['f1_macro', 'f1_urgent', 'normal_recall', 'urgent_threshold']
    else:
        # Rang buoc BAT KHA THI.  Uu tien da tuyen bo cua he thong la khong bo
        # sot ban tin khan cap, nen chon diem co bao phu CAO NHAT.  Nhung cuc
        # dai recall khong kem dieu kien se day nguong xuong toi muc bao dong
        # gia tran ngap, nen phai giu mot SAN PRECISION: canh bao chi con gia
        # tri van hanh khi phan lon canh bao la that.
        with_floor = sweep[sweep['urgent_precision'] >= min_urgent_precision]
        floor_met = not with_floor.empty
        eligible = with_floor if floor_met else sweep
        order = ['urgent_recall', 'f1_macro', 'f1_urgent', 'urgent_threshold']
        note = (f"san precision >= {min_urgent_precision:.2f}" if floor_met
                else "KHONG diem nao dat san precision, chon recall cao nhat")
        print(f"  {prefix}: khong nguong nao dat Recall URGENT >= "
              f"{min_urgent_recall:.2f}; {note}")
    choice = eligible.sort_values(
        order, ascending=[False] * len(order)).iloc[0]
    result = {
        'urgent_threshold': float(choice['urgent_threshold']),
        'validation_f1_macro': float(choice['f1_macro']),
        'validation_f1_urgent': float(choice['f1_urgent']),
        'validation_urgent_recall': float(choice['urgent_recall']),
        'validation_urgent_precision': float(choice['urgent_precision']),
        'recall_constraint_met': bool(feasible),
        'precision_floor': float(min_urgent_precision),
    }
    print(f"  {prefix:>22} threshold={result['urgent_threshold']:.2f}, "
          f"macro-F1={result['validation_f1_macro']:.4f}, "
          f"F1_URGENT={result['validation_f1_urgent']:.4f}, "
          f"recall_URGENT={result['validation_urgent_recall']:.4f}")
    return result


def tune_scope(train_df, validation_df, scope, family, args, out_dir):
    if scope == 'pooled':
        groups = {'ALL': (train_df, validation_df)}
    else:
        protocols = sorted(set(train_df['protocol']) &
                           set(validation_df['protocol']))
        groups = {
            str(protocol): (
                train_df[train_df['protocol'] == protocol],
                validation_df[validation_df['protocol'] == protocol])
            for protocol in protocols
        }

    configs = {}
    for protocol, (train_group, validation_group) in groups.items():
        prefix = f'binary_{scope}_{protocol}_{family}'.replace('/', '_')
        model_config = hier.tune_stage(
            train_group, validation_group, 1, family, args.depths,
            args.n_estimators, args.leaf, args.tolerance, prefix, out_dir,
            cv_folds=args.cv_folds)
        if model_config is None:
            continue
        threshold_config = tune_binary_threshold(
            train_group, validation_group, model_config,
            args.urgent_thresholds, args.min_urgent_recall,
            prefix, out_dir, cv_folds=args.cv_folds,
            min_urgent_precision=args.min_urgent_precision)
        configs[protocol] = {
            'model': model_config,
            'threshold': threshold_config,
        }
    return configs


def fit_predict(train_df, test_df, scope, configs):
    prediction = np.full(len(test_df), 'NORMAL', dtype=object)
    if scope == 'pooled':
        config = configs['ALL']
        model = hier.fit_stage(train_df, 1, config['model'])
        probability = hier.class_probability(
            model, hier.feature_matrix(test_df), 'URGENT')
        return np.where(
            probability >= config['threshold']['urgent_threshold'],
            'URGENT', 'NORMAL')

    protocols = test_df['protocol'].astype(str).to_numpy()
    for protocol in sorted(set(protocols)):
        mask = protocols == protocol
        if protocol not in configs:
            print(f"  {protocol}: no urgent samples in train; fallback NORMAL")
            continue
        train_group = train_df[train_df['protocol'].astype(str) == protocol]
        config = configs[protocol]
        model = hier.fit_stage(train_group, 1, config['model'])
        probability = hier.class_probability(
            model, hier.feature_matrix(test_df.loc[mask]), 'URGENT')
        prediction[mask] = np.where(
            probability >= config['threshold']['urgent_threshold'],
            'URGENT', 'NORMAL')
    return prediction


def evaluate(name, test_df, prediction, out_dir):
    truth = binary_truth(test_df)
    print(f"\n--- {name} final binary test ---")
    print(classification_report(
        truth, prediction, labels=BINARY_CLASSES,
        target_names=BINARY_CLASSES, zero_division=0, digits=4))
    matrix = confusion_matrix(truth, prediction, labels=BINARY_CLASSES)
    print('Confusion matrix (rows=true, cols=pred):')
    print(f"             {'  '.join(f'{c:>8}' for c in BINARY_CLASSES)}")
    for label, row in zip(BINARY_CLASSES, matrix):
        print(f"  {label:>8}  {'  '.join(f'{value:>8}' for value in row)}")

    report = classification_report(
        truth, prediction, labels=BINARY_CLASSES,
        target_names=BINARY_CLASSES, zero_division=0, output_dict=True)
    rows = []
    protocols = test_df['protocol'].astype(str).to_numpy()
    for protocol in sorted(set(protocols)):
        mask = protocols == protocol
        protocol_truth = truth[mask]
        protocol_prediction = prediction[mask]
        if set(protocol_truth) == {'NORMAL'}:
            print(f"  {protocol}: NORMAL-only; binary urgency F1 not applicable")
            continue
        protocol_report = classification_report(
            protocol_truth, protocol_prediction, labels=BINARY_CLASSES,
            target_names=BINARY_CLASSES, zero_division=0, output_dict=True)
        protocol_macro = f1_score(
            protocol_truth, protocol_prediction, labels=BINARY_CLASSES,
            average='macro', zero_division=0)
        print(f"  {protocol}: macro-F1={protocol_macro:.4f}, "
              f"F1_URGENT={protocol_report['URGENT']['f1-score']:.4f}, "
              f"recall_URGENT={protocol_report['URGENT']['recall']:.4f}")
        rows.append({
            'model': name,
            'protocol': protocol,
            'support': int(mask.sum()),
            'f1_macro': float(protocol_macro),
            'f1_urgent': float(protocol_report['URGENT']['f1-score']),
            'urgent_recall': float(protocol_report['URGENT']['recall']),
        })
    pd.DataFrame(rows).to_csv(
        out_dir / f'{name}_binary_metrics_by_protocol.csv', index=False)

    columns = [column for column in
               ['run_id', 't_start', 'device_id', 'protocol', 'scenario',
                'message_kind', trainlib.TARGET]
               if column in test_df.columns]
    output = test_df[columns].copy()
    output['binary_truth'] = truth
    output['prediction'] = prediction
    output['correct'] = truth == prediction
    output.to_csv(out_dir / f'{name}_binary_predictions.csv', index=False)
    output[~output['correct']].to_csv(
        out_dir / f'{name}_binary_errors.csv', index=False)

    return {
        'model': name,
        'accuracy': float(accuracy_score(truth, prediction)),
        'f1_macro': float(f1_score(
            truth, prediction, labels=BINARY_CLASSES,
            average='macro', zero_division=0)),
        'f1_urgent': float(report['URGENT']['f1-score']),
        'urgent_precision': float(report['URGENT']['precision']),
        'urgent_recall': float(report['URGENT']['recall']),
        'f1_normal': float(report['NORMAL']['f1-score']),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv-train', nargs='+', required=True)
    parser.add_argument('--csv-validation', nargs='+', required=True)
    parser.add_argument('--csv-test', nargs='+', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--scope', choices=['pooled', 'per-protocol', 'both'],
                        default='both')
    parser.add_argument('--families', nargs='+', choices=['dt', 'rf'],
                        default=['dt', 'rf'])
    parser.add_argument('--depths', nargs='+', type=int,
                        default=[3, 5, 8, 10, 12, 15, 20, 25, 30])
    parser.add_argument('--n-estimators', nargs='+', type=int,
                        default=[10, 30, 50, 100])
    parser.add_argument('--leaf', type=int, default=10)
    parser.add_argument('--tolerance', type=float, default=0.005)
    parser.add_argument(
        '--urgent-thresholds', nargs='+', type=float,
        default=[0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 0.98, 0.99])
    parser.add_argument('--min-urgent-recall', type=float, default=0.95)
    parser.add_argument(
        '--min-urgent-precision', type=float, default=0.80,
        help='San precision cho lop URGENT khi rang buoc recall bat kha thi.')
    parser.add_argument(
        '--cv-folds', type=int, default=0,
        help='So fold kiem dinh cheo theo lan chay tren hop train+validation. '
             '0 = giu nguyen cach chia mot tap kiem dinh co dinh.')
    args = parser.parse_args()

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    trainlib.FEATURES = trainlib.FEATURES_BEHAVIOR20

    train_df = hier.load_group(args.csv_train, 1, 'Training runs')
    validation_df = hier.load_group(
        args.csv_validation, 100, 'Validation runs')
    test_df = hier.load_group(args.csv_test, 200, 'Final test runs')
    fit_df = pd.concat([train_df, validation_df], ignore_index=True)
    scopes = ['pooled', 'per-protocol'] if args.scope == 'both' else [args.scope]
    summary = []

    if args.cv_folds > 0:
        runs = sorted(set(train_df['run_id']) | set(validation_df['run_id']))
        print(f'\nChe do kiem dinh cheo: {args.cv_folds} fold theo lan chay '
              f'tren {len(runs)} lan chay gop lai (train + validation).')

    for scope in scopes:
        for family in args.families:
            name = f'binary_{scope}_{family}'
            print('\n' + '=' * 78)
            print(f'TUNING {name.upper()}')
            print('=' * 78)
            configs = tune_scope(
                train_df, validation_df, scope, family, args, out_dir)
            if not configs:
                continue
            (out_dir / f'{name}_config.json').write_text(
                json.dumps(configs, indent=2), encoding='utf-8')
            prediction = fit_predict(fit_df, test_df, scope, configs)
            summary.append(evaluate(name, test_df, prediction, out_dir))

    summary_df = pd.DataFrame(summary).sort_values(
        ['f1_macro', 'f1_urgent'], ascending=False)
    summary_df.to_csv(out_dir / 'binary_summary.csv', index=False)
    print('\n' + '=' * 78)
    print('FINAL BINARY TEST SUMMARY')
    print('=' * 78)
    print(summary_df[[
        'model', 'f1_macro', 'f1_urgent', 'urgent_precision',
        'urgent_recall', 'f1_normal']].to_string(index=False))
    print(f"\nSaved results to: {out_dir}")


if __name__ == '__main__':
    main()
