#!/usr/bin/env python3
"""Tune DT/RF on held-out simulation runs using urgency-aware metrics."""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, f1_score, recall_score
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).parent))
import train_and_export as trainlib


def score_model(model, x_train, y_train, x_test, y_test, classes):
    pred_train = model.predict(x_train)
    pred_test = model.predict(x_test)
    labels = np.arange(len(classes))
    f1 = f1_score(y_test, pred_test, labels=labels, average=None,
                  zero_division=0)
    recall = recall_score(y_test, pred_test, labels=labels, average=None,
                          zero_division=0)
    result = {
        'train_acc': float((pred_train == y_train).mean()),
        'test_acc': float((pred_test == y_test).mean()),
        'balanced_acc': float(balanced_accuracy_score(y_test, pred_test)),
        'f1_macro': float(f1_score(y_test, pred_test, labels=labels,
                                   average='macro', zero_division=0)),
    }
    result['gap'] = result['train_acc'] - result['test_acc']
    for cls, value, rec in zip(classes, f1, recall):
        result[f'f1_{cls}'] = float(value)
        result[f'recall_{cls}'] = float(rec)
    return result


def print_header(first_name, classes):
    class_cols = ' '.join(f"{('f1_' + c[:3]):>8}" for c in classes)
    print(f"{first_name:>7} {'train':>8} {'test':>8} {'bal_acc':>8} "
          f"{'gap':>8} {class_cols} {'macro':>8} {'flag':>10}")
    print('-' * (70 + 9 * len(classes)))


def print_row(first, result, classes):
    values = ' '.join(f"{result[f'f1_{c}']:>8.4f}" for c in classes)
    flag = ('OVERFIT' if result['gap'] > 0.05 else
            'borderline' if result['gap'] > 0.03 else '')
    print(f"{first:>7} {result['train_acc']:>8.4f} "
          f"{result['test_acc']:>8.4f} {result['balanced_acc']:>8.4f} "
          f"{result['gap']:>8.4f} {values} "
          f"{result['f1_macro']:>8.4f} {flag:>10}")


def sweep_dt(x_train, y_train, x_test, y_test, classes, depths, leaf):
    print(f"\n[Stage 1 - DT depth sweep] depths={depths}, leaf={leaf}")
    print_header('depth', classes)
    rows = []
    for depth in depths:
        model = DecisionTreeClassifier(
            max_depth=depth, min_samples_leaf=leaf,
            class_weight='balanced', random_state=42)
        model.fit(x_train, y_train)
        result = score_model(
            model, x_train, y_train, x_test, y_test, classes)
        result.update(max_depth=depth, n_leaves=model.get_n_leaves())
        rows.append(result)
        print_row(depth, result, classes)
    return pd.DataFrame(rows)


def sweep_rf(x_train, y_train, x_test, y_test, classes, trees, depth, leaf):
    print(f"\n[Stage 2 - RF tree sweep] depth={depth}, leaf={leaf}")
    print_header('trees', classes)
    rows = []
    for count in trees:
        model = RandomForestClassifier(
            n_estimators=count, max_depth=depth, min_samples_leaf=leaf,
            class_weight='balanced', n_jobs=-1, random_state=42)
        model.fit(x_train, y_train)
        result = score_model(
            model, x_train, y_train, x_test, y_test, classes)
        result.update(n_estimators=count, max_depth=depth)
        rows.append(result)
        print_row(count, result, classes)
    return pd.DataFrame(rows)


def recommend(df, parameter, tolerance):
    candidates = df[df['gap'] < 0.05]
    if candidates.empty:
        candidates = df
    peak = candidates['f1_macro'].max()
    near = candidates[candidates['f1_macro'] >= peak - tolerance]
    return near.sort_values(parameter).iloc[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv-train', nargs='+', required=True)
    ap.add_argument('--csv-test', nargs='+', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--depths', nargs='+', type=int,
                    default=[3, 5, 8, 10, 12, 15, 18, 20])
    ap.add_argument('--n-estimators', nargs='+', type=int,
                    default=[10, 30, 50, 100, 200])
    ap.add_argument('--leaf', type=int, default=10)
    ap.add_argument('--tolerance', type=float, default=0.005)
    ap.add_argument('--features', choices=['behavior20'], default='behavior20')
    ap.add_argument('--target-mode', choices=['three', 'binary'],
                    default='three')
    ap.add_argument('--oversample-minority', action='store_true')
    ap.add_argument('--max-normal-ratio', type=float, default=5.0,
                    help='Train-only NORMAL cap; set 0 to disable')
    args = ap.parse_args()

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    trainlib.FEATURES = trainlib.FEATURES_BEHAVIOR20

    train_df, test_df = trainlib.load_and_clean(
        args.csv_train, args.csv_test)
    train_df, test_df = trainlib.configure_target_mode(
        train_df, test_df, args.target_mode)
    trainlib.class_distribution(train_df, 'Train before balancing')
    trainlib.class_distribution(test_df, 'Held-out test')
    if args.max_normal_ratio > 0:
        train_df = trainlib.downsample_normal(
            train_df, args.max_normal_ratio)
    if args.oversample_minority:
        train_df = trainlib.oversample_minority(train_df, min_frac=0.10)
    trainlib.class_distribution(train_df, 'Train used for tuning')

    missing = sorted(set(trainlib.TRAFFIC_CLASSES) -
                     set(train_df[trainlib.TARGET].unique()))
    if missing:
        raise SystemExit(f'Training set is missing classes: {missing}')

    x_train, y_train = trainlib.prepare_xy(train_df)
    x_test, y_test = trainlib.prepare_xy(test_df)
    classes = trainlib.TRAFFIC_CLASSES
    print(f"\nTarget mode: {args.target_mode}; classes={classes}")
    print(f"Features: {len(trainlib.FEATURES)} behavior-only causal features")

    dt = sweep_dt(x_train, y_train, x_test, y_test, classes,
                  args.depths, args.leaf)
    dt.to_csv(out_dir / 'sweep_dt.csv', index=False)
    dt_rec = recommend(dt, 'max_depth', args.tolerance)
    depth = int(dt_rec['max_depth'])

    rf = sweep_rf(x_train, y_train, x_test, y_test, classes,
                  args.n_estimators, depth, args.leaf)
    rf.to_csv(out_dir / 'sweep_rf.csv', index=False)
    rf_rec = recommend(rf, 'n_estimators', args.tolerance)
    trees = int(rf_rec['n_estimators'])

    print('\n' + '=' * 72)
    print('RECOMMENDATION (selected by held-out macro-F1, gap < 5%)')
    print('=' * 72)
    print(f"DT: depth={depth}, leaf={args.leaf}, "
          f"macro-F1={dt_rec['f1_macro']:.4f}, "
          f"balanced_acc={dt_rec['balanced_acc']:.4f}")
    print(f"RF: depth={depth}, trees={trees}, leaf={args.leaf}, "
          f"macro-F1={rf_rec['f1_macro']:.4f}, "
          f"balanced_acc={rf_rec['balanced_acc']:.4f}")
    print('\nRun binary first as a feasibility check, then repeat with '
          '--target-mode three for the final QoS classes.')


if __name__ == '__main__':
    main()
