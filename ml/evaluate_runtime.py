#!/usr/bin/env python3
"""Evaluate gateway runtime predictions from scada_runtime_ml.csv."""

import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score


BINARY_CLASSES = ['URGENT', 'NORMAL']
FINAL_CLASSES = ['EMERGENCY', 'IMPORTANT', 'NORMAL']


def evaluate(path, label):
    frame = pd.read_csv(path)
    if 'evaluated' in frame.columns:
        frame = frame[frame['evaluated'] == 1].copy()
    else:
        frame = frame[(frame['baseline_ready'] == 1) &
                      (frame['message_kind'] != 'PROTOCOL')].copy()
    if frame.empty:
        raise SystemExit(f'{path}: no evaluated telemetry/event rows')

    print('\n' + '=' * 76)
    print(f'{label}: {path} ({len(frame)} evaluated messages)')
    print('=' * 76)
    print('\nBinary NORMAL/URGENT')
    print(classification_report(
        frame['true_binary'], frame['pred_binary'],
        labels=BINARY_CLASSES, target_names=BINARY_CLASSES,
        digits=4, zero_division=0))
    print('Confusion matrix (rows=true, cols=pred):')
    print(confusion_matrix(
        frame['true_binary'], frame['pred_binary'], labels=BINARY_CLASSES))

    print('\nFinal classes after semantic rule')
    print(classification_report(
        frame['true_traffic_class'], frame['pred_traffic_class'],
        labels=FINAL_CLASSES, target_names=FINAL_CLASSES,
        digits=4, zero_division=0))

    rows = []
    for protocol, group in frame.groupby('protocol'):
        if group['true_binary'].nunique() < 2:
            continue
        rows.append({
            'model': label,
            'protocol': protocol,
            'support': len(group),
            'f1_urgent': f1_score(
                group['true_binary'], group['pred_binary'],
                labels=['URGENT'], average='macro', zero_division=0),
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', nargs='+', required=True)
    ap.add_argument('--labels', nargs='+')
    ap.add_argument('--out')
    args = ap.parse_args()
    labels = args.labels or [Path(path).parent.parent.name for path in args.csv]
    if len(labels) != len(args.csv):
        raise SystemExit('--labels must contain one label per --csv path')

    rows = []
    for path, label in zip(args.csv, labels):
        rows.extend(evaluate(path, label))
    summary = pd.DataFrame(rows)
    if not summary.empty:
        print('\nF1 URGENT by protocol')
        print(summary.pivot(index='protocol', columns='model',
                            values='f1_urgent').to_string())
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            summary.to_csv(out, index=False)
            print(f'\nSaved: {out}')


if __name__ == '__main__':
    main()
