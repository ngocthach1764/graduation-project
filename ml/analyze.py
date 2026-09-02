#!/usr/bin/env python3
"""
analyze.py — Phase 1 final comparison: 4-mode SCADA classification eval.

Compares 4 classification modes (same --run= deployment):
    baseline  : expert-rule reference (scenario-aware, ground truth)
    port      : L4 port-based traditional classifier (no scenario awareness)
    dt        : Decision Tree ML
    rf        : Random Forest ML

Reports:
    [1] Latency       — per protocol × scenario × mode
    [2] Drop rate     — per DSCP class × scenario × mode
    [3] Throughput    — per protocol × scenario × mode
    [4] Jitter        — per DSCP class × scenario × mode
    [5] ML metrics    — accuracy / precision / recall / F1 per mode
    [6] Confusion matrix — per mode

Usage:
    python ml/analyze.py \
        --base output/baseline/scada_features.csv \
        --port output/port/scada_features.csv \
        --dt   output/dt/scada_features.csv \
        --rf   output/rf/scada_features.csv
"""
import argparse
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


# Ground-truth DSCP for each (protocol, scenario) pair — mirrors the
# scenario-aware expert rule in scada.cc's LabelToTos.  Used to evaluate
# all 4 classification modes against the same authoritative ground truth.
GT_DSCP = {
    'Modbus':       {'normal': 'AF31', 'high_load': 'AF31', 'emergency': 'AF31'},
    'DNP3':         {'normal': 'AF31', 'high_load': 'AF31', 'emergency': 'EF'},
    'IEC104':       {'normal': 'AF31', 'high_load': 'AF31', 'emergency': 'EF'},
    'OPC-UA':       {'normal': 'AF21', 'high_load': 'AF21', 'emergency': 'AF21'},
    'MQTT':         {'normal': 'BE',   'high_load': 'BE',   'emergency': 'BE'},
    'GW_Heartbeat': {'normal': 'AF31', 'high_load': 'AF31', 'emergency': 'AF31'},
    'GW_Status':    {'normal': 'AF21', 'high_load': 'AF21', 'emergency': 'AF21'},
}

DSCP_PRIORITY = ['EF', 'AF31', 'AF21', 'BE']
TRAFFIC_CLASSES = ['EMERGENCY', 'IMPORTANT', 'NORMAL']
SCENARIOS     = ['normal', 'high_load', 'emergency']


def load(path, name):
    p = Path(path).expanduser().resolve()
    if not p.exists():
        sys.exit(f"ERROR: not found ({name}): {p}")
    df = pd.read_csv(p)
    df = df[df['protocol'] != 'Other']
    df = df[df['t_start'] > 0.0]
    return df


def add_gt_column(df):
    """Annotate df with ground-truth DSCP class per row."""
    df = df.copy()
    if 'traffic_class' in df.columns:
        cls_to_dscp = {
            'EMERGENCY': 'EF',
            'IMPORTANT': 'AF31',
            'NORMAL': 'BE',
        }
        df['gt_dscp'] = df['traffic_class'].map(cls_to_dscp)
        missing = df['gt_dscp'].isna()
        if missing.any():
            df.loc[missing, 'gt_dscp'] = df[missing].apply(
                lambda r: GT_DSCP.get(r['protocol'], {}).get(r['scenario'], None),
                axis=1
            )
    else:
        df['gt_dscp'] = df.apply(
            lambda r: GT_DSCP.get(r['protocol'], {}).get(r['scenario'], None),
            axis=1
        )
    return df


def traffic_eval_frame(df):
    """Return rows with gt_traffic and pred_traffic for ML metrics."""
    d = df.copy()
    if 'traffic_class' not in d.columns:
        d['gt_traffic'] = d['protocol'].map({
            'DNP3': 'IMPORTANT',
            'IEC104': 'IMPORTANT',
            'Modbus': 'NORMAL',
            'OPC-UA': 'NORMAL',
            'MQTT': 'NORMAL',
        })
    else:
        d['gt_traffic'] = d['traffic_class']

    if 'pred_traffic_class' in d.columns:
        pred = d['pred_traffic_class'].replace('', np.nan)
        d['pred_traffic'] = pred
    else:
        d['pred_traffic'] = np.nan

    missing = d['pred_traffic'].isna()
    if missing.any() and 'dscp_class' in d.columns:
        dscp_to_tc = {
            'EF': 'EMERGENCY',
            'AF31': 'IMPORTANT',
            'AF21': 'NORMAL',
            'BE': 'NORMAL',
        }
        d.loc[missing, 'pred_traffic'] = d.loc[missing, 'dscp_class'].map(dscp_to_tc)

    return d[d['gt_traffic'].notna() & d['pred_traffic'].notna()]


def sec(num, title):
    bar = '=' * 70
    print(f"\n{bar}\n  [{num}] {title}\n{bar}")


# =====================================================================
#  Section 1: LATENCY per protocol × scenario × mode
# =====================================================================
def section_1_latency(dfs):
    sec(1, "LATENCY (ms) - per protocol x scenario x mode (mean)")
    modes = list(dfs.keys())
    protos = sorted(set().union(*[set(d['protocol'].unique()) for d in dfs.values()]))

    header = f"{'scenario':>11} {'protocol':>14}  " + \
             "  ".join(f"{m:>10}" for m in modes)
    print(header)
    print('-' * len(header))
    for scn in SCENARIOS:
        for proto in protos:
            row_vals = []
            for mode, df in dfs.items():
                d = df[(df['scenario'] == scn) & (df['protocol'] == proto)]
                if len(d) == 0:
                    row_vals.append(f"{'-':>10}")
                else:
                    row_vals.append(f"{d['mean_delay_ms'].mean():>10.3f}")
            print(f"{scn:>11} {proto:>14}  " + "  ".join(row_vals))
        print()


# =====================================================================
#  Section 2: DROP RATE per DSCP × scenario × mode
# =====================================================================
def section_2_drop(dfs):
    sec(2, "DROP RATE (%) - per DSCP class x scenario x mode")
    modes = list(dfs.keys())

    header = f"{'scenario':>11} {'dscp_class':>11}  " + \
             "  ".join(f"{m:>10}" for m in modes)
    print(header)
    print('-' * len(header))
    for scn in SCENARIOS:
        for cls in DSCP_PRIORITY:
            row_vals = []
            for mode, df in dfs.items():
                d = df[(df['scenario'] == scn) & (df['dscp_class'] == cls)]
                tx = d['pkts_tx'].sum()
                lost = d['pkts_lost'].sum()
                rate = (lost / tx) if tx > 0 else 0.0
                row_vals.append(f"{rate*100:>10.3f}")
            print(f"{scn:>11} {cls:>11}  " + "  ".join(row_vals))
        print()


# =====================================================================
#  Section 3: THROUGHPUT per protocol × scenario × mode
# =====================================================================
def section_3_throughput(dfs):
    sec(3, "THROUGHPUT (Mbps) - per protocol x scenario x mode (mean)")
    modes = list(dfs.keys())
    protos = sorted(set().union(*[set(d['protocol'].unique()) for d in dfs.values()]))

    header = f"{'scenario':>11} {'protocol':>14}  " + \
             "  ".join(f"{m:>11}" for m in modes)
    print(header)
    print('-' * len(header))
    for scn in SCENARIOS:
        for proto in protos:
            row_vals = []
            for mode, df in dfs.items():
                d = df[(df['scenario'] == scn) & (df['protocol'] == proto)]
                if len(d) == 0:
                    row_vals.append(f"{'-':>11}")
                else:
                    row_vals.append(f"{d['thr_mbps'].mean():>11.5f}")
            print(f"{scn:>11} {proto:>14}  " + "  ".join(row_vals))
        print()


# =====================================================================
#  Section 4: JITTER per DSCP × scenario × mode
# =====================================================================
def section_4_jitter(dfs):
    sec(4, "JITTER (ms) - per DSCP class x scenario x mode (mean / p95)")
    modes = list(dfs.keys())

    for cls in DSCP_PRIORITY:
        print(f"\n  DSCP class: {cls}")
        header = f"  {'scenario':>11}  " + \
                 "  ".join(f"{m+' mean':>13}" for m in modes) + "    " + \
                 "  ".join(f"{m+' p95':>12}" for m in modes)
        print(header)
        print('  ' + '-' * (len(header) - 2))
        for scn in SCENARIOS:
            means, p95s = [], []
            for mode, df in dfs.items():
                d = df[(df['scenario'] == scn) & (df['dscp_class'] == cls)]
                if len(d) == 0:
                    means.append(f"{'-':>13}")
                    p95s.append(f"{'-':>12}")
                else:
                    means.append(f"{d['jitter_ms'].mean():>13.4f}")
                    p95s.append(f"{np.percentile(d['jitter_ms'], 95):>12.4f}")
            print(f"  {scn:>11}  " + "  ".join(means) + "    " + "  ".join(p95s))


# =====================================================================
#  Section 5: ML METRICS - accuracy / precision / recall / F1
# =====================================================================
def section_5_ml_metrics(dfs):
    sec(5, "ML METRICS - traffic_class accuracy / precision / recall / F1")

    # Overall accuracy per mode
    print("\n  Overall accuracy (pred_traffic_class vs traffic_class):")
    print(f"  {'mode':>14} {'correct':>10} {'total':>10} {'accuracy':>10}")
    print('  ' + '-' * 50)
    for mode, df in dfs.items():
        valid = traffic_eval_frame(df)
        correct = (valid['pred_traffic'] == valid['gt_traffic']).sum()
        total = len(valid)
        acc = correct / total if total > 0 else 0.0
        print(f"  {mode:>14} {correct:>10} {total:>10} {acc*100:>9.2f}%")

    # Per-class metrics side-by-side (head-to-head comparison)
    print(f"\n  Per-class metrics (precision / recall / F1):")
    header = f"\n  {'class':>8} {'metric':>12}  " + \
             "  ".join(f"{m:>10}" for m in dfs)
    print(header)
    print('  ' + '-' * (len(header) - 2))

    # Compute reports for all modes once
    reports = {}
    for mode, df in dfs.items():
        valid = traffic_eval_frame(df)
        try:
            rep = classification_report(
                valid['gt_traffic'], valid['pred_traffic'],
                labels=TRAFFIC_CLASSES, output_dict=True, zero_division=0
            )
            reports[mode] = rep
        except Exception as e:
            reports[mode] = None
            print(f"  ERROR mode={mode}: {e}")

    for cls in TRAFFIC_CLASSES:
        for metric in ['precision', 'recall', 'f1-score']:
            vals = []
            for mode in dfs:
                rep = reports.get(mode)
                if rep and cls in rep:
                    vals.append(f"{rep[cls][metric]:>10.4f}")
                else:
                    vals.append(f"{'-':>10}")
            print(f"  {cls:>8} {metric:>12}  " + "  ".join(vals))
        # Show support count (same across modes since GT-based)
        sup_vals = []
        for mode in dfs:
            rep = reports.get(mode)
            if rep and cls in rep:
                sup_vals.append(f"{int(rep[cls]['support']):>10}")
            else:
                sup_vals.append(f"{'-':>10}")
        print(f"  {cls:>8} {'support':>12}  " + "  ".join(sup_vals))
        print()

    # Macro / weighted averages
    print(f"  Aggregate F1 scores:")
    print(f"  {'avg type':>14}  " + "  ".join(f"{m:>10}" for m in dfs))
    print('  ' + '-' * (16 + (12 * len(dfs))))
    for avg in ['macro avg', 'weighted avg']:
        vals = []
        for mode in dfs:
            rep = reports.get(mode)
            if rep and avg in rep:
                vals.append(f"{rep[avg]['f1-score']:>10.4f}")
            else:
                vals.append(f"{'-':>10}")
        print(f"  {avg:>14}  " + "  ".join(vals))


# =====================================================================
#  Section 6: CONFUSION MATRIX per mode
# =====================================================================
def section_6_confusion(dfs):
    sec(6, "CONFUSION MATRIX - traffic_class (rows = ground truth, cols = predicted)")

    for mode, df in dfs.items():
        valid = traffic_eval_frame(df)
        cm = confusion_matrix(
            valid['gt_traffic'], valid['pred_traffic'], labels=TRAFFIC_CLASSES
        )

        print(f"\n  Mode: {mode.upper()}")
        print(f"  {'':>10} " + " ".join(f"{c:>10}" for c in TRAFFIC_CLASSES) + "  (predicted)")
        for i, true_cls in enumerate(TRAFFIC_CLASSES):
            row = "  ".join(f"{cm[i][j]:>10}" for j in range(len(TRAFFIC_CLASSES)))
            print(f"  {true_cls:>10}  {row}")

        # Highlight critical errors
        total_errors = cm.sum() - cm.trace()
        if total_errors > 0:
            print(f"\n    Total errors: {total_errors} / {cm.sum()} "
                  f"({total_errors/cm.sum()*100:.2f}%)")
            # Most common error
            err_mask = np.ones_like(cm, dtype=bool)
            np.fill_diagonal(err_mask, False)
            cm_err = np.where(err_mask, cm, 0)
            if cm_err.max() > 0:
                idx = np.unravel_index(cm_err.argmax(), cm_err.shape)
                print(f"    Top error pair: {TRAFFIC_CLASSES[idx[0]]:>10} "
                      f"-> {TRAFFIC_CLASSES[idx[1]]:>10}  ({cm_err.max()} cases)")
        else:
            print("    Total errors: 0 (perfect classification)")


# =====================================================================
#  Main
# =====================================================================
def main():
    ap = argparse.ArgumentParser(
        description="SCADA QoS and traffic_class ML evaluation")
    ap.add_argument('--base', required=True,
                    help='Baseline (expert-rule reference) CSV')
    ap.add_argument('--port', required=True,
                    help='Port-based traditional DPI CSV')
    ap.add_argument('--dt',   required=True, help='Decision Tree CSV')
    ap.add_argument('--rf',   required=True, help='Random Forest CSV')
    args = ap.parse_args()

    # Ordered dict for consistent column order in all tables
    dfs = {
        'baseline': load(args.base, 'baseline'),
        'port':     load(args.port, 'port'),
        'dt':       load(args.dt,   'dt'),
        'rf':       load(args.rf,   'rf'),
    }
    print("Loaded CSVs:")
    for name, df in dfs.items():
        print(f"  {name:>10}: {len(df):>6} rows  "
              f"({df['protocol'].nunique()} protocols, "
              f"{df['scenario'].nunique()} scenarios)")

    section_1_latency(dfs)
    section_2_drop(dfs)
    section_3_throughput(dfs)
    section_4_jitter(dfs)
    section_5_ml_metrics(dfs)
    section_6_confusion(dfs)

    print("\n" + "=" * 70)
    print("  ANALYSIS DONE")
    print("=" * 70)


if __name__ == '__main__':
    main()
