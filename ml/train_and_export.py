#!/usr/bin/env python3
"""
train_and_export.py â€” DT/RF training pipeline (multi-run).

Splits train/test by RUN to prevent intra-run leakage:
    * train on N-1 runs (each = independent device deployment)
    * test on the held-out run (cross-deployment generalization)

Default hyperparameters chosen after depth-sweep analysis (see
tune_depth.py / sweep_dt.csv / sweep_rf.csv) for best balance of
test accuracy, train-test gap, and per-class F1.

Usage:
    python train_and_export.py \
        --csv-train ../output/run1/scada_features.csv \
                    ../output/run2/scada_features.csv \
        --csv-test  ../output/run3/scada_features.csv \
        --out       ../scratch/scada/

Feature ordering must match ns3::FeatureIdx in ml_inference.h.
"""
import argparse
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

try:
    import m2cgen as m2c
except ImportError:
    sys.exit("ERROR: m2cgen not installed.  Run: pip install m2cgen")


FEATURES_BASE = ['pkts_tx', 'pkts_rx', 'bytes_rx', 'pkts_lost',
                 'thr_mbps', 'mean_delay_ms', 'jitter_ms']

# Phase A1 (13 features): base + 6 derived.
FEATURES_EXT  = FEATURES_BASE + [
    'avg_pkt_size',     # bytes_rx / pkts_rx
    'tx_rx_ratio',      # pkts_tx / pkts_rx â€” directionality
    'pkts_tx_delta',    # window-to-window burst signal
    'delay_delta',      # delay change between windows
    'interval_cov',     # rolling 5-window CoV of pkts_tx
    'burst_indicator']  # 1 if pkts_tx > 1.5 Ã— previous

FEATURES_NETWORK = [
    # Kept from base (drop pkts_lost â€” flat 0 importance)
    'pkts_tx', 'pkts_rx', 'bytes_rx',
    'thr_mbps', 'mean_delay_ms', 'jitter_ms',
    # Kept from ext (drop tx_rx_ratio & burst_indicator â€” flop)
    'avg_pkt_size', 'pkts_tx_delta', 'delay_delta', 'interval_cov',
    # NEW Phase A2 features
    'jitter_delay_ratio',  # jitter / delay â€” relative variability
    'interval_cov_10',     # rolling 10-window CoV (longer-horizon)
    'delay_smooth',        # rolling 10-window mean delay (denoise)
    'pkt_rate_change',     # pct change of pkts_tx (scale-invariant burst)
    'jitter_std_5',        # rolling 5-window std of jitter
]

# Protocol + device-aware gateway classifier (17 features): 15
# network-behavior features plus protocol_id and device_type_id. This assumes
# the gateway has an asset/tag mapping for broad device categories, but does
# not inspect message semantics such as telemetry/status/alarm/trip.
FEATURES_PROTO_DEVICE17 = FEATURES_NETWORK + [
    'protocol_id',
    'device_type_id',
]

# Legacy feature sets above are kept only for old CSV compatibility.  The
# current thesis pipeline uses behavior-only features generated from
# scada_packets.csv by ml/build_behavior_features.py.
FEATURES_BEHAVIOR20 = [
    'pkt_count_1s',
    'current_pkt_size',
    'avg_pkt_size',
    'max_pkt_size',
    'pkt_size_std',
    'pkt_size_entropy',
    'inter_arrival_mean',
    'inter_arrival_min',
    'inter_arrival_std',
    'current_size_baseline_ratio',
    'time_since_last_pkt',
    'silent_gap_ratio',
    'pkt_rate_delta',
    'current_size_zscore',
    'burst_count_100ms',
    'burst_count_500ms',
    'short_long_rate_ratio',
    'baseline_pkt_rate_zscore',
    'baseline_size_zscore',
    'uplink_downlink_ratio',
]

FEATURES = FEATURES_BEHAVIOR20
TARGET = 'traffic_class'
TRAFFIC_CLASSES = ['EMERGENCY', 'IMPORTANT', 'NORMAL']
TRAFFIC_CLASS_TO_IDX = {name: i for i, name in enumerate(TRAFFIC_CLASSES)}


def configure_target_mode(train_df, test_df, mode):
    """Configure three-class production training or binary diagnosis."""
    global TRAFFIC_CLASSES, TRAFFIC_CLASS_TO_IDX
    if mode == 'binary':
        train_df = train_df.copy()
        test_df = test_df.copy()
        mapping = {'EMERGENCY': 'URGENT', 'IMPORTANT': 'URGENT',
                   'NORMAL': 'NORMAL'}
        train_df[TARGET] = train_df[TARGET].map(mapping)
        test_df[TARGET] = test_df[TARGET].map(mapping)
        TRAFFIC_CLASSES = ['URGENT', 'NORMAL']
    else:
        TRAFFIC_CLASSES = ['EMERGENCY', 'IMPORTANT', 'NORMAL']
    TRAFFIC_CLASS_TO_IDX = {
        name: i for i, name in enumerate(TRAFFIC_CLASSES)
    }
    return train_df, test_df


def add_derived_features(df):
    """Compute all derived features needed for the active feature mode.
    All features are CAUSAL (only same-window or past data of the same flow)
    so they can be wired into ns-3 OnWindow.

    Groupby on (run_id, flow_id) prevents leakage between independent
    deployments â€” flow_id can repeat across runs since FlowMonitor
    restarts IDs per simulation.
    """
    if set(FEATURES_BEHAVIOR20).issubset(df.columns):
        return df.sort_values(['run_id', 'device_id', 't_start']).reset_index(drop=True)
    if 'pkt_count_1s' in df.columns:
        missing = sorted(set(FEATURES_BEHAVIOR20) - set(df.columns))
        raise SystemExit(
            'Behavior feature CSV uses an older schema. Re-run '
            'ml/build_behavior_features.py on the existing scada_packets.csv. '
            f'Missing columns: {missing}')

    df = df.sort_values(['run_id', 'flow_id', 't_start']).reset_index(drop=True)

    # â”€â”€ Phase A1 derived features (kept for backward compatibility) â”€â”€
    df['avg_pkt_size'] = df['bytes_rx'] / df['pkts_rx'].clip(lower=1)
    df['tx_rx_ratio']  = df['pkts_tx'] / df['pkts_rx'].clip(lower=1)

    grp = df.groupby(['run_id', 'flow_id'])
    pkts_prev  = grp['pkts_tx'].shift(1).fillna(0)
    delay_prev = grp['mean_delay_ms'].shift(1).fillna(0)
    df['pkts_tx_delta'] = df['pkts_tx']       - pkts_prev
    df['delay_delta']   = df['mean_delay_ms'] - delay_prev

    roll_mean_5 = grp['pkts_tx'].transform(
        lambda x: x.rolling(window=5, min_periods=2).mean())
    roll_std_5  = grp['pkts_tx'].transform(
        lambda x: x.rolling(window=5, min_periods=2).std())
    df['interval_cov'] = (roll_std_5 / roll_mean_5.clip(lower=0.1)).fillna(0)

    df['burst_indicator'] = ((df['pkts_tx'] > pkts_prev * 1.5) &
                              (pkts_prev > 0)).astype(int)

    # â”€â”€ Phase A2 NEW features â”€â”€

    # F1: jitter / delay â€” relative variability (networking-aware)
    df['jitter_delay_ratio'] = (df['jitter_ms'] /
                                df['mean_delay_ms'].clip(lower=0.1))

    # F2: rolling 10-window CoV â€” capture longer-horizon periodicity
    roll_mean_10 = grp['pkts_tx'].transform(
        lambda x: x.rolling(window=10, min_periods=3).mean())
    roll_std_10  = grp['pkts_tx'].transform(
        lambda x: x.rolling(window=10, min_periods=3).std())
    df['interval_cov_10'] = (roll_std_10 / roll_mean_10.clip(lower=0.1)).fillna(0)

    # F3: rolling 10-window mean of delay â€” denoise instantaneous spikes
    df['delay_smooth'] = grp['mean_delay_ms'].transform(
        lambda x: x.rolling(window=10, min_periods=3).mean()).fillna(
        df['mean_delay_ms'])

    # F4: percent change of pkts_tx â€” scale-invariant burst signal.
    # Replace inf/NaN with 0 (first window or division by zero).
    pct = grp['pkts_tx'].pct_change().fillna(0)
    df['pkt_rate_change'] = pct.replace([np.inf, -np.inf], 0)

    # F5: rolling 5-window std of jitter â€” variability-of-variability,
    # captures protocol behavior stability.
    df['jitter_std_5'] = grp['jitter_ms'].transform(
        lambda x: x.rolling(window=5, min_periods=2).std()).fillna(0)

    return df


def load_csv(path, run_id):
    p = Path(path).expanduser().resolve()
    if not p.exists():
        sys.exit(f"ERROR: CSV not found: {p}")
    df = pd.read_csv(p)
    if TARGET not in df.columns:
        sys.exit(
            f"ERROR: CSV {p} does not contain '{TARGET}'. "
            "Regenerate simulation CSVs with the updated scada.cc first.")
    df['run_id'] = run_id
    before = len(df)
    df = df[df['protocol'] != 'Other']
    df = df[df['t_start'] > 0.0]
    if 'train_usable' in df.columns:
        df = df[df['train_usable'] == 1]
    # Protocol overhead (ACK/S/U frames, polls, handshakes) is handled by a
    # fixed gateway policy. The urgency classifier only compares telemetry
    # messages with incident events from the same simulated traffic stream.
    if 'message_kind' in df.columns:
        df = df[df['message_kind'].isin(['TELEMETRY', 'EVENT'])]
    print(f"  {p.name:>30}: {len(df):>6} rows  (filtered {before - len(df)})")
    return df


def load_and_clean(train_paths, test_paths):
    print("\n[1/6] Loading datasets")
    print("  Train set:")
    train_dfs = [load_csv(p, i+1) for i, p in enumerate(train_paths)]
    print("  Test set:")
    test_dfs  = [load_csv(p, 100+i) for i, p in enumerate(test_paths)]

    train = pd.concat(train_dfs, ignore_index=True)
    test  = pd.concat(test_dfs,  ignore_index=True)

    # Enrich with derived features (per-DataFrame to avoid
    # cross-train/test leakage in rolling stats)
    print("\n  Computing derived features (avg_pkt_size, tx_rx_ratio, "
          "deltas, CoV, burst)...")
    train = add_derived_features(train)
    test  = add_derived_features(test)

    print(f"\n  Train total: {len(train)} rows from {len(train_dfs)} runs")
    print(f"  Test  total: {len(test)} rows from {len(test_dfs)} runs")
    return train, test


def class_distribution(df, name):
    print(f"\n  {name} class distribution:")
    counts = df[TARGET].value_counts().sort_index()
    total = counts.sum()
    for cls, n in counts.items():
        print(f"    {cls:>6}: {n:>6} ({100*n/total:5.2f}%)")
    minority = (counts.get('EMERGENCY', 0) if 'EMERGENCY' in counts
                else counts.get('URGENT', 0))
    if total > 0 and minority / total < 0.05:
        print("    WARNING: urgent minority < 5%; report recall/F1 and consider "
              "--oversample-minority for training only.")


def oversample_minority(df, min_frac=0.10, classes=None):
    """Oversample minority urgency classes on TRAIN ONLY.

    This does not touch the held-out test run.  It is intentionally simple
    random oversampling because DT/RF can work well with duplicated minority
    windows and it avoids adding synthetic traffic-pattern points.
    """
    counts = df[TARGET].value_counts()
    if len(df) == 0:
        return df
    if classes is None:
        classes = (['URGENT'] if 'URGENT' in counts
                   else ['EMERGENCY', 'IMPORTANT'])
    parts = [df]
    total = len(df)
    for cls in classes:
        n = counts.get(cls, 0)
        if n == 0 or n / total >= min_frac:
            continue
        # Solve (n + k) / (total + k) >= min_frac.
        k = int(np.ceil((min_frac * total - n) / (1.0 - min_frac)))
        parts.append(df[df[TARGET] == cls].sample(
            n=k, replace=True, random_state=42 + len(parts)))
        total += k
        print(f"  Oversampled {cls} in train: +{k} rows")
    out = pd.concat(parts, ignore_index=True)
    return out.sample(frac=1.0, random_state=42).reset_index(drop=True)


def downsample_normal(df, max_ratio=5.0):
    """Limit NORMAL rows on train only; held-out prevalence stays realistic."""
    minority = df[df[TARGET] != 'NORMAL']
    normal = df[df[TARGET] == 'NORMAL']
    if len(minority) == 0 or max_ratio <= 0:
        return df
    keep = min(len(normal), int(np.ceil(max_ratio * len(minority))))
    if keep == len(normal):
        return df
    normal = normal.sample(n=keep, random_state=42)
    print(f"  Downsampled NORMAL in train: {len(df[df[TARGET] == 'NORMAL'])} "
          f"-> {keep} rows")
    return pd.concat([minority, normal], ignore_index=True).sample(
        frac=1.0, random_state=42).reset_index(drop=True)


def prepare_xy(df):
    X = df[FEATURES].values.astype(np.float64)
    y_str = df[TARGET].values
    unknown = sorted(set(y_str) - set(TRAFFIC_CLASSES))
    if unknown:
        sys.exit(f"ERROR: unknown {TARGET} labels: {unknown}")
    y = np.array([TRAFFIC_CLASS_TO_IDX[v] for v in y_str], dtype=np.int32)
    return X, y


def train_dt(X_train, y_train, max_depth=15, min_samples_leaf=10):
    print(f"\n[3/6] Training DT (depth={max_depth}, leaf={min_samples_leaf})")
    dt = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        class_weight='balanced',
        random_state=42)
    dt.fit(X_train, y_train)
    return dt


def train_rf(X_train, y_train, n_estimators=50, max_depth=15,
             min_samples_leaf=10):
    print(f"\n[4/6] Training RF (trees={n_estimators}, depth={max_depth}, "
          f"leaf={min_samples_leaf})")
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=min_samples_leaf,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42)
    rf.fit(X_train, y_train)
    return rf


def evaluate(name, model, X_test, y_test, classes):
    y_pred = model.predict(X_test)
    acc = (y_pred == y_test).mean()
    labels = list(range(len(classes)))
    print(f"\n--- {name} eval (held-out test run) ---")
    print(f"  overall accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, labels=labels,
                                target_names=[str(c) for c in classes],
                                zero_division=0))
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    print("  confusion matrix (rows=true, cols=pred):")
    print(f"           {'  '.join(f'{c:>6}' for c in classes)}")
    for i, row in enumerate(cm):
        print(f"  {classes[i]:>6}  {'  '.join(f'{v:>6}' for v in row)}")
    return acc


def feature_importance(name, model):
    print(f"\n  {name} feature importance:")
    imps = model.feature_importances_
    paired = sorted(zip(FEATURES, imps), key=lambda x: -x[1])
    for feat, imp in paired:
        print(f"    {feat:>15}: {imp:.4f}")


def _fix_compound_literals(code, n_classes):
    """Replace C99 compound literals with direct assignments for C++ compat.

    m2cgen emits:  memcpy(var0, (double[]){a, b, c, d}, 4 * sizeof(double));
    C++ (esp. -O2) rejects taking address of a temporary array.
    Replace with:  var0[0] = a; var0[1] = b; var0[2] = c; var0[3] = d;
    """
    import re
    def _repl(m):
        var = m.group(1)
        vals = [v.strip() for v in m.group(2).split(',')]
        return '; '.join(f'{var}[{i}] = {v}' for i, v in enumerate(vals)) + ';'
    pattern = r'memcpy\((\w+), \(double\[\]\)\{([^}]+)\}, \d+ \* sizeof\(double\)\);'
    fixed = re.sub(pattern, _repl, code)
    return fixed


def export_model(model, fn_name, out_path, n_classes):
    code = m2c.export_to_c(model, function_name=fn_name)
    code = _fix_compound_literals(code, n_classes)
    guard_macro = f"SCADA_MODEL_{fn_name.upper().replace('SCORE_', '')}_TRAINED"
    header = (
        f"// =====================================================================\n"
        f"//  {out_path.name}  â€”  AUTO-GENERATED by ml/train_and_export.py\n"
        f"//  Function: {fn_name}(double* input, double* output)\n"
        f"//    input  = N_FEATURES doubles (see ml_inference.h)\n"
        f"//    output = {n_classes} doubles (one per traffic class)\n"
        f"// =====================================================================\n"
        f"#pragma once\n\n"
        f"#define {guard_macro}\n\n"
    )
    out_path.write_text(header + code + "\n")
    size_kb = out_path.stat().st_size / 1024
    print(f"  -> {out_path.name}  ({size_kb:.1f} KB)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv-train', nargs='+', required=True,
                    help='Training run CSV(s).  Each = independent deployment.')
    ap.add_argument('--csv-test', nargs='+', required=True,
                    help='Held-out test run CSV(s).')
    ap.add_argument('--out', required=True,
                    help='Output directory (typically scratch/scada/)')
    # Defaults updated per depth-sweep recommendation (tune_depth.py):
    #   DT: depth=15, leaf=10 â€” best test_acc with smallest gap
    #   RF: depth=15, leaf=10, trees=50 â€” best per-class F1 balance
    ap.add_argument('--dt-depth',  type=int, default=15)
    ap.add_argument('--dt-leaf',   type=int, default=10)
    ap.add_argument('--rf-trees',  type=int, default=50)
    ap.add_argument('--rf-depth',  type=int, default=15)
    ap.add_argument('--rf-leaf',   type=int, default=10)
    ap.add_argument('--features',  choices=['behavior20'],
                    default='behavior20',
                    help="Feature set: behavior20 = 20 traffic-pattern features")
    ap.add_argument('--oversample-minority', action='store_true',
                    help='Oversample EMERGENCY/IMPORTANT to at least 10% each in train only')
    ap.add_argument('--oversample-emergency', action='store_true',
                    help='Deprecated alias for --oversample-minority')
    ap.add_argument('--target-mode', choices=['three', 'binary'],
                    default='three',
                    help='three = NORMAL/IMPORTANT/EMERGENCY; binary is an '
                         'offline URGENT-vs-NORMAL diagnostic')
    ap.add_argument('--max-normal-ratio', type=float, default=5.0,
                    help='Train-only NORMAL cap relative to all urgent rows; '
                         'set 0 to disable (default 5)')
    args = ap.parse_args()

    # Select active feature set based on --features flag.
    global FEATURES
    FEATURES = FEATURES_BEHAVIOR20
    print(f"\nFeature mode: {args.features} ({len(FEATURES)} features)")

    out_dir  = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    train_df, test_df = load_and_clean(args.csv_train, args.csv_test)
    train_df, test_df = configure_target_mode(
        train_df, test_df, args.target_mode)

    class_distribution(train_df, "Train")
    class_distribution(test_df,  "Test")
    if args.max_normal_ratio > 0:
        train_df = downsample_normal(train_df, args.max_normal_ratio)
    if args.oversample_minority or args.oversample_emergency:
        train_df = oversample_minority(train_df, min_frac=0.10)
        class_distribution(train_df, "Train after oversample")

    print("\n[2/6] Preparing features")
    missing_train = sorted(set(TRAFFIC_CLASSES) - set(train_df[TARGET].unique()))
    if missing_train:
        sys.exit(
            f"ERROR: training data missing traffic_class labels: {missing_train}. "
            "Run longer/more simulation runs so every target class is present.")

    X_train, y_train = prepare_xy(train_df)
    X_test,  y_test  = prepare_xy(test_df)
    print(f"      Features ({len(FEATURES)}): {FEATURES}")
    print(f"      Label encoding ({len(TRAFFIC_CLASSES)} classes):")
    for i, c in enumerate(TRAFFIC_CLASSES):
        print(f"        {i} = {c}")

    dt = train_dt(X_train, y_train,
                  max_depth=args.dt_depth,
                  min_samples_leaf=args.dt_leaf)
    rf = train_rf(X_train, y_train,
                  n_estimators=args.rf_trees,
                  max_depth=args.rf_depth,
                  min_samples_leaf=args.rf_leaf)

    evaluate("Decision Tree", dt, X_test, y_test, TRAFFIC_CLASSES)
    feature_importance("DT", dt)
    evaluate("Random Forest", rf, X_test, y_test, TRAFFIC_CLASSES)
    feature_importance("RF", rf)

    # This script is now diagnostic only.  The C++ runtime consumes the
    # per-protocol binary models written by export_binary_models.py; the old
    # three-class scada_model_{dt,rf}.h headers it used to emit were never
    # included by any .cc file and have been removed.
    print("\n[5/6] Diagnostic run only; no C++ runtime headers were written. "
          "Use ml/export_binary_models.py to regenerate scratch/scada models.")

    print(f"\n[6/6] DONE.  Rebuild ns-3 to pick up new models:")


if __name__ == '__main__':
    main()
