#!/usr/bin/env python3
"""Tune and evaluate a two-stage SCADA urgency classifier.

Stage 1 detects NORMAL versus URGENT. Stage 2 classifies urgent messages as
IMPORTANT or EMERGENCY. The script compares one pooled model with separate
models selected by the gateway's known protocol. Protocol is never included
in the feature vector.

The split is explicit and run-safe:
  * --csv-train      tunes model candidates
  * --csv-validation selects hyperparameters
  * --csv-test       is evaluated once after retraining on train+validation
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, balanced_accuracy_score,
                             classification_report, confusion_matrix,
                             f1_score, recall_score)
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).parent))
import train_and_export as trainlib


FINAL_CLASSES = ['EMERGENCY', 'IMPORTANT', 'NORMAL']
STAGE1_CLASSES = ['URGENT', 'NORMAL']
STAGE2_CLASSES = ['EMERGENCY', 'IMPORTANT']


def load_group(paths, first_run_id, title):
    print(f"\n{title}:")
    frames = [trainlib.load_csv(path, first_run_id + i)
              for i, path in enumerate(paths)]
    frame = pd.concat(frames, ignore_index=True)
    frame = trainlib.add_derived_features(frame)
    print(f"  Total: {len(frame)} rows from {len(frames)} runs")
    print('  Class counts by protocol:')
    print(pd.crosstab(frame['protocol'], frame[trainlib.TARGET])
          .reindex(columns=FINAL_CLASSES, fill_value=0).to_string())
    return frame


def feature_matrix(df):
    values = df[trainlib.FEATURES_BEHAVIOR20].to_numpy(dtype=np.float64)
    return np.nan_to_num(values, nan=0.0, posinf=10.0, neginf=-10.0)


def stage_labels(df, stage):
    labels = df[trainlib.TARGET].astype(str).to_numpy()
    if stage == 1:
        return np.where(labels == 'NORMAL', 'NORMAL', 'URGENT')
    return labels


def stage_frame(df, stage):
    if stage == 1:
        return df
    return df[df[trainlib.TARGET] != 'NORMAL']


def make_model(family, depth, leaf, trees=30):
    common = {
        'max_depth': int(depth),
        'min_samples_leaf': int(leaf),
        'class_weight': 'balanced',
        'random_state': 42,
    }
    if family == 'dt':
        return DecisionTreeClassifier(**common)
    return RandomForestClassifier(
        n_estimators=int(trees), n_jobs=-1, **common)


def candidate_score(model, x_train, y_train, x_validation, y_validation):
    pred_train = model.predict(x_train)
    pred_validation = model.predict(x_validation)
    train_acc = accuracy_score(y_train, pred_train)
    validation_acc = accuracy_score(y_validation, pred_validation)
    # Khoang cach tong quat hoa phai do bang CHINH do do dung de chon mo hinh.
    # Voi du lieu lech 100:1, accuracy luon ~0,99 bat ke mo hinh lam gi voi lop
    # thieu so, nen gap tinh theo accuracy khong bao gio phat hien duoc qua khop.
    f1_train = f1_score(y_train, pred_train, average='macro', zero_division=0)
    f1_validation = f1_score(y_validation, pred_validation,
                             average='macro', zero_division=0)
    return {
        'train_acc': float(train_acc),
        'validation_acc': float(validation_acc),
        'f1_train': float(f1_train),
        'gap_acc': float(train_acc - validation_acc),
        'gap': float(f1_train - f1_validation),
        'balanced_acc': float(balanced_accuracy_score(
            y_validation, pred_validation)),
        'f1_macro': float(f1_score(
            y_validation, pred_validation, average='macro',
            zero_division=0)),
    }


MAX_GAP = 0.10          # nguong loai qua khop, do tren F1 macro


def choose_row(frame, parameter_order, tolerance, n_folds=0):
    """Chon cau hinh don gian nhat khong kem dang ke so voi cau hinh tot nhat.

    Khi co kiem dinh cheo, bien do chap nhan duoc lay bang quy tac mot sai so
    chuan (Breiman et al. 1984): moi cau hinh co F1 macro nam trong 1 SE cua
    gia tri cao nhat deu khong phan biet duoc ve mat thong ke, nen chon cau
    hinh nho nhat trong so do.  Dung sai co dinh chi con la san duoi.
    """
    eligible = frame[frame['gap'] < MAX_GAP]
    if eligible.empty:
        eligible = frame
    peak_row = eligible.loc[eligible['f1_macro'].idxmax()]
    peak = float(peak_row['f1_macro'])
    margin = tolerance
    if n_folds > 1 and 'f1_macro_std' in eligible.columns:
        se = float(peak_row['f1_macro_std']) / np.sqrt(n_folds)
        margin = max(tolerance, se)
    near = eligible[eligible['f1_macro'] >= peak - margin]
    return near.sort_values(parameter_order).iloc[0]


def run_folds(df, n_folds):
    """Chia cac lan chay thanh n_folds nhom roi nhau, tra ve danh sach
    (chi_so_huan_luyen, chi_so_danh_gia). Chia theo run_id chu khong theo mau,
    vi cac mau trong cung mot lan chay khong doc lap voi nhau."""
    runs = sorted(df['run_id'].unique())
    if n_folds > len(runs):
        n_folds = len(runs)
    groups = [runs[i::n_folds] for i in range(n_folds)]
    folds = []
    for held in groups:
        if not held:
            continue
        mask = df['run_id'].isin(held).to_numpy()
        folds.append((~mask, mask))
    return folds


def candidate_score_cv(family, depth, leaf, trees, df, stage, folds):
    """Diem cua mot cau hinh, lay trung binh tren cac fold. Cac cot tra ve
    trung ten voi candidate_score de choose_row dung duoc chung mot ma."""
    x_all = feature_matrix(df)
    y_all = stage_labels(df, stage)
    rows = []
    for train_mask, eval_mask in folds:
        if len(set(y_all[train_mask])) < 2 or len(set(y_all[eval_mask])) < 2:
            continue
        model = make_model(family, depth, leaf, trees)
        model.fit(x_all[train_mask], y_all[train_mask])
        rows.append(candidate_score(model, x_all[train_mask], y_all[train_mask],
                                    x_all[eval_mask], y_all[eval_mask]))
    if not rows:
        return None
    keys = rows[0].keys()
    out = {k: float(np.mean([r[k] for r in rows])) for k in keys}
    out['f1_macro_std'] = float(np.std([r['f1_macro'] for r in rows]))
    out['n_folds'] = len(rows)
    return out


def oof_probability(df, stage, config, folds, class_name):
    """Xac suat out-of-fold cho tung mau: moi mau duoc du doan boi mo hinh
    KHONG nhin thay lan chay cua no. Dung de quet nguong khong thien vi."""
    x_all = feature_matrix(df)
    y_all = stage_labels(df, stage)
    out = np.zeros(len(df), dtype=float)
    for train_mask, eval_mask in folds:
        if len(set(y_all[train_mask])) < 2:
            continue
        model = make_model(config['family'], config['depth'],
                          config['leaf'], config['trees'])
        model.fit(x_all[train_mask], y_all[train_mask])
        out[eval_mask] = class_probability(model, x_all[eval_mask], class_name)
    return out


def tune_stage(train_df, validation_df, stage, family, depths, trees,
               leaf, tolerance, prefix, out_dir, cv_folds=0):
    train_stage = stage_frame(train_df, stage)
    validation_stage = stage_frame(validation_df, stage)
    classes = STAGE1_CLASSES if stage == 1 else STAGE2_CLASSES
    missing_train = sorted(set(classes) -
                           set(stage_labels(train_stage, stage)))
    missing_validation = sorted(set(classes) -
                                set(stage_labels(validation_stage, stage)))
    if missing_train or missing_validation:
        print(f"  SKIP {prefix} stage {stage}: missing train={missing_train}, "
              f"validation={missing_validation}")
        return None

    x_train = feature_matrix(train_stage)
    y_train = stage_labels(train_stage, stage)
    x_validation = feature_matrix(validation_stage)
    y_validation = stage_labels(validation_stage, stage)
    rows = []

    if cv_folds > 0:
        # Kiem dinh cheo theo lan chay tren hop cua train + validation.
        pooled = pd.concat([train_stage, validation_stage], ignore_index=True)
        folds = run_folds(pooled, cv_folds)
        if family == 'dt':
            for depth in depths:
                score = candidate_score_cv('dt', depth, leaf, 1,
                                            pooled, stage, folds)
                if score is None:
                    continue
                score.update(depth=int(depth), trees=1, leaf=int(leaf))
                rows.append(score)
        else:
            # Buoc do sau dung F1 CAO NHAT (khong ap 1-SE) de khong thu nho mo
            # hinh truoc khi biet so cay anh huong the nao.
            probe_trees = 30 if 30 in trees else int(trees[0])
            depth_rows = []
            for depth in depths:
                score = candidate_score_cv('rf', depth, leaf, probe_trees,
                                            pooled, stage, folds)
                if score is None:
                    continue
                score.update(depth=int(depth), trees=probe_trees,
                             leaf=int(leaf), sweep='depth')
                depth_rows.append(score)
            selected_depth = int(pd.DataFrame(depth_rows)
                                 .sort_values('f1_macro').iloc[-1]['depth'])
            rows.extend(depth_rows)
            for count in trees:
                if count == probe_trees:
                    continue
                score = candidate_score_cv('rf', selected_depth, leaf, count,
                                            pooled, stage, folds)
                if score is None:
                    continue
                score.update(depth=selected_depth, trees=int(count),
                             leaf=int(leaf), sweep='trees')
                rows.append(score)

        # Ap quy tac 1-SE DUNG MOT LAN tren hop cac cau hinh da danh gia.  Ap
        # hai lan noi tiep (do sau roi so cay) lam sai so lui cong don.  Do
        # phuc tap lay bang trees x depth, dung bang so phep so sanh khi suy
        # luan, nen viec chon mo hinh gan truc tiep voi chi phi trien khai.
        sweep = pd.DataFrame(rows)
        sweep['complexity'] = sweep['trees'] * sweep['depth']
        choice = choose_row(sweep, ['complexity', 'depth'], tolerance, cv_folds)
        sweep.to_csv(out_dir / f'{prefix}_stage{stage}_{family}_sweep.csv',
                     index=False)
        config = {
            'family': family,
            'depth': int(choice['depth']),
            'trees': int(choice['trees']),
            'leaf': int(choice['leaf']),
            'validation_f1_macro': float(choice['f1_macro']),
            'validation_f1_macro_std': float(choice.get('f1_macro_std', 0.0)),
            'validation_balanced_acc': float(choice['balanced_acc']),
            'cv_folds': int(choice.get('n_folds', cv_folds)),
        }
        print(f"  {prefix:>14} stage {stage} {family.upper()} [CV"
              f"{config['cv_folds']}]: depth={config['depth']}, "
              f"trees={config['trees']}, macro-F1="
              f"{config['validation_f1_macro']:.4f} "
              f"+/- {config['validation_f1_macro_std']:.4f}")
        return config

    if family == 'dt':
        for depth in depths:
            model = make_model('dt', depth, leaf)
            model.fit(x_train, y_train)
            score = candidate_score(
                model, x_train, y_train, x_validation, y_validation)
            score.update(depth=int(depth), trees=1, leaf=int(leaf))
            rows.append(score)
    else:
        # First select depth with a small, stable forest, then select tree count.
        probe_trees = 30 if 30 in trees else int(trees[0])
        depth_rows = []
        for depth in depths:
            model = make_model('rf', depth, leaf, probe_trees)
            model.fit(x_train, y_train)
            score = candidate_score(
                model, x_train, y_train, x_validation, y_validation)
            score.update(depth=int(depth), trees=probe_trees, leaf=int(leaf),
                         sweep='depth')
            depth_rows.append(score)
        depth_frame = pd.DataFrame(depth_rows)
        depth_choice = choose_row(
            depth_frame, ['depth'], tolerance)
        selected_depth = int(depth_choice['depth'])
        rows.extend(depth_rows)
        for count in trees:
            model = make_model('rf', selected_depth, leaf, count)
            model.fit(x_train, y_train)
            score = candidate_score(
                model, x_train, y_train, x_validation, y_validation)
            score.update(depth=selected_depth, trees=int(count), leaf=int(leaf),
                         sweep='trees')
            rows.append(score)

    sweep = pd.DataFrame(rows)
    sweep_path = out_dir / f'{prefix}_stage{stage}_{family}_sweep.csv'
    sweep.to_csv(sweep_path, index=False)
    if family == 'dt':
        choice = choose_row(sweep, ['depth'], tolerance)
    else:
        tree_sweep = sweep[sweep['sweep'] == 'trees']
        choice = choose_row(tree_sweep, ['trees'], tolerance)

    config = {
        'family': family,
        'depth': int(choice['depth']),
        'trees': int(choice['trees']),
        'leaf': int(choice['leaf']),
        'validation_f1_macro': float(choice['f1_macro']),
        'validation_balanced_acc': float(choice['balanced_acc']),
    }
    print(f"  {prefix:>14} stage {stage} {family.upper()}: "
          f"depth={config['depth']}, trees={config['trees']}, "
          f"macro-F1={config['validation_f1_macro']:.4f}")
    return config


def fit_stage(df, stage, config):
    selected = stage_frame(df, stage)
    classes = STAGE1_CLASSES if stage == 1 else STAGE2_CLASSES
    labels = stage_labels(selected, stage)
    if sorted(set(labels)) != sorted(classes):
        return None
    model = make_model(config['family'], config['depth'], config['leaf'],
                       config['trees'])
    model.fit(feature_matrix(selected), labels)
    return model


def class_probability(model, x, class_name):
    indices = np.flatnonzero(model.classes_ == class_name)
    if len(indices) != 1:
        raise ValueError(f'Model does not contain class {class_name}')
    return model.predict_proba(x)[:, int(indices[0])]


def predict_hierarchy(df, stage1_model, stage2_model,
                      urgent_threshold=0.5, emergency_threshold=0.5):
    x = feature_matrix(df)
    urgent_probability = class_probability(stage1_model, x, 'URGENT')
    final = np.full(len(df), 'NORMAL', dtype=object)
    urgent_idx = np.flatnonzero(urgent_probability >= urgent_threshold)
    if len(urgent_idx) and stage2_model is not None:
        emergency_probability = class_probability(
            stage2_model, x[urgent_idx], 'EMERGENCY')
        final[urgent_idx] = np.where(
            emergency_probability >= emergency_threshold,
            'EMERGENCY', 'IMPORTANT')
    elif len(urgent_idx):
        final[urgent_idx] = 'EMERGENCY'
    return final


def tune_thresholds(train_df, validation_df, stage1_config, stage2_config,
                    urgent_thresholds, emergency_thresholds,
                    min_emergency_recall, prefix, out_dir):
    stage1_model = fit_stage(train_df, 1, stage1_config)
    stage2_model = (fit_stage(train_df, 2, stage2_config)
                    if stage2_config is not None else None)
    if stage1_model is None or stage2_model is None:
        return {
            'urgent_threshold': 0.5,
            'emergency_threshold': 0.5,
            'validation_f1_macro': 0.0,
            'validation_emergency_recall': 0.0,
        }

    truth = validation_df[trainlib.TARGET].astype(str).to_numpy()
    rows = []
    for urgent_threshold in urgent_thresholds:
        for emergency_threshold in emergency_thresholds:
            prediction = predict_hierarchy(
                validation_df, stage1_model, stage2_model,
                urgent_threshold, emergency_threshold)
            rows.append({
                'urgent_threshold': float(urgent_threshold),
                'emergency_threshold': float(emergency_threshold),
                'f1_macro': float(f1_score(
                    truth, prediction, labels=FINAL_CLASSES,
                    average='macro', zero_division=0)),
                'balanced_acc': float(recall_score(
                    truth, prediction, labels=FINAL_CLASSES,
                    average='macro', zero_division=0)),
                'emergency_recall': float(recall_score(
                    truth, prediction, labels=['EMERGENCY'],
                    average='macro', zero_division=0)),
                'important_recall': float(recall_score(
                    truth, prediction, labels=['IMPORTANT'],
                    average='macro', zero_division=0)),
                'normal_recall': float(recall_score(
                    truth, prediction, labels=['NORMAL'],
                    average='macro', zero_division=0)),
            })

    sweep = pd.DataFrame(rows)
    sweep.to_csv(out_dir / f'{prefix}_threshold_sweep.csv', index=False)
    eligible = sweep[sweep['emergency_recall'] >= min_emergency_recall]
    if eligible.empty:
        eligible = sweep
        print(f"  {prefix}: no threshold meets EMERGENCY recall >= "
              f"{min_emergency_recall:.2f}; using best macro-F1")
    choice = eligible.sort_values(
        ['f1_macro', 'emergency_recall', 'normal_recall',
         'urgent_threshold'],
        ascending=[False, False, False, False]).iloc[0]
    result = {
        'urgent_threshold': float(choice['urgent_threshold']),
        'emergency_threshold': float(choice['emergency_threshold']),
        'validation_f1_macro': float(choice['f1_macro']),
        'validation_balanced_acc': float(choice['balanced_acc']),
        'validation_emergency_recall': float(choice['emergency_recall']),
    }
    print(f"  {prefix:>14} thresholds: urgent>="
          f"{result['urgent_threshold']:.2f}, emergency>="
          f"{result['emergency_threshold']:.2f}, composed macro-F1="
          f"{result['validation_f1_macro']:.4f}, EMERGENCY recall="
          f"{result['validation_emergency_recall']:.4f}")
    return result


def print_evaluation(name, truth, prediction):
    print(f"\n--- {name} final held-out test ---")
    print(classification_report(
        truth, prediction, labels=FINAL_CLASSES,
        target_names=FINAL_CLASSES, zero_division=0, digits=4))
    matrix = confusion_matrix(truth, prediction, labels=FINAL_CLASSES)
    print('Confusion matrix (rows=true, cols=pred):')
    print(f"             {'  '.join(f'{c:>9}' for c in FINAL_CLASSES)}")
    for label, row in zip(FINAL_CLASSES, matrix):
        print(f"  {label:>9}  {'  '.join(f'{v:>9}' for v in row)}")
    report = classification_report(
        truth, prediction, labels=FINAL_CLASSES,
        target_names=FINAL_CLASSES, zero_division=0, output_dict=True)
    present_labels = sorted(set(truth))
    balanced = recall_score(
        truth, prediction, labels=present_labels, average='macro',
        zero_division=0)
    return {
        'accuracy': float(accuracy_score(truth, prediction)),
        'balanced_acc': float(balanced),
        'f1_macro': float(f1_score(
            truth, prediction, labels=FINAL_CLASSES, average='macro',
            zero_division=0)),
        'f1_emergency': float(report['EMERGENCY']['f1-score']),
        'f1_important': float(report['IMPORTANT']['f1-score']),
        'f1_normal': float(report['NORMAL']['f1-score']),
    }


def protocol_report(test_df, prediction, name, out_dir):
    rows = []
    truth = test_df[trainlib.TARGET].astype(str).to_numpy()
    print(f"\n{name} metrics by protocol:")
    for protocol in sorted(test_df['protocol'].astype(str).unique()):
        mask = test_df['protocol'].astype(str).to_numpy() == protocol
        protocol_truth = truth[mask]
        if set(protocol_truth) == {'NORMAL'}:
            normal_recall = float(np.mean(prediction[mask] == 'NORMAL'))
            print(f"  {protocol}: NORMAL-only in held-out test; urgency F1 is "
                  f"not applicable (NORMAL recall={normal_recall:.4f})")
            rows.append({
                'model': name, 'protocol': protocol, 'support': int(mask.sum()),
                'accuracy': normal_recall, 'balanced_acc': normal_recall,
                'f1_macro': np.nan, 'f1_emergency': np.nan,
                'f1_important': np.nan, 'f1_normal': normal_recall,
            })
            continue
        metrics = print_evaluation(
            f'{name} / {protocol}', protocol_truth, prediction[mask])
        metrics.update(model=name, protocol=protocol, support=int(mask.sum()))
        rows.append(metrics)
    pd.DataFrame(rows).to_csv(
        out_dir / f'{name}_metrics_by_protocol.csv', index=False)


def tune_scope(train_df, validation_df, scope, family, args, out_dir):
    configs = {}
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

    for protocol, (train_group, validation_group) in groups.items():
        prefix = f'{scope}_{protocol}'.replace('/', '_').replace(' ', '_')
        stage1 = tune_stage(
            train_group, validation_group, 1, family, args.depths,
            args.n_estimators, args.leaf, args.tolerance, prefix, out_dir)
        stage2 = tune_stage(
            train_group, validation_group, 2, family, args.depths,
            args.n_estimators, args.leaf, args.tolerance, prefix, out_dir)
        if stage1 is not None:
            thresholds = tune_thresholds(
                train_group, validation_group, stage1, stage2,
                args.urgent_thresholds, args.emergency_thresholds,
                args.min_emergency_recall, prefix, out_dir)
            configs[protocol] = {
                'stage1': stage1,
                'stage2': stage2,
                'thresholds': thresholds,
            }
    return configs


def fit_and_predict_scope(train_df, test_df, scope, configs):
    truth = test_df[trainlib.TARGET].astype(str).to_numpy()
    prediction = np.full(len(test_df), 'NORMAL', dtype=object)
    if scope == 'pooled':
        cfg = configs['ALL']
        model1 = fit_stage(train_df, 1, cfg['stage1'])
        model2 = fit_stage(train_df, 2, cfg['stage2'])
        thresholds = cfg.get('thresholds', {})
        return predict_hierarchy(
            test_df, model1, model2,
            thresholds.get('urgent_threshold', 0.5),
            thresholds.get('emergency_threshold', 0.5))

    for protocol in sorted(test_df['protocol'].astype(str).unique()):
        mask = test_df['protocol'].astype(str).to_numpy() == protocol
        if protocol not in configs:
            print(f"  {protocol}: no trainable urgent model; fallback NORMAL")
            continue
        train_group = train_df[train_df['protocol'].astype(str) == protocol]
        test_group = test_df.loc[mask]
        cfg = configs[protocol]
        model1 = fit_stage(train_group, 1, cfg['stage1'])
        model2 = (fit_stage(train_group, 2, cfg['stage2'])
                  if cfg['stage2'] is not None else None)
        thresholds = cfg.get('thresholds', {})
        prediction[mask] = predict_hierarchy(
            test_group, model1, model2,
            thresholds.get('urgent_threshold', 0.5),
            thresholds.get('emergency_threshold', 0.5))
    return prediction


def save_predictions(test_df, prediction, name, out_dir):
    columns = [column for column in
               ['run_id', 't_start', 'device_id', 'protocol', 'scenario',
                'message_kind', trainlib.TARGET]
               if column in test_df.columns]
    output = test_df[columns].copy()
    output['prediction'] = prediction
    output['correct'] = (
        output[trainlib.TARGET].astype(str).to_numpy() == prediction)
    output.to_csv(out_dir / f'{name}_predictions.csv', index=False)
    output[~output['correct']].to_csv(
        out_dir / f'{name}_errors.csv', index=False)


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
                        default=[3, 5, 8, 10, 12, 15])
    parser.add_argument('--n-estimators', nargs='+', type=int,
                        default=[10, 30, 50, 100])
    parser.add_argument('--leaf', type=int, default=10)
    parser.add_argument('--tolerance', type=float, default=0.005)
    parser.add_argument(
        '--urgent-thresholds', nargs='+', type=float,
        default=[0.50, 0.60, 0.70, 0.80, 0.90, 0.95],
        help='Stage-1 P(URGENT) thresholds selected on validation only')
    parser.add_argument(
        '--emergency-thresholds', nargs='+', type=float,
        default=[0.30, 0.40, 0.50, 0.60, 0.70],
        help='Stage-2 P(EMERGENCY) thresholds selected on validation only')
    parser.add_argument(
        '--min-emergency-recall', type=float, default=0.80,
        help='Validation recall floor used during threshold selection')
    args = parser.parse_args()

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    trainlib.FEATURES = trainlib.FEATURES_BEHAVIOR20

    train_df = load_group(args.csv_train, 1, 'Training runs')
    validation_df = load_group(
        args.csv_validation, 100, 'Validation runs')
    test_df = load_group(args.csv_test, 200, 'Final test runs')
    fit_df = pd.concat([train_df, validation_df], ignore_index=True)
    scopes = ['pooled', 'per-protocol'] if args.scope == 'both' else [args.scope]
    summary = []

    for scope in scopes:
        for family in args.families:
            name = f'{scope}_{family}'
            print('\n' + '=' * 78)
            print(f'TUNING {name.upper()}')
            print('=' * 78)
            configs = tune_scope(
                train_df, validation_df, scope, family, args, out_dir)
            if not configs:
                print(f'No trainable configuration for {name}')
                continue
            (out_dir / f'{name}_config.json').write_text(
                json.dumps(configs, indent=2), encoding='utf-8')
            prediction = fit_and_predict_scope(
                fit_df, test_df, scope, configs)
            truth = test_df[trainlib.TARGET].astype(str).to_numpy()
            metrics = print_evaluation(name, truth, prediction)
            metrics.update(model=name, support=len(test_df))
            summary.append(metrics)
            protocol_report(test_df, prediction, name, out_dir)
            save_predictions(test_df, prediction, name, out_dir)

    summary_df = pd.DataFrame(summary).sort_values(
        ['f1_macro', 'balanced_acc'], ascending=False)
    summary_df.to_csv(out_dir / 'summary.csv', index=False)
    print('\n' + '=' * 78)
    print('FINAL TEST SUMMARY (selected configs came from validation only)')
    print('=' * 78)
    if summary_df.empty:
        print('No model completed.')
    else:
        print(summary_df[[
            'model', 'f1_macro', 'balanced_acc', 'f1_emergency',
            'f1_important', 'f1_normal']].to_string(index=False))
        print(f"\nSaved results to: {out_dir}")


if __name__ == '__main__':
    main()
