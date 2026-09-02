#!/usr/bin/env python3
"""Generate every figure and numeric table used in the DT/RF evaluation.

The script reads artefacts that already exist after the offline pipeline has
been run (feature CSVs, tuning sweeps, exported model manifest) plus optional
runtime diagnostics CSVs produced by the ns-3 program, and writes:

  <out>/figs/*.png      one file per figure referenced in the report
  <out>/tables/*.csv    the numbers behind every table in the report

Every stage is skipped with a printed reason when its inputs are missing, so
the script is safe to run before the full pipeline has been executed.
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score)

import train_and_export as trainlib
import tune_hierarchical as hier

PROTOCOLS = ['DNP3', 'IEC104', 'OPC-UA']
FAMILIES = ['dt', 'rf']
FAMILY_NAME = {'dt': 'Decision Tree', 'rf': 'Random Forest'}
BINARY_CLASSES = ['URGENT', 'NORMAL']
FINAL_CLASSES = ['EMERGENCY', 'IMPORTANT', 'NORMAL']

FEATURE_GROUP = {
    'current_pkt_size': 'N1 kich thuoc',
    'avg_pkt_size': 'N1 kich thuoc',
    'max_pkt_size': 'N1 kich thuoc',
    'pkt_size_std': 'N1 kich thuoc',
    'pkt_size_entropy': 'N1 kich thuoc',
    'inter_arrival_mean': 'N2 thoi gian den',
    'inter_arrival_min': 'N2 thoi gian den',
    'inter_arrival_std': 'N2 thoi gian den',
    'time_since_last_pkt': 'N2 thoi gian den',
    'pkt_count_1s': 'N3 cuong do',
    'burst_count_100ms': 'N3 cuong do',
    'burst_count_500ms': 'N3 cuong do',
    'short_long_rate_ratio': 'N3 cuong do',
    'pkt_rate_delta': 'N3 cuong do',
    'current_size_baseline_ratio': 'N4 duong co so',
    'current_size_zscore': 'N4 duong co so',
    'silent_gap_ratio': 'N4 duong co so',
    'baseline_pkt_rate_zscore': 'N4 duong co so',
    'baseline_size_zscore': 'N4 duong co so',
    'uplink_downlink_ratio': 'N5 hai chieu',
}
GROUP_COLOR = {
    'N1 kich thuoc': '#4E79A7',
    'N2 thoi gian den': '#F28E2B',
    'N3 cuong do': '#E15759',
    'N4 duong co so': '#59A14F',
    'N5 hai chieu': '#9C755F',
}


def save(fig, out_dir, name):
    # Hyphens, not underscores: an underscore in a filename passed to LaTeX
    # \includegraphics is a math-mode character and needs extra packages.
    path = out_dir / f"{name.replace('_', '-')}.png"
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)
    print(f'  figure -> {path}')


def dump(frame, out_dir, name):
    path = out_dir / f'{name}.csv'
    frame.to_csv(path, index=False)
    print(f'  table  -> {path}')


def draw_confusion(ax, matrix, labels, title):
    ax.imshow(matrix, cmap='Blues')
    ax.set_xticks(range(len(labels)), labels, rotation=20)
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel('Du doan')
    ax.set_ylabel('Nhan dung')
    ax.set_title(title)
    total = matrix.sum()
    limit = matrix.max() / 2 if matrix.max() else 1
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            value = matrix[i, j]
            share = 100.0 * value / total if total else 0.0
            ax.text(j, i, f'{value:,}\n{share:.2f}%', ha='center',
                    va='center', fontsize=9,
                    color='white' if value > limit else 'black')


# ---------------------------------------------------------------------------
#  Figure 1 + Table 1: dataset composition
# ---------------------------------------------------------------------------
def dataset_overview(train_paths, validation_paths, test_paths, figs, tables):
    print('\n[1] Dataset composition')
    groups = {}
    if train_paths:
        groups['Huan luyen'] = hier.load_group(train_paths, 1, 'Train')
    if validation_paths:
        groups['Kiem dinh'] = hier.load_group(validation_paths, 100, 'Validation')
    if test_paths:
        groups['Kiem tra'] = hier.load_group(test_paths, 200, 'Test')
    if not groups:
        print('  skipped: no feature CSV given')
        return None

    rows = []
    for split, frame in groups.items():
        for protocol, block in frame.groupby('protocol'):
            counts = block[trainlib.TARGET].value_counts()
            urgent = int(counts.get('EMERGENCY', 0) + counts.get('IMPORTANT', 0))
            normal = int(counts.get('NORMAL', 0))
            rows.append({
                'split': split,
                'protocol': str(protocol),
                'runs': int(block['run_id'].nunique()),
                'messages': int(len(block)),
                'normal': normal,
                'important': int(counts.get('IMPORTANT', 0)),
                'emergency': int(counts.get('EMERGENCY', 0)),
                'urgent': urgent,
                'urgent_ratio_pct': round(100.0 * urgent / max(len(block), 1), 3),
                'imbalance_ratio': round(normal / max(urgent, 1), 1),
            })
    summary = pd.DataFrame(rows)
    dump(summary, tables, 't1_dataset_composition')

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2))
    pivot = (summary.groupby(['split', 'protocol'])['messages'].sum()
             .unstack('protocol').fillna(0))
    pivot.plot(kind='bar', ax=axes[0], rot=0)
    axes[0].set_ylabel('So ban tin')
    axes[0].set_title('(a) So ban tin theo tap va giao thuc')
    axes[0].legend(fontsize=8)

    ratio = (summary.groupby(['split', 'protocol'])
             .apply(lambda g: 100.0 * g['urgent'].sum() /
                    max(g['messages'].sum(), 1), include_groups=False)
             .unstack('protocol').fillna(0))
    ratio.plot(kind='bar', ax=axes[1], rot=0)
    axes[1].set_ylabel('Ti le URGENT (%)')
    axes[1].set_title('(b) Ti le lop URGENT')
    axes[1].legend(fontsize=8)
    save(fig, figs, 'fig1_class_distribution')
    return groups


# ---------------------------------------------------------------------------
#  Figures 2-3: hyper-parameter sweeps
# ---------------------------------------------------------------------------
def sweep_figures(tune_dir, figs, tables):
    print('\n[2] Hyper-parameter sweeps')
    depth_rows, tree_rows = [], []
    for family in FAMILIES:
        for protocol in PROTOCOLS:
            stem = f'binary_per-protocol_{protocol}_{family}'
            path = tune_dir / f'{stem}_stage1_{family}_sweep.csv'
            if not path.exists():
                print(f'  missing {path.name}')
                continue
            frame = pd.read_csv(path)
            frame['protocol'] = protocol
            frame['family'] = family
            if 'sweep' in frame.columns:
                depth_rows.append(frame[frame['sweep'] == 'depth'])
                tree_rows.append(frame[frame['sweep'] == 'trees'])
            else:
                depth_rows.append(frame)
    if not depth_rows:
        print('  skipped: no sweep CSV found')
        return

    depth = pd.concat(depth_rows, ignore_index=True)
    dump(depth, tables, 't2_depth_sweep')
    fig, axes = plt.subplots(2, 3, figsize=(13, 7), sharex=True)
    for r, family in enumerate(FAMILIES):
        for c, protocol in enumerate(PROTOCOLS):
            ax = axes[r][c]
            block = depth[(depth['family'] == family) &
                          (depth['protocol'] == protocol)].sort_values('depth')
            if block.empty:
                ax.set_visible(False)
                continue
            ax.plot(block['depth'], block['f1_macro'], 'o-', label='F1 macro')
            ax.plot(block['depth'], block['gap'], 's--',
                    label='Khoang cach tong quat hoa')
            peak = block['f1_macro'].max()
            ax.axhline(peak - 0.005, color='grey', ls=':',
                       label='Nguong dung sai 0,005')
            ax.axhline(0.05, color='red', ls=':', lw=0.8)
            ax.set_title(f'{FAMILY_NAME[family]} / {protocol}', fontsize=10)
            ax.set_xlabel('Do sau')
            if c == 0:
                ax.set_ylabel('Gia tri')
            if r == 0 and c == 0:
                ax.legend(fontsize=7)
    save(fig, figs, 'fig2_depth_sweep')

    if tree_rows:
        trees = pd.concat(tree_rows, ignore_index=True)
        dump(trees, tables, 't3_trees_sweep')
        fig, axes = plt.subplots(1, 3, figsize=(13, 3.8))
        for c, protocol in enumerate(PROTOCOLS):
            ax = axes[c]
            block = trees[trees['protocol'] == protocol].sort_values('trees')
            if block.empty:
                ax.set_visible(False)
                continue
            ax.plot(block['trees'], block['f1_macro'], 'o-')
            peak = block['f1_macro'].max()
            ax.axhline(peak - 0.005, color='grey', ls=':',
                       label='Nguong dung sai 0,005')
            ax.set_title(f'Random Forest / {protocol}', fontsize=10)
            ax.set_xlabel('So cay')
            if c == 0:
                ax.set_ylabel('F1 macro')
            ax.legend(fontsize=7)
        save(fig, figs, 'fig3_trees_sweep')


# ---------------------------------------------------------------------------
#  Figure 4 + Table: threshold sweep
# ---------------------------------------------------------------------------
def threshold_figures(tune_dir, min_recall, figs, tables):
    print('\n[3] Threshold sweeps')
    frames, chosen = [], []
    for family in FAMILIES:
        config_path = tune_dir / f'binary_per-protocol_{family}_config.json'
        configs = (json.loads(config_path.read_text(encoding='utf-8'))
                   if config_path.exists() else {})
        for protocol in PROTOCOLS:
            path = (tune_dir /
                    f'binary_per-protocol_{protocol}_{family}'
                    f'_binary_threshold_sweep.csv')
            if not path.exists():
                print(f'  missing {path.name}')
                continue
            frame = pd.read_csv(path)
            frame['protocol'] = protocol
            frame['family'] = family
            frames.append(frame)
            if protocol in configs:
                entry = configs[protocol]
                chosen.append({
                    'family': family,
                    'protocol': protocol,
                    'depth': entry['model']['depth'],
                    'trees': entry['model']['trees'],
                    'leaf': entry['model']['leaf'],
                    'threshold': entry['threshold']['urgent_threshold'],
                    'validation_f1_macro':
                        entry['threshold']['validation_f1_macro'],
                    'validation_urgent_recall':
                        entry['threshold']['validation_urgent_recall'],
                })
    if not frames:
        print('  skipped: no threshold sweep CSV found')
        return
    sweep = pd.concat(frames, ignore_index=True)
    dump(sweep, tables, 't4_threshold_sweep')
    if chosen:
        dump(pd.DataFrame(chosen), tables, 't5_selected_config')

    picked = {(row['family'], row['protocol']): row['threshold']
              for row in chosen}
    fig, axes = plt.subplots(2, 3, figsize=(13, 7), sharex=True)
    for r, family in enumerate(FAMILIES):
        for c, protocol in enumerate(PROTOCOLS):
            ax = axes[r][c]
            block = sweep[(sweep['family'] == family) &
                          (sweep['protocol'] == protocol)]
            block = block.sort_values('urgent_threshold')
            if block.empty:
                ax.set_visible(False)
                continue
            ax.plot(block['urgent_threshold'], block['urgent_recall'],
                    'o-', label='Recall URGENT')
            ax.plot(block['urgent_threshold'], block['f1_macro'],
                    's-', label='F1 macro')
            ax.axhline(min_recall, color='red', ls='--', lw=1,
                       label=f'Rang buoc r_min={min_recall}')
            key = (family, protocol)
            if key in picked:
                ax.axvline(picked[key], color='green', ls='-.', lw=1.2,
                           label=f'tau = {picked[key]:.2f}')
            ax.set_title(f'{FAMILY_NAME[family]} / {protocol}', fontsize=10)
            ax.set_xlabel('Nguong tau')
            if c == 0:
                ax.set_ylabel('Gia tri')
            ax.legend(fontsize=7, loc='lower left')
    save(fig, figs, 'fig4_threshold_sweep')


# ---------------------------------------------------------------------------
#  Figures 5-6 + Tables: offline test-set results
# ---------------------------------------------------------------------------
def offline_results(tune_dir, figs, tables):
    print('\n[4] Offline test-set results')
    summary_path = tune_dir / 'binary_summary.csv'
    if summary_path.exists():
        dump(pd.read_csv(summary_path), tables, 't6_test_summary')

    per_protocol = []
    for scope in ['per-protocol', 'pooled']:
        for family in FAMILIES:
            path = (tune_dir /
                    f'binary_{scope}_{family}_binary_metrics_by_protocol.csv')
            if path.exists():
                frame = pd.read_csv(path)
                frame['scope'] = scope
                frame['family'] = family
                per_protocol.append(frame)
    if per_protocol:
        merged = pd.concat(per_protocol, ignore_index=True)
        dump(merged, tables, 't7_test_by_protocol')
        fig, axes = plt.subplots(1, 3, figsize=(13, 3.9))
        for ax, metric, title in zip(
                axes, ['f1_macro', 'f1_urgent', 'urgent_recall'],
                ['F1 macro', 'F1 lop URGENT', 'Recall lop URGENT']):
            pivot = (merged.assign(
                        model=merged['scope'] + ' / ' + merged['family'])
                     .pivot_table(index='protocol', columns='model',
                                  values=metric))
            pivot.plot(kind='bar', ax=ax, rot=0, legend=(ax is axes[0]))
            low = float(np.nanmin(pivot.to_numpy()))
            ax.set_ylim(max(0.0, min(0.8, low - 0.05)), 1.02)
            ax.axhline(1.0, color='grey', lw=0.6, ls=':')
            ax.set_title(title, fontsize=10)
            ax.set_ylabel(metric)
            if ax is axes[0]:
                ax.legend(fontsize=7)
        save(fig, figs, 'fig6_f1_by_protocol')

    matrices = {}
    for family in FAMILIES:
        path = (tune_dir /
                f'binary_per-protocol_{family}_binary_predictions.csv')
        if not path.exists():
            print(f'  missing {path.name}')
            continue
        frame = pd.read_csv(path)
        matrices[family] = frame
    if matrices:
        fig, axes = plt.subplots(1, len(matrices),
                                 figsize=(5.2 * len(matrices), 4.3))
        axes = np.atleast_1d(axes)
        rows = []
        for ax, (family, frame) in zip(axes, matrices.items()):
            matrix = confusion_matrix(frame['binary_truth'],
                                      frame['prediction'],
                                      labels=BINARY_CLASSES)
            draw_confusion(ax, matrix, BINARY_CLASSES,
                           f'{FAMILY_NAME[family]} (ngoai tuyen)')
            tp, fn, fp, tn = matrix.ravel()
            rows.append({
                'family': family, 'TP': int(tp), 'FN': int(fn),
                'FP': int(fp), 'TN': int(tn),
                'precision_urgent': round(tp / max(tp + fp, 1), 6),
                'recall_urgent': round(tp / max(tp + fn, 1), 6),
                'f1_urgent': round(2 * tp / max(2 * tp + fp + fn, 1), 6),
                'accuracy': round((tp + tn) / max(matrix.sum(), 1), 6),
            })
        save(fig, figs, 'fig5_confusion_binary')
        dump(pd.DataFrame(rows), tables, 't8_confusion_binary')

        error_rows = []
        for family in FAMILIES:
            path = (tune_dir /
                    f'binary_per-protocol_{family}_binary_errors.csv')
            if not path.exists():
                continue
            frame = pd.read_csv(path)
            if frame.empty:
                continue
            grouped = (frame.groupby(['protocol', 'binary_truth',
                                      'message_kind'])
                       .size().reset_index(name='count'))
            grouped['family'] = family
            error_rows.append(grouped)
        if error_rows:
            dump(pd.concat(error_rows, ignore_index=True),
                 tables, 't9_error_breakdown')


# ---------------------------------------------------------------------------
#  Figures 7-8: feature importance and score separability
# ---------------------------------------------------------------------------
def model_analysis(tune_dir, train_groups, figs, tables, permutation):
    print('\n[5] Feature importance and score separability')
    if not train_groups or 'Huan luyen' not in train_groups:
        print('  skipped: training features not given')
        return
    fit_df = train_groups['Huan luyen']
    if 'Kiem dinh' in train_groups:
        fit_df = pd.concat([fit_df, train_groups['Kiem dinh']],
                           ignore_index=True)
    test_df = train_groups.get('Kiem tra')

    importance_rows, score_rows, models = [], [], {}
    for family in FAMILIES:
        config_path = tune_dir / f'binary_per-protocol_{family}_config.json'
        if not config_path.exists():
            print(f'  missing {config_path.name}')
            continue
        configs = json.loads(config_path.read_text(encoding='utf-8'))
        for protocol in PROTOCOLS:
            if protocol not in configs:
                continue
            block = fit_df[fit_df['protocol'].astype(str) == protocol]
            model = hier.fit_stage(block, 1, configs[protocol]['model'])
            if model is None:
                continue
            models[(family, protocol)] = (
                model, configs[protocol]['threshold']['urgent_threshold'])
            for name, value in zip(trainlib.FEATURES_BEHAVIOR20,
                                   model.feature_importances_):
                importance_rows.append({
                    'family': family, 'protocol': protocol,
                    'feature': name, 'group': FEATURE_GROUP[name],
                    'gini_importance': float(value),
                })
            if permutation and test_df is not None:
                sub = test_df[test_df['protocol'].astype(str) == protocol]
                if len(sub) > 20000:
                    sub = sub.sample(20000, random_state=42)
                if not sub.empty:
                    result = permutation_importance(
                        model, hier.feature_matrix(sub),
                        hier.stage_labels(sub, 1), n_repeats=5,
                        random_state=42, scoring='f1_macro', n_jobs=-1)
                    for name, value in zip(trainlib.FEATURES_BEHAVIOR20,
                                           result.importances_mean):
                        importance_rows.append({
                            'family': family, 'protocol': protocol,
                            'feature': name, 'group': FEATURE_GROUP[name],
                            'permutation_importance': float(value),
                        })

    if importance_rows:
        importance = pd.DataFrame(importance_rows)
        dump(importance, tables, 't10_feature_importance')
        gini = importance.dropna(subset=['gini_importance'])
        fig, axes = plt.subplots(1, 3, figsize=(15, 5.6), sharey=False)
        for ax, protocol in zip(axes, PROTOCOLS):
            block = (gini[(gini['protocol'] == protocol) &
                          (gini['family'] == 'rf')]
                     .sort_values('gini_importance', ascending=True).tail(12))
            if block.empty:
                ax.set_visible(False)
                continue
            colors = [GROUP_COLOR[g] for g in block['group']]
            ax.barh(block['feature'], block['gini_importance'], color=colors)
            ax.set_title(f'Random Forest / {protocol}', fontsize=10)
            ax.set_xlabel('Muc quan trong Gini')
            ax.tick_params(axis='y', labelsize=7)
        handles = [plt.Rectangle((0, 0), 1, 1, color=c)
                   for c in GROUP_COLOR.values()]
        fig.legend(handles, list(GROUP_COLOR), loc='lower center',
                   ncol=5, fontsize=8)
        fig.tight_layout(rect=(0, 0.09, 1, 1))
        path = figs / 'fig7-feature-importance.png'
        fig.savefig(path, dpi=200)
        plt.close(fig)
        print(f'  figure -> {path}')

        grouped = (gini.groupby(['family', 'protocol', 'group'])
                   ['gini_importance'].sum().reset_index())
        dump(grouped, tables, 't11_importance_by_group')

    if models and test_df is not None:
        fig, axes = plt.subplots(2, 3, figsize=(13, 7))
        for r, family in enumerate(FAMILIES):
            for c, protocol in enumerate(PROTOCOLS):
                ax = axes[r][c]
                key = (family, protocol)
                if key not in models:
                    ax.set_visible(False)
                    continue
                model, threshold = models[key]
                sub = test_df[test_df['protocol'].astype(str) == protocol]
                if sub.empty:
                    ax.set_visible(False)
                    continue
                probability = hier.class_probability(
                    model, hier.feature_matrix(sub), 'URGENT')
                truth = hier.stage_labels(sub, 1)
                bins = np.linspace(0, 1, 41)
                ax.hist(probability[truth == 'NORMAL'], bins=bins, log=True,
                        alpha=0.65, label='Nhan dung NORMAL')
                ax.hist(probability[truth == 'URGENT'], bins=bins, log=True,
                        alpha=0.65, label='Nhan dung URGENT')
                ax.axvline(threshold, color='green', ls='-.',
                           label=f'tau = {threshold:.2f}')
                ax.set_title(f'{FAMILY_NAME[family]} / {protocol}', fontsize=10)
                ax.set_xlabel('Diem s_urgent')
                if c == 0:
                    ax.set_ylabel('So ban tin (log)')
                if r == 0 and c == 0:
                    ax.legend(fontsize=7)
                for name, low, high in [('below', 0.0, threshold),
                                        ('above', threshold, 1.01)]:
                    mask = (probability >= low) & (probability < high)
                    score_rows.append({
                        'family': family, 'protocol': protocol,
                        'side': name,
                        'normal': int(((truth == 'NORMAL') & mask).sum()),
                        'urgent': int(((truth == 'URGENT') & mask).sum()),
                    })
        save(fig, figs, 'fig8_score_distribution')
        if score_rows:
            dump(pd.DataFrame(score_rows), tables, 't12_score_split')


# ---------------------------------------------------------------------------
#  Figures 9-10 + Tables: runtime results inside ns-3
# ---------------------------------------------------------------------------
def runtime_results(runtime_paths, figs, tables):
    print('\n[6] Runtime results inside ns-3')
    frames = {}
    for family, path in runtime_paths.items():
        if path is None:
            continue
        path = Path(path)
        if not path.exists():
            print(f'  missing {path}')
            continue
        frame = pd.read_csv(path)
        frames[family] = frame
    if not frames:
        print('  skipped: no runtime CSV given')
        return

    binary_rows, class_rows, gate_rows, protocol_rows = [], [], [], []
    fig_b, axes_b = plt.subplots(1, len(frames),
                                 figsize=(5.2 * len(frames), 4.3))
    fig_c, axes_c = plt.subplots(1, len(frames),
                                 figsize=(5.6 * len(frames), 4.6))
    axes_b = np.atleast_1d(axes_b)
    axes_c = np.atleast_1d(axes_c)

    for idx, (family, frame) in enumerate(frames.items()):
        total = len(frame)
        gate_rows.append({
            'family': family,
            'uplink_messages': total,
            'protocol_messages': int((frame['message_kind'] == 'PROTOCOL').sum()),
            'baseline_not_ready': int((frame['baseline_ready'] == 0).sum()),
            'evaluated': int((frame['evaluated'] == 1).sum()),
            'evaluated_pct': round(100.0 * (frame['evaluated'] == 1).sum() /
                                   max(total, 1), 3),
        })
        graded = frame[frame['evaluated'] == 1]
        if graded.empty:
            continue

        matrix = confusion_matrix(graded['true_binary'],
                                 graded['pred_binary'],
                                 labels=BINARY_CLASSES)
        draw_confusion(axes_b[idx], matrix, BINARY_CLASSES,
                       f'{FAMILY_NAME[family]} (thoi gian chay)')
        tp, fn, fp, tn = matrix.ravel()
        binary_rows.append({
            'family': family, 'evaluated': int(len(graded)),
            'TP': int(tp), 'FN': int(fn), 'FP': int(fp), 'TN': int(tn),
            'precision_urgent': round(tp / max(tp + fp, 1), 6),
            'recall_urgent': round(tp / max(tp + fn, 1), 6),
            'f1_urgent': round(2 * tp / max(2 * tp + fp + fn, 1), 6),
            'f1_macro': round(f1_score(graded['true_binary'],
                                       graded['pred_binary'],
                                       labels=BINARY_CLASSES,
                                       average='macro', zero_division=0), 6),
            'accuracy': round((tp + tn) / max(matrix.sum(), 1), 6),
        })

        matrix3 = confusion_matrix(graded['true_traffic_class'],
                                  graded['pred_traffic_class'],
                                  labels=FINAL_CLASSES)
        draw_confusion(axes_c[idx], matrix3, FINAL_CLASSES,
                       f'{FAMILY_NAME[family]} (ba lop sau quy tac)')
        for cls in FINAL_CLASSES:
            class_rows.append({
                'family': family, 'traffic_class': cls,
                'support': int((graded['true_traffic_class'] == cls).sum()),
                'precision': round(precision_score(
                    graded['true_traffic_class'],
                    graded['pred_traffic_class'], labels=[cls],
                    average='macro', zero_division=0), 6),
                'recall': round(recall_score(
                    graded['true_traffic_class'],
                    graded['pred_traffic_class'], labels=[cls],
                    average='macro', zero_division=0), 6),
                'f1': round(f1_score(
                    graded['true_traffic_class'],
                    graded['pred_traffic_class'], labels=[cls],
                    average='macro', zero_division=0), 6),
            })

        for protocol, block in graded.groupby('protocol'):
            if block['true_binary'].nunique() < 2:
                protocol_rows.append({
                    'family': family, 'protocol': str(protocol),
                    'support': int(len(block)), 'f1_urgent': float('nan'),
                    'recall_urgent': float('nan'),
                    'note': 'khong co mau URGENT'})
                continue
            protocol_rows.append({
                'family': family, 'protocol': str(protocol),
                'support': int(len(block)),
                'f1_urgent': round(f1_score(
                    block['true_binary'], block['pred_binary'],
                    labels=['URGENT'], average='macro', zero_division=0), 6),
                'recall_urgent': round(recall_score(
                    block['true_binary'], block['pred_binary'],
                    labels=['URGENT'], average='macro', zero_division=0), 6),
                'note': '',
            })

    save(fig_b, figs, 'fig9_confusion_runtime_binary')
    save(fig_c, figs, 'fig10_confusion_runtime_3class')
    if gate_rows:
        dump(pd.DataFrame(gate_rows), tables, 't13_runtime_gating')
    if binary_rows:
        dump(pd.DataFrame(binary_rows), tables, 't14_runtime_binary')
    if class_rows:
        dump(pd.DataFrame(class_rows), tables, 't15_runtime_3class')
    if protocol_rows:
        dump(pd.DataFrame(protocol_rows), tables, 't16_runtime_by_protocol')

    fig, ax = plt.subplots(figsize=(7.5, 4))
    for family, frame in frames.items():
        graded = frame[frame['evaluated'] == 1].copy()
        if graded.empty:
            continue
        graded['bucket'] = (graded['t'] // 10) * 10
        series = (graded.groupby('bucket')['binary_correct'].mean() * 100)
        ax.plot(series.index, series.values, label=FAMILY_NAME[family])
    ax.set_xlabel('Thoi gian mo phong (s)')
    ax.set_ylabel('Ti le du doan dung (%)')
    ax.set_title('Do chinh xac nhi phan theo thoi gian mo phong')
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    save(fig, figs, 'fig11_accuracy_over_time')


# ---------------------------------------------------------------------------
#  Table: exported model cost
# ---------------------------------------------------------------------------
def model_cost(model_dir, tables):
    print('\n[7] Exported model cost')
    manifest_path = model_dir / 'scada_binary_manifest.json'
    if not manifest_path.exists():
        print(f'  skipped: {manifest_path} not found')
        return
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    stem = {'DNP3': 'dnp3', 'IEC104': 'iec104', 'OPC-UA': 'opcua'}
    rows = []
    for family, models in manifest['models'].items():
        for protocol, entry in models.items():
            header = model_dir / f'scada_binary_{family}_{stem[protocol]}.h'
            size_kb = (header.stat().st_size / 1024) if header.exists() else 0.0
            rows.append({
                'family': family, 'protocol': protocol,
                'depth': entry['depth'], 'trees': entry['trees'],
                'leaf': entry['leaf'], 'threshold': entry['threshold'],
                'header': header.name,
                'size_kb': round(size_kb, 1),
                'comparisons_worst_case': entry['depth'] * entry['trees'],
            })
    dump(pd.DataFrame(rows), tables, 't17_model_cost')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--features-train', nargs='*', default=[])
    ap.add_argument('--features-validation', nargs='*', default=[])
    ap.add_argument('--features-test', nargs='*', default=[])
    ap.add_argument('--tune-dir', required=True)
    ap.add_argument('--model-dir', default='scratch/scada')
    ap.add_argument('--runtime-dt')
    ap.add_argument('--runtime-rf')
    ap.add_argument('--min-urgent-recall', type=float, default=0.95)
    ap.add_argument('--permutation', action='store_true',
                    help='also compute permutation importance (slow)')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    trainlib.FEATURES = trainlib.FEATURES_BEHAVIOR20
    out = Path(args.out).expanduser().resolve()
    figs = out / 'figs'
    tables = out / 'tables'
    figs.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    tune_dir = Path(args.tune_dir).expanduser().resolve()

    groups = dataset_overview(args.features_train, args.features_validation,
                              args.features_test, figs, tables)
    sweep_figures(tune_dir, figs, tables)
    threshold_figures(tune_dir, args.min_urgent_recall, figs, tables)
    offline_results(tune_dir, figs, tables)
    model_analysis(tune_dir, groups, figs, tables, args.permutation)
    runtime_results({'dt': args.runtime_dt, 'rf': args.runtime_rf},
                    figs, tables)
    model_cost(Path(args.model_dir).expanduser().resolve(), tables)

    print(f'\nDone. Figures in {figs}, tables in {tables}')


if __name__ == '__main__':
    main()
