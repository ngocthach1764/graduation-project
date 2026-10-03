"""Frozen-model offline replay on the archived 3100--3114 benchmark.

No fitting, threshold tuning, model export, or end-to-end policy simulation.
"""
import argparse
import hashlib
import importlib.util
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

CLASSES = ['TIME_CRITICAL', 'OPERATIONAL', 'MONITORING']
SCENARIOS = [('all_clean_phases', 'clean', 1, 121),
             ('normal', 'clean', 1, 41), ('high_load', 'clean', 41, 81),
             ('emergency', 'clean', 81, 121), ('udp_flood', 'udp', 51, 71),
             ('routing_poison', 'poison', 51, 71), ('mixed', 'mixed', 51, 71)]


def sha256(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def matrix(truth, prediction):
    mapping = {name: index for index, name in enumerate(CLASSES)}
    actual = np.fromiter((mapping[c] for c in truth), dtype=int)
    assigned = np.fromiter((mapping[c] for c in prediction), dtype=int)
    return np.bincount(actual * 3 + assigned, minlength=9).reshape(3, 3)


def measures(confusion):
    total = int(confusion.sum())
    if total == 0:
        raise ValueError('Empty evaluation group')
    accuracy = 100 * np.trace(confusion) / total
    rows = []
    for index, name in enumerate(CLASSES):
        support = int(confusion[index].sum())
        predicted = int(confusion[:, index].sum())
        tp = int(confusion[index, index])
        rows.append(dict(service_class=name, support=support, predicted=predicted,
                         TP=tp, FP=predicted-tp, FN=support-tp,
                         precision_pct=100*tp/predicted if predicted else (0.0 if support else None),
                         recall_pct=100*tp/support if support else None,
                         f1_pct=200*tp/(support+predicted) if support+predicted else None,
                         accuracy_pct=float(accuracy)))
    active = [row for row in rows if row['support'] > 0]
    summary = dict(support=total, accuracy_pct=float(accuracy),
                   active_classes=len(active),
                   macro_precision_pct=float(np.mean([r['precision_pct'] for r in active])),
                   macro_recall_pct=float(np.mean([r['recall_pct'] for r in active])),
                   macro_f1_pct=float(np.mean([r['f1_pct'] for r in active])))
    return rows, summary


def explain_csv_rounding(model, sample, runtime_probability, features):
    """Require the same probability vector within six-decimal log precision."""
    result = []
    target = np.array([runtime_probability[c] for c in model.classes_])
    for index, feature in enumerate(features):
        for shift in (-.499e-6, .499e-6):
            values = sample.copy()
            values[index] += shift
            probability = model.predict_proba(values.reshape(1, -1))[0]
            if np.max(np.abs(probability-target)) <= .501e-6:
                result.append(dict(feature=feature, logged_value=float(sample[index]),
                                   compatible_value=float(values[index])))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--logs', type=Path, default=Path('output/final_clean_normal_15seed_20261003'))
    parser.add_argument('--candidate', type=Path, default=Path('output/service_split_70_15_15_20261003'))
    parser.add_argument('--out-dir', type=Path, default=Path('output/service_candidate_3100_3114_20261003'))
    parser.add_argument('--run-types', nargs='+', choices=['clean', 'udp', 'poison', 'mixed'],
                        default=['clean', 'udp', 'poison', 'mixed'])
    parser.add_argument('--allow-domain-shift', action='store_true')
    parser.add_argument('--allow-csv-rounding', action='store_true',
        help='Verify rare six-decimal feature-rounding differences, then use the logged C++ baseline decision')
    args = parser.parse_args()
    root = args.root.resolve()
    logs, candidate, out = [(root / path).resolve()
                            for path in (args.logs, args.candidate, args.out_dir)]
    if out in (logs, candidate):
        raise ValueError('Evaluation output must be separate from source data/models')
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('service_trainer', root / 'ml/train_service_classifier.py')
    trainer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trainer)
    locked = json.loads((candidate / 'locked_models.json').read_text())
    split = json.loads((candidate / 'split_manifest.json').read_text())
    log_manifest = json.loads((logs / 'manifest.json').read_text())
    trained_overlap = bool(split.get('iec104_service_overlap', False))
    observed_overlap = bool(log_manifest.get('iec104_service_overlap',
        '--iec104ServiceOverlap=1' in log_manifest.get('common_flags', [])))
    trained_behavior = bool(split.get('protocol_behavior', False))
    observed_behavior = bool(log_manifest.get('protocol_behavior',
        '--protocolBehavior=1' in log_manifest.get('common_flags', [])))
    trained_refresh = float(split.get('modbus_refresh_ms', 0)) if split.get('modbus_only') else 0.0
    observed_refresh = float(log_manifest.get('modbus_refresh_ms', 0))
    if trained_refresh != observed_refresh and not args.allow_domain_shift:
        raise ValueError('Modbus polling model differs from training; regenerate logs')
    if trained_behavior != observed_behavior and not args.allow_domain_shift:
        raise ValueError('Protocol behavior differs from training; regenerate logs')
    if trained_overlap != observed_overlap and not args.allow_domain_shift:
        raise ValueError('IEC-104 generator differs from training; regenerate logs or explicitly allow domain shift')
    scenarios = [item for item in SCENARIOS if item[1] in args.run_types]
    runs = list(range(3100, 3115))
    used = {run for values in split['runs'].values() for run in values}
    assert not used.intersection(runs), 'Benchmark overlaps train/validation/test runs'
    features = locked['rf']['features']
    assert features == list(trainer.FEATURES) == locked['dt']['features']
    baseline = json.loads((root / 'scratch/scada/scada_service_manifest.json').read_text())
    assert features == baseline['features']
    models, thresholds, hashes = {}, {}, {}
    for family in ('rf', 'dt'):
        paths = {'new_70_15_15': candidate / 'models' / f'{family}.pkl',
                 'current_50_25_25': root / 'output/modbus_scan_plan_20261002/models' / f'{family}21.pkl'}
        for version, path in paths.items():
            key = f'{family}_{version}'
            with path.open('rb') as stream:
                models[key] = pickle.load(stream)
            if split.get('modbus_only') and hasattr(models[key], 'n_jobs'):
                models[key].set_params(n_jobs=1)
            assert models[key].n_features_in_ == 21
            thresholds[key] = (locked[family]['thresholds'] if version.startswith('new')
                               else baseline['models'][family]['thresholds'])
            hashes[str(path)] = sha256(path)
    protected = list((root / 'scratch/scada').glob('scada_service_*.h')) + [
        root / 'scratch/scada/scada_service_manifest.json',
        root / 'scratch/scada/scada_ddos_rf.h', root / 'scratch/scada/rl_agent.h']
    before = {str(path): sha256(path) for path in protected if path.exists()}
    pooled, by_seed, inputs = {}, [], []
    parity_cases = []
    parity_rows = parity_mismatches = 0
    columns = features + ['t', 'protocol', 'evaluated', 'message_kind',
                          'true_service_class', 'pred_service_class',
                          'prob_time_critical', 'prob_operational', 'prob_monitoring']
    for kind in args.run_types:
        for run in runs:
            path = logs / f'qos_rl_{kind}_seed{run}' / 'scada_runtime_ml.csv'
            marker = path.parent / 'complete.json'
            if observed_behavior:
                if not marker.exists():
                    raise ValueError(f'Incomplete protocol benchmark: {path.parent}')
                metadata = json.loads(marker.read_text())
                if (metadata.get('sha256') != sha256(path)
                        or '--protocolBehavior=1' not in metadata.get('command', [])):
                    raise ValueError(f'Benchmark provenance mismatch: {path.parent}')
            frame = pd.read_csv(path, usecols=columns)
            frame = frame[(frame.evaluated == 1) &
                          frame.message_kind.isin(['TELEMETRY', 'EVENT'])].copy()
            frame[features] = frame[features].replace([np.inf, -np.inf], np.nan).fillna(0)
            inputs.append(dict(run=run, run_type=kind, path=str(path),
                               evaluated_rows=len(frame), sha256=sha256(path)))
            x = frame[features].to_numpy(dtype=float)
            truth = frame.true_service_class.to_numpy()
            predictions = {}
            for key, model in models.items():
                probability = model.predict_proba(x)
                tc = probability[:, list(model.classes_).index(CLASSES[0])]
                op = probability[:, list(model.classes_).index(CLASSES[1])]
                prediction = np.full(len(frame), 'MONITORING', dtype=object)
                for protocol, config in thresholds[key].items():
                    mask = frame.protocol.to_numpy() == protocol
                    prediction[mask] = trainer.threshold_prediction_from_probability(
                        tc[mask], op[mask], config['time_critical'], config['operational'])
                predictions[key] = prediction
            if split.get('modbus_only'):
                other = frame.protocol.to_numpy() != 'Modbus'
                for family in ('rf', 'dt'):
                    assert np.array_equal(predictions[f'{family}_new_70_15_15'][other],
                        predictions[f'{family}_current_50_25_25'][other]), 'Non-Modbus classifier changed'
            parity_rows += len(frame)
            parity_mask = predictions['rf_current_50_25_25'] != frame.pred_service_class.to_numpy()
            parity_mismatches += int(np.count_nonzero(parity_mask))
            for index in np.flatnonzero(parity_mask):
                row = frame.iloc[index]
                probability = models['rf_current_50_25_25'].predict_proba(x[index:index+1])[0]
                runtime_probability = dict(TIME_CRITICAL=row.prob_time_critical,
                    OPERATIONAL=row.prob_operational, MONITORING=row.prob_monitoring)
                explanation = explain_csv_rounding(models['rf_current_50_25_25'],
                    x[index], runtime_probability, features) if args.allow_csv_rounding else []
                parity_cases.append(dict(run=run, run_type=kind,
                    input=row.to_dict(), offline_prediction=predictions['rf_current_50_25_25'][index],
                    rounding_explanation=explanation,
                    probability={str(c): float(p) for c,p in
                        zip(models['rf_current_50_25_25'].classes_, probability)}))
                if args.allow_csv_rounding:
                    if not explanation:
                        raise ValueError(f'Unexplained C++ difference: {run}/{kind}/{row.t}')
                    predictions['rf_current_50_25_25'][index] = row.pred_service_class
            for scenario, source, begin, end in scenarios:
                if source != kind:
                    continue
                window = (frame.t.to_numpy() >= begin) & (frame.t.to_numpy() < end)
                for protocol in ('ALL', 'DNP3', 'IEC104', 'Modbus', 'OPC-UA'):
                    mask = window if protocol == 'ALL' else window & (frame.protocol.to_numpy() == protocol)
                    if not mask.any():
                        raise ValueError(f'No samples: {scenario}/{protocol}/{run}')
                    for key, prediction in predictions.items():
                        confusion = matrix(truth[mask], prediction[mask])
                        group = (key, scenario, protocol)
                        pooled[group] = pooled.get(group, np.zeros((3, 3), dtype=int)) + confusion
                        class_rows, summary = measures(confusion)
                        by_seed.append(dict(model=key, scenario=scenario, protocol=protocol,
                                            run=run, **summary))
            print(f'REPLAY {kind} run={run} rows={len(frame)}', flush=True)
    (out / 'runtime_parity_cases.json').write_text(json.dumps(parity_cases, indent=2))
    assert parity_mismatches == 0 or (args.allow_csv_rounding and
        parity_mismatches/parity_rows <= 1e-5), f'Current RF differs on {parity_mismatches}/{parity_rows} rows; see runtime_parity_cases.json'
    assert before == {path: sha256(Path(path)) for path in before}, 'Deployed models changed'
    assert hashes == {path: sha256(Path(path)) for path in hashes}, 'Candidate or baseline pickle changed'
    class_rows, summary_rows = [], []
    for (key, scenario, protocol), confusion in pooled.items():
        rows, summary = measures(confusion)
        class_rows.extend(dict(model=key, scenario=scenario, protocol=protocol, **row) for row in rows)
        summary_rows.append(dict(model=key, scenario=scenario, protocol=protocol, **summary))
    pd.DataFrame(class_rows).to_csv(out / 'class_metrics.csv', index=False)
    pd.DataFrame(summary_rows).to_csv(out / 'summary.csv', index=False)
    per_seed = pd.DataFrame(by_seed)
    per_seed.to_csv(out / 'per_seed_summary.csv', index=False)
    pairs = []
    rng = np.random.default_rng(42)
    for scenario, _, _, _ in scenarios:
        for family in ('rf', 'dt'):
            subset = per_seed[(per_seed.scenario == scenario) & (per_seed.protocol == 'ALL')]
            pivot = subset.pivot(index='run', columns='model', values='macro_f1_pct')
            delta = (pivot[f'{family}_new_70_15_15'] - pivot[f'{family}_current_50_25_25']).to_numpy()
            bootstrap = rng.choice(delta, size=(10000, len(delta)), replace=True).mean(axis=1)
            pairs.append(dict(scenario=scenario, family=family,
                              new_better_runs=int((delta > 0).sum()), run_count=len(delta),
                              mean_macro_f1_delta_pp=float(delta.mean()),
                              bootstrap_ci95_pp=np.quantile(bootstrap, [.025, .975]).tolist()))
    manifest = dict(scope='Offline replay, not end-to-end simulation with the new model',
                    runs=runs, inputs=inputs, thresholds=thresholds, candidate_and_baseline_hashes=hashes,
                    deployed_models_unchanged=True, runtime_parity_rows=parity_rows,
                    current_rf_runtime_mismatches=parity_mismatches,
                    csv_rounding_checked=args.allow_csv_rounding,
                    baseline_rf_uses_logged_cpp_decision_for_verified_rounding_cases=args.allow_csv_rounding,
                    no_fitting_or_threshold_tuning=True,
                    run_types=args.run_types, iec104_service_overlap=observed_overlap,
                    protocol_behavior=observed_behavior,
                    modbus_only=bool(split.get('modbus_only', False)),
                    non_modbus_models_frozen=bool(split.get('modbus_only', False)),
                    modbus_refresh_ms=observed_refresh,
                    generator_matches_candidate=(trained_overlap == observed_overlap
                                                 and trained_behavior == observed_behavior),
                    paired_seed_macro_f1=pairs)
    (out / 'audit.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    view = pd.DataFrame(summary_rows)
    view = view[(view.scenario == 'all_clean_phases') & (view.protocol == 'ALL')]
    print(view.to_string(index=False), flush=True)
    print(f'COMPLETE {out}; no model deployment', flush=True)


if __name__ == '__main__':
    main()
