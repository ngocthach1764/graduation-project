"""Train candidate service RF/DT with run-grouped 70/15/15 data.

Does not export or overwrite deployed models. Run in the ns-3 checkout.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import pickle
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_only_model import ModbusOnlyModel

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier


def split_plan(train_start=2000, validation_start=None, test_start=None):
    validation_start = train_start + 200 if validation_start is None else validation_start
    test_start = train_start + 400 if test_start is None else test_start
    return {"train": list(range(train_start, train_start + 84)),
            "validation": list(range(validation_start, validation_start + 18)),
            "test": list(range(test_start, test_start + 18))}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')


def sampled_training(frame):
    kept = []
    for (_, run), group in frame.groupby(['protocol', 'run']):
        priority = group[group.service_class != 'MONITORING']
        monitoring = group[group.service_class == 'MONITORING']
        cap = min(len(monitoring), max(200, 12 * len(priority)))
        kept.extend([priority, monitoring.sample(n=cap, random_state=int(run))])
    return pd.concat(kept, ignore_index=True).sample(frac=1, random_state=42)


def scores(model, frame, features, classes):
    values = model.predict_proba(frame[features].to_numpy(dtype=float))
    return values[:, [list(model.classes_).index(c) for c in classes]]


def reports(frame, prediction, classes):
    result = {}
    for protocol, group in frame.groupby('protocol'):
        mask = frame.protocol.to_numpy() == protocol
        result[protocol] = classification_report(
            group.service_class, prediction[mask], labels=classes,
            output_dict=True, zero_division=0)
    result['overall'] = classification_report(
        frame.service_class, prediction, labels=classes,
        output_dict=True, zero_division=0)
    return result


def rank(report, active_classes, protocol=None, modbus_recall_floor=None):
    if protocol == 'Modbus' and modbus_recall_floor is not None:
        metric = report['OPERATIONAL']
        if metric['recall'] >= modbus_recall_floor:
            return (True, metric['precision'], metric['recall'], metric['f1-score'])
        return (False, metric['recall'], metric['precision'], metric['f1-score'])
    metrics = [report[c] for c in active_classes]
    deficits = [max(0, .8-m['precision']) + max(0, .96-m['recall']) for m in metrics]
    return (all(m['precision'] >= .8 and m['recall'] >= .96 for m in metrics),
            -max(deficits), -sum(deficits), sum(m['f1-score'] for m in metrics))


def tune(frame, probability, trainer, modbus_recall_floor=None):
    selected = {}
    grid = np.round(np.arange(.02, .981, .04), 6)
    classes = list(trainer.CLASSES)
    for protocol, group in frame.groupby('protocol'):
        mask = frame.protocol.to_numpy() == protocol
        actual = np.array([classes.index(c) for c in group.service_class])
        active = [c for c in classes[:2] if np.any(group.service_class == c)]
        best = None
        for tc in (grid if 'TIME_CRITICAL' in active else [1.01]):
            for op in grid:
                prediction = trainer.threshold_prediction_from_probability(
                    probability[mask, 0], probability[mask, 1], tc, op)
                assigned = np.where(prediction == classes[0], 0,
                                    np.where(prediction == classes[1], 1, 2))
                confusion = np.bincount(actual*3 + assigned, minlength=9).reshape(3, 3)
                key = rank(trainer.metrics_from_confusion(confusion), active,
                           protocol, modbus_recall_floor)
                if best is None or key > best[0]:
                    best = (key, float(tc), float(op))
        selected[protocol] = {'time_critical': best[1], 'operational': best[2]}
    return selected


def predict(frame, probability, thresholds, trainer):
    result = np.full(len(frame), 'MONITORING', dtype=object)
    for protocol, config in thresholds.items():
        mask = frame.protocol.to_numpy() == protocol
        result[mask] = trainer.threshold_prediction_from_probability(
            probability[mask, 0], probability[mask, 1],
            config['time_critical'], config['operational'])
    return result


def generate(root, out, split, runs, workers, iec_overlap=False, binary_hash=None,
             protocol_behavior=False, modbus_only=False, modbus_refresh_ms=100.0):
    binary = root / 'build/scratch/scada/ns3.47-scada-optimized'

    def one(item):
        index, run = item
        folder = out / 'data' / split / f'run{run}'
        folder.mkdir(parents=True, exist_ok=True)
        jitter, burst = [.15, .35, .55][(index % 6)//2], index % 2
        if modbus_only:
            jitter = .15  # Do not change the other protocols' generator setting.
        command = [str(binary), '--profile=qos', '--sceneDur=40', f'--run={run}',
                   '--normalClean=1', '--modbusServiceEvents=1',
                   '--modbusServiceWorkflow=1', '--modbusMixedWorkflow=0',
                   f'--modbusMonitoringBursts={burst}', f'--serviceRateJitter={jitter}',
                   '--rlMode=off', '--qosCtrl=0', '--qosSafetyPromote=0',
                   '--ddosProtectUrgent=0', '--ddos=0', '--ripPoison=0',
                   '--anim=0', '--packetCsv=0', '--featureCsv=0', '--flowXml=0',
                   '--runtimeMlCsv=1', '--qosQueueCsv=0', f'--outDir={folder}/']
        if iec_overlap:
            command.append('--iec104ServiceOverlap=1')
        if protocol_behavior:
            command.append('--protocolBehavior=1')
        if modbus_only:
            command.append(f'--modbusOperationalRefreshMs={modbus_refresh_ms}')
        marker = folder / 'complete.json'
        csv = folder / 'scada_runtime_ml.csv'
        if marker.exists():
            meta = json.loads(marker.read_text())
            if (meta['command'] != command or meta['sha256'] != digest(csv)
                    or meta.get('binary_sha256') != binary_hash):
                raise RuntimeError(f'Cached run differs: {folder}')
        else:
            with (folder / 'simulation.log').open('w') as stream:
                subprocess.run(command, cwd=root, stdout=stream,
                               stderr=subprocess.STDOUT, check=True, timeout=180)
            write_json(marker, dict(split=split, run=run, jitter=jitter,
                                    monitoring_burst=burst, command=command,
                                    binary_sha256=binary_hash,
                                    sha256=digest(csv)))
        print(f'DATA {split}: run={run} jitter={jitter} burst={burst}', flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(one, enumerate(runs)))


def load(out, split, features):
    frames = []
    columns = list(features) + ['evaluated', 'message_kind', 'true_service_class',
                               'protocol', 't', 'device_id']
    for folder in sorted((out / 'data' / split).glob('run*')):
        meta = json.loads((folder / 'complete.json').read_text())
        path = folder / 'scada_runtime_ml.csv'
        if meta['sha256'] != digest(path):
            raise RuntimeError(f'Data checksum changed: {path}')
        frame = pd.read_csv(path, usecols=columns)
        frame = frame[(frame.evaluated == 1) &
                      frame.message_kind.isin(['TELEMETRY', 'EVENT'])].copy()
        frame['service_class'] = frame.true_service_class
        frame['run'] = meta['run']
        frames.append(frame)
    data = pd.concat(frames, ignore_index=True)
    data[features] = data[features].replace([np.inf, -np.inf], np.nan).fillna(0)
    data['row_id'] = np.arange(len(data))
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out-dir', type=Path, default=Path('output/service_split_70_15_15_20261003'))
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--train-start', type=int, default=2000)
    parser.add_argument('--validation-start', type=int)
    parser.add_argument('--test-start', type=int)
    parser.add_argument('--modbus-recall-floor', type=float)
    parser.add_argument('--iec104-service-overlap', action='store_true')
    parser.add_argument('--protocol-behavior', action='store_true')
    parser.add_argument('--modbus-only', action='store_true')
    parser.add_argument('--modbus-refresh-ms', type=float, default=100.0)
    args = parser.parse_args()
    if args.modbus_only and (args.protocol_behavior or args.iec104_service_overlap):
        parser.error('Modbus-only must preserve the other committed protocols')
    if args.modbus_only and args.modbus_refresh_ms <= 0:
        parser.error('Modbus refresh interval must be positive')
    root = args.root.resolve()
    out = (root / args.out_dir).resolve()
    plan = split_plan(args.train_start, args.validation_start, args.test_start)
    all_runs = [run for runs in plan.values() for run in runs]
    assert len(set(all_runs)) == 120 and 0 < min(all_runs) and max(all_runs) < 3000
    if args.modbus_recall_floor is not None:
        assert 0 < args.modbus_recall_floor <= 1
    # Each split contains the same six generator combinations equally often.
    assert all(len(runs) % 6 == 0 for runs in plan.values())
    collisions = []
    for folder in (root / 'output').rglob('run*'):
        match = re.fullmatch(r'run(\d+)', folder.name)
        if match and folder.is_dir() and int(match[1]) in all_runs and out not in folder.parents:
            collisions.append(str(folder))
    if collisions:
        raise RuntimeError('Requested run already used: ' + '; '.join(collisions))
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('trainer', root / 'ml/train_service_classifier.py')
    trainer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trainer)
    features, classes = list(trainer.FEATURES), list(trainer.CLASSES)
    assert len(features) == 21
    protected = list((root / 'scratch/scada').glob('scada_service_*.h')) + [
        root / 'scratch/scada/scada_service_manifest.json',
        root / 'scratch/scada/scada_ddos_rf.h', root / 'scratch/scada/rl_agent.h']
    before = {str(path): digest(path) for path in protected if path.exists()}
    baseline = json.loads((root / 'scratch/scada/scada_service_manifest.json').read_text())
    binary_hash = digest(root / 'build/scratch/scada/ns3.47-scada-optimized')
    manifest_path = out / 'split_manifest.json'
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text())
        if (existing.get('binary_sha256') != binary_hash or existing['runs'] != plan
                or existing.get('iec104_service_overlap', False) != args.iec104_service_overlap
                or existing.get('protocol_behavior', False) != args.protocol_behavior
                or existing.get('modbus_only', False) != args.modbus_only
                or existing.get('modbus_refresh_ms', 100.0) != args.modbus_refresh_ms
                or existing.get('modbus_recall_floor') != args.modbus_recall_floor):
            raise RuntimeError('Dataset provenance differs; use a new --out-dir')
    write_json(out / 'split_manifest.json', dict(runs=plan, ratio=[70, 15, 15],
               features=features, scene_duration=40, normal_clean=True,
               iec104_service_overlap=args.iec104_service_overlap,
               protocol_behavior=args.protocol_behavior,
               modbus_only=args.modbus_only, modbus_refresh_ms=args.modbus_refresh_ms,
               modbus_recall_floor=args.modbus_recall_floor, binary_sha256=binary_hash,
               source_hashes={str(path): digest(path) for path in
                              [root / 'scratch/scada/protocols.cc', root / 'scratch/scada/protocols.h',
                               root / 'scratch/scada/scada.cc']},
               model_hashes_before=before, baseline=baseline))
    generate(root, out, 'train', plan['train'], args.workers, args.iec104_service_overlap,
             binary_hash, args.protocol_behavior, args.modbus_only, args.modbus_refresh_ms)
    generate(root, out, 'validation', plan['validation'], args.workers, args.iec104_service_overlap,
             binary_hash, args.protocol_behavior, args.modbus_only, args.modbus_refresh_ms)
    train, val = load(out, 'train', features), load(out, 'validation', features)
    fit = sampled_training(train[train.protocol == 'Modbus'] if args.modbus_only else train)
    fit[['row_id', 'run', 'protocol', 'service_class']].to_csv(out / 'training_selection.csv', index=False)
    counts = {name: dict(rows=len(frame), classes=frame.service_class.value_counts().to_dict())
              for name, frame in [('train_raw', train), ('train_fit', fit), ('validation', val)]}
    del train
    models = {'rf': RandomForestClassifier(n_estimators=100, max_depth=20,
                  min_samples_leaf=2, max_features='sqrt', class_weight='balanced_subsample',
                  n_jobs=4, random_state=42),
              'dt': DecisionTreeClassifier(max_depth=20, min_samples_leaf=2,
                                          class_weight='balanced', random_state=42)}
    records = {}
    (out / 'models').mkdir(exist_ok=True)
    for family, model in models.items():
        print(f'FIT {family}: rows={len(fit)}', flush=True)
        model.fit(fit[features].to_numpy(dtype=float), fit.service_class)
        params = model.get_params()
        if args.modbus_only:
            with (root / 'output/modbus_scan_plan_20261002/models' / f'{family}21.pkl').open('rb') as stream:
                frozen = pickle.load(stream)
            # Fixed accumulation order makes the frozen branch reproducible
            # bit-for-bit across a full batch and a non-Modbus sub-batch.
            if hasattr(frozen, 'n_jobs'):
                frozen.set_params(n_jobs=1)
            model = ModbusOnlyModel(frozen, model, features.index('protocol_id'))
            models[family] = model
        validation_scores = scores(model, val, features, classes)
        if args.modbus_only:
            mask = val.protocol.to_numpy() == 'Modbus'
            thresholds = dict(baseline['models'][family]['thresholds'])
            thresholds.update(tune(val[mask], validation_scores[mask], trainer, args.modbus_recall_floor))
            other = ~mask
            assert np.array_equal(model.predict_proba(val[features].to_numpy(dtype=float)[other]),
                frozen.predict_proba(val[features].to_numpy(dtype=float)[other]))
        else:
            thresholds = tune(val, validation_scores, trainer, args.modbus_recall_floor)
        records[family] = dict(features=features, thresholds=thresholds,
                               validation=reports(val, predict(val, validation_scores, thresholds, trainer), classes),
                               params=params, training_rows=len(fit), modbus_only=args.modbus_only)
        with (out / 'models' / f'{family}.pkl').open('wb') as stream:
            pickle.dump(model, stream)
        print(f'LOCK {family}: {thresholds}', flush=True)
    write_json(out / 'locked_models.json', records)
    del fit, val
    # No test generation/loading before the thresholds have been frozen.
    generate(root, out, 'test', plan['test'], args.workers, args.iec104_service_overlap,
             binary_hash, args.protocol_behavior, args.modbus_only, args.modbus_refresh_ms)
    test = load(out, 'test', features)
    counts['test'] = dict(rows=len(test), classes=test.service_class.value_counts().to_dict())
    results, rows = {}, []
    for family in ('rf', 'dt'):
        candidates = [('new_70_15_15', models[family], records[family]['thresholds'])]
        old_path = root / 'output/modbus_scan_plan_20261002/models' / f'{family}21.pkl'
        with old_path.open('rb') as stream:
            frozen_reference = pickle.load(stream)
            if args.modbus_only and hasattr(frozen_reference, 'n_jobs'):
                frozen_reference.set_params(n_jobs=1)
            candidates.append(('current_50_25_25', frozen_reference,
                               baseline['models'][family]['thresholds']))
        for name, model, thresholds in candidates:
            prediction = predict(test, scores(model, test, features, classes), thresholds, trainer)
            report = reports(test, prediction, classes)
            key = family + '_' + name
            results[key] = report
            for protocol, metrics in report.items():
                for service_class in classes:
                    rows.append(dict(model=key, protocol=protocol, service_class=service_class,
                                     **metrics[service_class]))
            pd.DataFrame(dict(run=test.run, t=test.t, device_id=test.device_id,
                             protocol=test.protocol, truth=test.service_class,
                             prediction=prediction)).to_csv(out / f'{key}_predictions.csv', index=False)
            print(f'TEST {key}: macro={report["overall"]["macro avg"]}', flush=True)
    unchanged = before == {path: digest(Path(path)) for path in before}
    assert unchanged, 'Deployed assets changed during candidate training'
    write_json(out / 'dataset_counts.json', counts)
    write_json(out / 'results.json', results)
    pd.DataFrame(rows).to_csv(out / 'test_metrics.csv', index=False)
    write_json(out / 'completed.json', dict(deployed_models_unchanged=unchanged,
               run_count=120, ratio=[70, 15, 15], model_hashes_before=before,
               candidate_hashes={family: digest(out / 'models' / f'{family}.pkl') for family in models}))
    print(f'COMPLETE {out}; deployed models unchanged', flush=True)


if __name__ == '__main__':
    main()
