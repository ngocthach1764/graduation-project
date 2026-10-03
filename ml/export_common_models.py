"""Export a locked common DT/RF model without training or changing thresholds."""
import argparse
import hashlib
import json
import pickle
from pathlib import Path

CLASS_ORDER = ['MONITORING', 'OPERATIONAL', 'TIME_CRITICAL']
PROTOCOL_IDS = {'Modbus': 1, 'DNP3': 2, 'IEC104': 3, 'OPC-UA': 4}


def export_tree(model, family, path):
    assert list(model.classes_) == CLASS_ORDER and model.n_features_in_ == 21
    estimators = model.estimators_ if family == 'rf' else [model]
    nodes, roots = [], []
    for estimator in estimators:
        tree, offset = estimator.tree_, len(nodes)
        roots.append(offset)
        for i in range(tree.node_count):
            probability = tree.value[i, 0].astype(float)
            probability /= probability.sum()
            left, right = int(tree.children_left[i]), int(tree.children_right[i])
            nodes.append('{%d,%d,%d,%.17g,{%.17g,%.17g,%.17g}}' % (
                offset+left if left>=0 else -1, offset+right if right>=0 else -1,
                tree.feature[i], tree.threshold[i], *probability))
    namespace = 'scada_common_' + family
    source = '#pragma once\n// Generated from locked common model; sklearn float32 comparison.\n'
    source += 'namespace '+namespace+' {\nstruct Node { int left,right,feature; double threshold; double p[3]; };\n'
    source += 'inline constexpr Node nodes[] = {\n'+',\n'.join(nodes)+'\n};\n'
    source += 'inline constexpr int roots[] = {'+','.join(map(str,roots))+'};\n}\n'
    source += 'inline void score_service_'+family+'(double* input, double* output) {\n'
    source += ' output[0]=output[1]=output[2]=0;\n for (int root: '+namespace+'::roots) {\n  int i=root;\n'
    source += '  while('+namespace+'::nodes[i].left>=0) {\n   const auto& n='+namespace+'::nodes[i];\n'
    source += '   i=static_cast<float>(input[n.feature])<=n.threshold?n.left:n.right;\n  }\n'
    source += '  for(int c=0;c<3;c++) output[c]+='+namespace+'::nodes[i].p[c];\n }\n'
    source += f' for(int c=0;c<3;c++) output[c]/={len(estimators)}.0;\n}}\n'
    path.write_text(source, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    candidate, dest = args.candidate.resolve(), args.destination.resolve()
    records = json.loads((candidate/'locked_models.json').read_text())
    split = json.loads((candidate/'split_manifest.json').read_text())
    assert not split['modbus_only'] and split['ratio'] == [70,15,15]
    groups = [set(runs) for runs in split['runs'].values()]
    assert not any(groups[i] & groups[j] for i in range(3) for j in range(i))
    dest.mkdir(parents=True, exist_ok=True)
    features = records['rf']['features']
    assert len(features) == 21 and features == records['dt']['features']
    model_hashes = {}
    for family in ['rf','dt']:
        model_path = candidate/'models'/f'{family}.pkl'
        with model_path.open('rb') as stream: model = pickle.load(stream)
        assert not records[family]['modbus_only']
        export_tree(model, family, dest/f'scada_service_{family}.h')
        model_hashes[family] = hashlib.sha256(model_path.read_bytes()).hexdigest()
    config = '#pragma once\nnamespace scada_service_config {\n'
    for symbol,name in [('MONITORING','MONITORING'),('OPERATIONAL','OPERATIONAL'),('TIME_CRITICAL','TIME_CRITICAL')]:
        config += f'inline constexpr int {symbol}_INDEX = {CLASS_ORDER.index(name)};\n'
    config += 'inline constexpr int N_PROTOCOL_IDS = 5;\n'
    for family in ['dt','rf']:
        for key,symbol in [('time_critical','TIME_CRITICAL'),('operational','OPERATIONAL')]:
            values = [.95]*5
            for protocol,idx in PROTOCOL_IDS.items(): values[idx] = records[family]['thresholds'][protocol][key]
            config += f'inline constexpr double {family.upper()}_{symbol}_THRESHOLD[N_PROTOCOL_IDS] = '+ '{'+','.join(format(v,'.17g') for v in values)+'};\n'
    (dest/'scada_service_config.h').write_text(config+'}\n',encoding='utf-8')
    feature_source = '#pragma once\n#include <string_view>\nnamespace scada_service_config {\n'
    feature_source += 'inline constexpr int TRAINED_N_FEATURES = 21;\ninline constexpr std::string_view TRAINED_FEATURE_NAMES[TRAINED_N_FEATURES] = {\n'
    feature_source += ',\n'.join(json.dumps(name) for name in features)+'\n};\n}\n'
    (dest/'scada_service_features.h').write_text(feature_source,encoding='utf-8')
    manifest = {'target':'service_class','classes':CLASS_ORDER,'features':features,'models':records,
        'mapping':{'TIME_CRITICAL':'EF','OPERATIONAL':'AF31','MONITORING':'BE'},
        'common_training':{'runs':split['runs'],'ratio':[70,15,15],'protocols':list(PROTOCOL_IDS),
            'model_sha256':model_hashes,'dataset_counts':json.loads((candidate/'dataset_counts.json').read_text()),
            'training_seed_reuse':split.get('training_seed_reuse',False),
            'threshold_selection':'validation only; locked before test and 3100-3114 benchmark',
            'source_hashes':split['source_hashes'],'binary_sha256':split['binary_sha256']}}
    (dest/'scada_service_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('EXPORTED COMMON DT/RF:',dest,flush=True)


if __name__ == '__main__': main()
