"""Export locked Modbus branches; preserve the pooled non-Modbus headers."""
import argparse
import hashlib
import json
import pickle
import re
from pathlib import Path


def export_tree_model(model, family, path):
    classes = list(model.classes_)
    assert set(classes) == {'MONITORING', 'OPERATIONAL'}
    assert model.n_features_in_ == 21
    estimators = model.estimators_ if family == 'rf' else [model]
    nodes, roots = [], []
    for estimator in estimators:
        tree, offset = estimator.tree_, len(nodes)
        roots.append(offset)
        for i in range(tree.node_count):
            values = tree.value[i, 0].astype(float)
            values /= values.sum()
            p = {str(c):float(v) for c,v in zip(classes,values)}
            left, right = int(tree.children_left[i]), int(tree.children_right[i])
            nodes.append('{%d,%d,%d,%.17g,{%.17g,%.17g,0}}' % (
                offset+left if left>=0 else -1, offset+right if right>=0 else -1,
                tree.feature[i],tree.threshold[i],p['MONITORING'],p['OPERATIONAL']))
    namespace='scada_modbus_'+family
    text='#pragma once\n// Generated from the locked Modbus model; no fitting or pruning.\n'
    text+='namespace '+namespace+' {\nstruct Node { int left,right,feature; double threshold; double p[3]; };\n'
    text+='inline constexpr Node nodes[] = {\n'+',\n'.join(nodes)+'\n};\n'
    text+='inline constexpr int roots[] = {'+','.join(map(str,roots))+'};\n}\n'
    text+='inline void score_modbus_'+family+'(double* input, double* output) {\n'
    text+=' output[0]=output[1]=output[2]=0;\n for (int root: '+namespace+'::roots) {\n  int i=root;\n'
    text+='  while('+namespace+'::nodes[i].left>=0) {\n   const auto& n='+namespace+'::nodes[i];\n'
    text+='   i=static_cast<float>(input[n.feature])<=n.threshold?n.left:n.right;\n  }\n'
    text+='  for(int c=0;c<3;c++) output[c]+='+namespace+'::nodes[i].p[c];\n }\n'
    text+=f' for(int c=0;c<3;c++) output[c]/={len(estimators)}.0;\n}}\n'
    path.write_text(text)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate',type=Path)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args()
    root=args.root.resolve(); candidate=args.candidate.resolve()
    stage=root/'scratch/scada'
    records=json.loads((candidate/'locked_models.json').read_text())
    split=json.loads((candidate/'split_manifest.json').read_text())
    assert split['modbus_only'] and len(set(sum(split['runs'].values(),[])))==120
    manifest_path=stage/'scada_service_manifest.json'
    manifest=json.loads(manifest_path.read_text())
    config_path=stage/'scada_service_config.h'; config=config_path.read_text()
    branches={}
    for family in ['rf','dt']:
        model_path=candidate/'models'/f'{family}.pkl'
        with model_path.open('rb') as stream:
            hybrid=pickle.load(stream)
        assert hybrid.protocol_index==20
        assert records[family]['features']==manifest['features']
        for protocol in ['DNP3','IEC104','OPC-UA']:
            assert records[family]['thresholds'][protocol]==manifest['models'][family]['thresholds'][protocol]
        export_tree_model(hybrid.modbus,family,stage/f'scada_modbus_{family}.h')
        thresholds=records[family]['thresholds']['Modbus']
        for key,symbol in [('time_critical','TIME_CRITICAL'),('operational','OPERATIONAL')]:
            pattern=rf'({family.upper()}_{symbol}_THRESHOLD\[N_PROTOCOL_IDS\]\s*=\s*\{{)([^}}]+)(\}})'
            def replace(match):
                values=match[2].split(','); values[1]=' '+format(thresholds[key],'.17g')
                return match[1]+','.join(values)+match[3]
            config,count=re.subn(pattern,replace,config)
            assert count==1
        manifest['models'][family]['thresholds']['Modbus']=thresholds
        branches[family]={'pickle_sha256':hashlib.sha256(model_path.read_bytes()).hexdigest(),
                         'thresholds':thresholds,'params':records[family]['params'],
                         'training_rows':records[family]['training_rows']}
    config_path.write_text(config)
    manifest['modbus_branch']={'provenance':'service_modbus_only_20261003','protocol_id':1,
        'features':records['rf']['features'],'runs':split['runs'],'split_ratio':[70,15,15],
        'refresh_ms':split['modbus_refresh_ms'],'service_rate_jitter':0.15,
        'monitoring_bursts':'half of sessions in each split','branches':branches,
        'dataset_counts':json.loads((candidate/'dataset_counts.json').read_text()),
        'non_modbus_models':'original pooled models retained unchanged',
        'threshold_selection':'validation only; no fitting/tuning on seeds 3100-3114'}
    manifest_path.write_text(json.dumps(manifest,indent=2))
    print('Exported locked Modbus DT/RF; pooled non-Modbus headers unchanged.')

if __name__=='__main__':
    main()
