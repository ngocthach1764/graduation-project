"""Regression checks for the clean reference phase and official 15-seed data."""
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT/'scratch/scada/scada.cc').read_text()
assert 'static bool g_normalClean = true;' in source
assert 'cmd.AddValue("normalClean"' in source
assert 'if (g_normalClean && sc == "normal") model->Disable();' in source
assert 'else model->Enable();' in source
assert 'g_linkErrorModels.push_back(model);' in source
assert 'g_linkErrorModels.push_back(g_pathErrorModels[i]);' in source
assert '(g_normalClean ? g_scenarioDur : 1.0)' in source
if len(sys.argv)>1:
    output = Path(sys.argv[1])
    with (output/'per_seed_15.csv').open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    normal = [row for row in rows if row['scenario']=='normal']
    assert len(normal)==60, len(normal)
    for row in normal:
        assert float(row['TC_miss_pct'])==0, row
        assert float(row['OP_miss_pct'])==0, row
        assert float(row['J'])==0, row
    assert len(list(output.glob('*/complete.json')))==240
print('Normal clean source contract passed; supplied results verified when present')
