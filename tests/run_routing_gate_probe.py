import json
import shlex
import subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
stage=root/'output/routing_gate_contract'
stage.mkdir(parents=True, exist_ok=True)
source=root/'tests/routing_gate_probe.cc'
entry=next(e for e in json.loads((root/'cmake-cache/compile_commands.json').read_text()) if e['file'].endswith('/scada/scada.cc'))
args=shlex.split(entry['command']);args[args.index('-o')+1]=str(stage/'probe.o');args[args.index('-c')+1]=str(source)
args+=['-I'+str(root/'scratch/scada')]
subprocess.run(args,cwd=entry['directory'],check=True)
link=subprocess.check_output(['ninja','-C','cmake-cache','-t','commands','scratch_scada_scada'],cwd=root,text=True).splitlines()[-1]
args=shlex.split(link.split('&&')[1]);args[args.index('scratch/CMakeFiles/scratch_scada_scada.dir/scada/scada.cc.o')]=str(stage/'probe.o')
args=[a for a in args if not a.endswith('.cc.o')]
args[args.index('-o')+1]=str(stage/'gate-probe')
subprocess.run(args,cwd=root/'cmake-cache',check=True)
result=subprocess.check_output([str(stage/'gate-probe')],cwd=root,text=True)
(stage/'gate_probe.txt').write_text(result)
print(result,flush=True)
