"""Compile and exercise the actual pure policy header."""
import subprocess
import tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
code=r'''
#include "station_boundary_policy.h"
#include <cassert>
#include <iostream>
using namespace scada_boundary;
int main(){
 Policy p; p.Configure(8,8,200,200,8,200); p.AddField(1,10); p.AddField(2,20);
 auto unknown=p.Forward(0,99,10,184,100,true,true);
 assert(!unknown.drop && unknown.tos==184 && p.counters.rawPackets==0);
 auto first=p.Forward(0,1,10,187,100,true,true);
 assert(!first.drop && first.tos==3); // Preserve ECN, remove spoofed DSCP.
 auto second=p.Forward(0,2,20,184,100,true,true); assert(!second.drop);
 auto aggregate=p.Forward(0,1,10,184,100,true,true); assert(aggregate.drop);
 auto replenished=p.Forward(.1,1,10,184,100,true,true); assert(!replenished.drop);
 auto source=p.Forward(.1,1,10,184,100,true,true); assert(source.drop);
 auto spoof=p.Forward(.2,2,999,184,100,true,true); assert(spoof.drop);
 assert(p.counters.spoofDropped==1);
 assert(p.counters.rawPackets==p.counters.rawAdmitted+p.counters.rawDropped);
 assert(p.AdmitPriority(0,100,200)); assert(!p.AdmitPriority(0,100,1));
 assert(p.AdmitPriority(0,200,200)); // Independent registered source.
 assert(p.AdmitPriority(.1,100,100)); // Time-based refill, not FSM reset.
 Policy bounded; bounded.Configure(8,8,200,200,8,200); bounded.AddField(1,10);
 unsigned allowed=0;
 for(int n=0;n<100;++n) allowed+=!bounded.Forward(0,1,10,184,100,false,true).drop;
 assert(allowed==2); // Rate limiter works without remarking and without labels.
 Policy noLimit; noLimit.Configure(8,8,200,200,8,200); noLimit.AddField(1,10);
 assert(!noLimit.Forward(0,1,10,184,9999,true,false).drop);
 Bucket b; b.Configure(8,200); b.tokens=0; b.Refill(1); assert(b.tokens==200);
 b.Refill(.5); assert(b.tokens==200 && b.last==1);
 std::cout<<"Boundary policy: ECN/source binding/atomic budgets/rate/source isolation passed\n";
}
'''
with tempfile.TemporaryDirectory(prefix='boundary_test_') as tmp:
    dest=Path(tmp); (dest/'test.cc').write_text(code)
    subprocess.run(['g++','-std=c++17','-I',str(ROOT/'scratch/scada'),
                    str(dest/'test.cc'),'-o',str(dest/'test')],check=True)
    subprocess.run([str(dest/'test')],check=True)
