#!/usr/bin/env python3
"""Compile real workflow helpers and causal request-statistic code."""
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = r'''
#include "modbus_workflow.h"
#include "behavior_features.h"
#include <cassert>
#include <cmath>
#include <iostream>
using namespace scada_modbus_workflow;
int main() {
    std::array<uint16_t,125> registers{};
    auto read = BuildRequest(1, 8, 0, 0);
    Request parsed;
    assert(read.size()==13 && ParseRequest(read.data(),read.size(),parsed));
    assert(parsed.function==3 && parsed.readCount==8 && parsed.values.empty());
    auto response = Execute(1, parsed, registers);
    assert(response.size()==26 && response[8]==3 && response[9]==16);
    auto write = BuildRequest(2, 8, 4, 50);
    assert(write.size()==26 && ParseRequest(write.data(),write.size(),parsed));
    response = Execute(2, parsed, registers);
    assert(response.size()==26 && response[8]==23 && registers[0]==50);
    assert(Read16(response.data()+10)==50 && Read16(response.data()+16)==53);
    assert(ParseRequest(read.data(),read.size(),parsed));
    response = Execute(3, parsed, registers);
    assert(Read16(response.data()+10)==50); // verification reads written value
    auto control = BuildRequest(4,8,4,60,32,32);
    assert(ParseRequest(control.data(),control.size(),parsed));
    response = Execute(4,parsed,registers);
    assert(registers[32]==60 && registers[0]==50);
    assert(Read16(response.data()+10)==60);
    auto bad = write;
    bad[17] = 0;
    assert(!ParseRequest(bad.data(),bad.size(),parsed));
    assert(!ParseRequest(write.data(),17,parsed));
    bad=read; Write16(bad.data()+11,0);
    assert(!ParseRequest(bad.data(),bad.size(),parsed));
    bad=read; Write16(bad.data()+9,120);
    assert(!ParseRequest(bad.data(),bad.size(),parsed));
    bad=read; bad[8]=99;
    assert(!ParseRequest(bad.data(),bad.size(),parsed));
    ns3::BehaviorFeatureExtractor features;
    double stats[8];
    features.GetRequestStatistics(1,1,1,stats);
    for (int i=0;i<7;++i) assert(stats[i]==0);
    assert(stats[7]==2.0);
    features.ObserveDownlink(1,1,1,13);
    features.ObserveDownlink(1,1,1.2,50);
    features.ObserveDownlink(1,1,1.5,60);
    features.GetRequestStatistics(1,1,1.4,stats);
    assert(stats[0]==50 && stats[1]==31.5 && stats[2]==50);
    assert(stats[4]==50 && std::abs(stats[5]-.2)<1e-9);
    assert(stats[6]==1 && std::abs(stats[7]-.2)<1e-9);
    assert(std::abs(stats[3]-std::sqrt(684.5))<1e-9);
    features.GetRequestStatistics(1,1,2.6,stats);
    assert(stats[0]==0 && stats[1]==0 && stats[2]==0 && stats[3]==0);
    assert(stats[4]==60 && std::abs(stats[5]-1.1)<1e-9);
    assert(stats[6]==2 && std::abs(stats[7]-1.1)<1e-9);
    features.ObserveDownlink(1,1,1.6,20);
    features.GetRequestStatistics(1,1,1.6,stats);
    assert(stats[4]==60 && stats[6]==3 && stats[7]==0);
    features.GetRequestStatistics(1,1,4,stats);
    for (int i=0;i<7;++i) assert(stats[i]==0);
    assert(stats[7]==2.0);
    features.GetRequestStatistics(2,1,1.4,stats);
    for (int i=0;i<7;++i) assert(stats[i]==0); // streams must not mix
    assert(stats[7]==2.0);
    std::cout << "Modbus workflow and causal request statistics passed\n";
}
'''
compiler = shutil.which('g++')
if not compiler:
    raise SystemExit('g++ required; run in the Ubuntu build environment.')
with tempfile.TemporaryDirectory(prefix='scada-modbus-') as directory:
    work = Path(directory)
    path = work/'test.cc'
    path.write_text(source, encoding='utf-8')
    subprocess.run([compiler, '-std=c++17', '-I', str(ROOT/'scratch/scada'),
        str(path), str(ROOT/'scratch/scada/behavior_features.cc'),
        '-o', str(work/'test')], check=True)
    subprocess.run([str(work/'test')], check=True)
