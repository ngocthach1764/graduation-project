"""Compile the actual meter functions with a minimal clock stub."""
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
text = (ROOT / 'scratch/scada/scada.cc').read_text()
begin = text.index('static bool ConsumeStationTokens(')
end = text.index('static void RunQosController()', begin)
functions = text[begin:end]
stub = r'''
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <iostream>
struct Time { double value; double GetSeconds() const { return value; } };
Time operator-(Time a, Time b) { return {a.value-b.value}; }
struct Simulator { static inline double now=0; static Time Now() {return {now};} };
struct StationClassMeter {
 bool enabled=true; double rateBytesPerSec=0, burstBytes=1000, tokens=0;
 Time lastUpdate{0};
};
struct StationMeterDecision {uint8_t served=0; bool demoted=false, borrowed=false;};
std::array<std::array<StationClassMeter,3>,3> g_stationMeters;
enum class SecurityState { CLEAN, SUSPECTED, UNDER_ATTACK, RECOVERY };
SecurityState g_securityState=SecurityState::UNDER_ATTACK;
bool g_ddosProtectUrgent=true, g_qosEmergencyBorrow=true;
std::string g_ddosMeterPolicy="bounded";
uint64_t g_ddosMeterBypassPackets=0;
'''
tests = r'''
int main() {
 auto& m=g_stationMeters[0];
 m[1].tokens=50; m[2].tokens=150;
 auto op=ApplyStationMeter(0,1,100);
 assert(op.served==1 && op.borrowed && !op.demoted);
 assert(m[1].tokens==50 && m[2].tokens==50);
 auto empty=ApplyStationMeter(0,1,100);
 assert(empty.served==0 && empty.demoted && !empty.borrowed);
 assert(g_ddosMeterBypassPackets==0);
 m[1].tokens=150; m[2].tokens=50;
 auto tc=ApplyStationMeter(0,2,100);
 assert(tc.served==2 && tc.borrowed && m[1].tokens==50);
 g_ddosMeterPolicy="standard";
 m[1].tokens=50; m[2].tokens=150;
 auto standard=ApplyStationMeter(0,1,100);
 assert(standard.served==0 && m[2].tokens==150);
 g_ddosMeterPolicy="legacy_bypass";
 auto legacy=ApplyStationMeter(0,1,100);
 assert(legacy.served==1 && m[1].tokens==50 && g_ddosMeterBypassPackets==1);
 g_ddosMeterPolicy="bounded";
 g_securityState=SecurityState::CLEAN;
 auto clean=ApplyStationMeter(0,1,100);
 assert(clean.served==0 && m[2].tokens==150);
 g_securityState=SecurityState::UNDER_ATTACK;
 m[1].tokens=0; m[2].tokens=0;
 m[1].rateBytesPerSec=100; m[2].rateBytesPerSec=0;
 Simulator::now=1;
 auto refill=ApplyStationMeter(0,1,100);
 assert(refill.served==1 && m[1].tokens==0);
 auto twice=ApplyStationMeter(0,1,100);
 assert(twice.served==0); // same instant must not refill a second time
 assert(ApplyStationMeter(10,1,100).served==1);
 std::cout << "Meter contract: 8 cases passed (real source functions)\n";
}
'''
compiler = shutil.which("g++")
if not compiler:
    raise SystemExit("g++ is required; run this check in the Ubuntu build environment.")
with tempfile.TemporaryDirectory(prefix="scada-meter-") as directory:
    out = Path(directory)
    (out / "meter_test.cc").write_text(stub + functions + tests, encoding="utf-8")
    subprocess.run([compiler, "-std=c++17", str(out / "meter_test.cc"),
                    "-o", str(out / "meter_test")], check=True)
    subprocess.run([str(out / "meter_test")], check=True)
