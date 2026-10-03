#include "rl_agent.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
using namespace ns3;

int main() {
    GatewayRlAgent stable, local, shared, security, recentSwitch;
    uint32_t recentPath = 0;
    for (auto* agent : {&stable, &local, &shared, &security, &recentSwitch}) {
        agent->Setup(0, RlMode::QTABLE, .1, .9, 0, 100, 1500,
                     true, 2000, true, 20, .04, true, true);
    }
    auto sample = [&]() {
        for (uint32_t p=0;p<3;p++) {
            stable.SetPathQueue(p,.05);
            local.SetPathQueue(p,p==0?.80:.05);
            shared.SetPathQueue(p,.80);
            security.SetPathQueue(p,.05);
            recentSwitch.SetPathQueue(p,p==0?.80:.05);
        }
    };
    sample();
    assert(local.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path==0);
    Simulator::Schedule(MilliSeconds(400), [&] {
        sample();
        assert(stable.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path==0);
        assert(shared.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path==0);
        assert(local.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path!=0);
        recentPath=recentSwitch.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path;
        assert(recentPath!=0);
        security.SetPathRouteAnomaly(0,true);
        assert(security.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path!=0);
    });
    Simulator::Schedule(MilliSeconds(500), [&] {
        security.SetPathRouteAnomaly(0,false);
        local.SetPathQueue(0,.05);
        local.SetPathQueue(1,.80);
        local.SetPathQueue(2,.80);
        recentSwitch.SetPathRouteAnomaly(recentPath,true);
    });
    Simulator::Schedule(MilliSeconds(700), [&] {
        assert(recentSwitch.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path!=recentPath);
    });
    Simulator::Schedule(MilliSeconds(800), [&] {
        recentSwitch.SetPathRouteAnomaly(recentPath,false);
    });
    Simulator::Schedule(MilliSeconds(1000), [&] {
        assert(recentSwitch.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path==0);
    });
    Simulator::Schedule(MilliSeconds(1100), [&] {
        local.SetPathQueue(0,.05);
        local.SetPathQueue(1,.80);
        local.SetPathQueue(2,.80);
        assert(security.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path==0);
        assert(local.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path!=0);
    });
    Simulator::Schedule(MilliSeconds(2600), [&] {
        local.SetPathQueue(0,.05);
        local.SetPathQueue(1,.80);
        local.SetPathQueue(2,.80);
        assert(local.SelectPath(RlTrafficClass::EMERGENCY,100,RlTrafficClass::EMERGENCY).path==0);
    });
    Simulator::Stop(MilliSeconds(2650));
    Simulator::Run();
    Simulator::Destroy();
    std::cout << "PASS: stable/shared hold, persistent local reroute, 2s congestion dwell, FIB escape and recovery bypass dwell.\n";
}
