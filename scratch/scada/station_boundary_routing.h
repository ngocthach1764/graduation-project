#pragma once
#include "station_boundary_policy.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4.h"
#include "ns3/simulator.h"

namespace ns3 {
// Wrapper installed after routing setup. Delegate RIP/static lookup unchanged;
// only condition transit packets arriving from configured access interfaces.
class StationBoundaryRouting : public Ipv4RoutingProtocol {
public:
    static TypeId GetTypeId() {
        static TypeId id=TypeId("ns3::StationBoundaryRouting")
            .SetParent<Ipv4RoutingProtocol>().SetGroupName("Internet")
            .AddConstructor<StationBoundaryRouting>();
        return id;
    }
    void Setup(Ptr<Ipv4RoutingProtocol> inner, scada_boundary::Policy* policy,
               bool remark, bool limit) {
        m_inner=inner; m_policy=policy; m_remark=remark; m_limit=limit;
    }
    Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p, const Ipv4Header& h,
                             Ptr<NetDevice> oif, Socket::SocketErrno& error) override {
        return m_inner->RouteOutput(p,h,oif,error);
    }
    bool RouteInput(Ptr<const Packet> p, const Ipv4Header& header,
                    Ptr<const NetDevice> device, const UnicastForwardCallback& ucb,
                    const MulticastForwardCallback& mcb, const LocalDeliverCallback& lcb,
                    const ErrorCallback& ecb) override {
        const int32_t interface=m_ipv4->GetInterfaceForDevice(device);
        // Local OT sessions and RIP/multicast control traffic are not forwarded
        // raw northbound and must retain the existing protocol behavior.
        if (interface>=0 && m_policy->IsField(interface)
            && !header.GetDestination().IsMulticast()
            && !header.GetDestination().IsBroadcast()
            && !m_ipv4->IsDestinationAddress(header.GetDestination(),interface)) {
            const auto decision=m_policy->Forward(Simulator::Now().GetSeconds(),
                interface,header.GetSource().Get(),header.GetTos(),
                p->GetSize()+header.GetSerializedSize(),m_remark,m_limit);
            if (decision.drop) return true; // explicit policer drop; audit counter
            Ipv4Header conditioned=header; conditioned.SetTos(decision.tos);
            return m_inner->RouteInput(p,conditioned,device,ucb,mcb,lcb,ecb);
        }
        return m_inner->RouteInput(p,header,device,ucb,mcb,lcb,ecb);
    }
    void SetIpv4(Ptr<Ipv4> ipv4) override { m_ipv4=ipv4; }
    void NotifyInterfaceUp(uint32_t i) override { m_inner->NotifyInterfaceUp(i); }
    void NotifyInterfaceDown(uint32_t i) override { m_inner->NotifyInterfaceDown(i); }
    void NotifyAddAddress(uint32_t i,Ipv4InterfaceAddress a) override { m_inner->NotifyAddAddress(i,a); }
    void NotifyRemoveAddress(uint32_t i,Ipv4InterfaceAddress a) override { m_inner->NotifyRemoveAddress(i,a); }
    void PrintRoutingTable(Ptr<OutputStreamWrapper> s,Time::Unit u=Time::S) const override {
        m_inner->PrintRoutingTable(s,u);
    }
protected:
    void DoInitialize() override { m_inner->Initialize(); Ipv4RoutingProtocol::DoInitialize(); }
    void DoDispose() override {
        if (m_inner) m_inner->Dispose();
        m_inner=nullptr; m_ipv4=nullptr; m_policy=nullptr;
        Ipv4RoutingProtocol::DoDispose();
    }
private:
    Ptr<Ipv4RoutingProtocol> m_inner;
    Ptr<Ipv4> m_ipv4;
    scada_boundary::Policy* m_policy=nullptr;
    bool m_remark=false, m_limit=false;
};
}
