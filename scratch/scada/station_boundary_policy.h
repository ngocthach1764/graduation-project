#pragma once
#include <algorithm>
#include <cstdint>
#include <map>

// Pure policy: no attack label, transport port, RF truth or scenario input.
namespace scada_boundary {
struct Bucket {
    double rate = 0, burst = 0, tokens = 0, last = 0;
    void Configure(double kbps, double bytes, double now = 0) {
        rate = kbps * 1000.0 / 8.0; burst = bytes; tokens = bytes; last = now;
    }
    void Refill(double now) {
        tokens = std::min(burst, tokens + std::max(0.0, now-last) * rate);
        last = std::max(last, now);
    }
};
struct Counters {
    uint64_t rawPackets=0, rawPrioritySeen=0, rawAdmitted=0, rawDropped=0;
    uint64_t spoofDropped=0, remarked=0, rawBytes=0, rawAdmittedBytes=0;
    uint64_t priorityOffered=0, priorityDemotions=0;
};
struct Decision { bool drop=false; uint8_t tos=0; };
struct Field { uint32_t address=0; Bucket bucket; };
class Policy {
public:
    Counters counters;
    void Configure(double rawSourceKbps, double rawStationKbps,
                   double rawBurst, double stationBurst,
                   double priorityKbps, double priorityBurst) {
        m_rawRate=rawSourceKbps; m_rawBurst=rawBurst;
        m_priorityRate=priorityKbps; m_priorityBurst=priorityBurst;
        m_aggregate.Configure(rawStationKbps, stationBurst);
    }
    void AddField(uint32_t interface, uint32_t address) {
        Field field; field.address=address;
        field.bucket.Configure(m_rawRate, m_rawBurst);
        m_fields.emplace(interface, field);
    }
    bool IsField(uint32_t interface) const { return m_fields.count(interface)>0; }
    Decision Forward(double now, uint32_t interface, uint32_t source,
                     uint8_t tos, uint32_t bytes, bool remark, bool limit) {
        Decision d; d.tos=tos;
        auto found=m_fields.find(interface);
        if (found==m_fields.end()) return d;
        ++counters.rawPackets; counters.rawBytes+=bytes;
        if (tos>>2) ++counters.rawPrioritySeen;
        if (remark && source!=found->second.address) {
            d.drop=true; ++counters.rawDropped; ++counters.spoofDropped; return d;
        }
        // All forwarded field traffic lacks Station proxy authorization.
        // Preserve ECN bits while removing the untrusted DSCP claim.
        if (remark) d.tos=tos & 3;
        if (limit) {
            Bucket& sourceBucket=found->second.bucket;
            sourceBucket.Refill(now); m_aggregate.Refill(now);
            if (sourceBucket.tokens<bytes || m_aggregate.tokens<bytes) {
                d.drop=true; ++counters.rawDropped; return d;
            }
            // Atomic debit: a rejected packet does not consume one bucket.
            sourceBucket.tokens-=bytes; m_aggregate.tokens-=bytes;
        }
        ++counters.rawAdmitted; counters.rawAdmittedBytes+=bytes;
        if (d.tos!=tos) ++counters.remarked;
        return d;
    }
    bool AdmitPriority(double now, uint64_t deviceProtocol, uint32_t bytes) {
        ++counters.priorityOffered;
        auto [it, added]=m_priority.try_emplace(deviceProtocol);
        if (added) it->second.Configure(m_priorityRate, m_priorityBurst, now);
        Bucket& b=it->second; b.Refill(now);
        if (b.tokens<bytes) { ++counters.priorityDemotions; return false; }
        b.tokens-=bytes; return true;
    }
private:
    double m_rawRate=20, m_rawBurst=4000, m_priorityRate=50, m_priorityBurst=4000;
    Bucket m_aggregate;
    std::map<uint32_t,Field> m_fields;
    std::map<uint64_t,Bucket> m_priority;
};
}
