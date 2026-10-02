#pragma once

#include "ml_inference.h"

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ns3 {

class BehaviorFeatureExtractor {
public:
    void ObserveDownlink(uint32_t deviceId, uint32_t protocolId, double t,
                         uint32_t bytes = 0);
    // Causal auxiliary statistics for candidate training; not inputs to the
    // deployed 21-feature model. last/mean/max/sample-std bytes in 1 s, plus
    // maximum request bytes and age of the latest maximum in trailing 2 s.
    // Also count requests >1.5 times the minimum observed size in 2 s and
    // report the age of the latest such request (2 s when none exists).
    void GetRequestStatistics(uint32_t deviceId, uint32_t protocolId, double t,
                              double statistics[8]) const;

    // Returns true once the current scenario's warm-up baseline is ready.
    // dataMessage = false cho khung cua chinh giao thuc (PROTOCOL).  Nhung
    // khung nay van dem vao cuong do luu luong, nhung KHONG duoc dua vao
    // duong co so kich thuoc: bo phan loai chi bao gio thay ban tin du lieu,
    // nen duong co so phai mo ta cung mot tap ban tin do.
    bool AddUplink(uint32_t deviceId,
                   uint32_t protocolId,
                   const std::string& scenario,
                   double scenarioStart,
                   bool warmup,
                   double t,
                   uint32_t packetSize,
                   bool dataMessage,
                   double features[N_FEATURES]);

private:
    struct State {
        std::string scenario;
        double scenarioStart = 0.0;
        std::deque<std::pair<double, double>> history;
        bool hasPrevPacket = false;
        double prevPacketT = 0.0;
        std::vector<double> warmTimes;
        std::vector<double> warmSizes;
        bool baselineReady = false;
        double baseRate = 0.0;
        double baseSize = 0.0;
        double baseIat = 1.0;
        double rateVar = 1.0;
        double sizeVar = 1.0;
        bool hasBucket = false;
        int64_t currentBucket = 0;
        uint32_t bucketCount = 0;
        uint32_t dataBucketCount = 0;
        double dataBucketSizeSum = 0.0;
    };

    static uint64_t Key(uint32_t deviceId, uint32_t protocolId);
    static void ResetScenario(State& state,
                              const std::string& scenario,
                              double scenarioStart);
    static void UpdateBaselineBucket(State& state,
                                     uint32_t count,
                                     uint32_t dataCount,
                                     double averageSize);
    static void AdvanceBuckets(State& state, double t);
    static void InitializeBaseline(State& state, double t);

    std::map<uint64_t, State> m_states;
    std::map<uint64_t, std::deque<double>> m_downlinkTimes;
    std::map<uint64_t, std::deque<std::pair<double,double>>> m_requestSizes;
};

} // namespace ns3
