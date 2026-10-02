#include "behavior_features.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <numeric>

namespace ns3 {
namespace {

constexpr double HISTORY_SECONDS = 2.0;
constexpr double ALPHA = 0.08;
constexpr double EPS = 1e-6;
constexpr double VALUE_CAP = 10.0;
constexpr std::array<double, 8> SIZE_EDGES = {
    16.0, 32.0, 64.0, 96.0, 160.0, 256.0, 512.0, 1024.0};

double PopulationVariance(const std::vector<double>& values, double mean) {
    if (values.size() <= 1) return 1.0;
    double sum = 0.0;
    for (double value : values) {
        double delta = value - mean;
        sum += delta * delta;
    }
    return sum / static_cast<double>(values.size());
}

double SampleStd(const std::vector<double>& values) {
    if (values.size() <= 1) return 0.0;
    double mean = std::accumulate(values.begin(), values.end(), 0.0) /
                  static_cast<double>(values.size());
    double sum = 0.0;
    for (double value : values) {
        double delta = value - mean;
        sum += delta * delta;
    }
    return std::sqrt(sum / static_cast<double>(values.size() - 1));
}

double ClippedZ(double value, double mean, double stdFloor) {
    double z = (value - mean) / std::max(stdFloor, EPS);
    return std::max(-VALUE_CAP, std::min(VALUE_CAP, z));
}

double SizeEntropy(const std::vector<double>& sizes) {
    if (sizes.empty()) return 0.0;
    std::array<uint32_t, 9> bins{};
    for (double size : sizes) {
        size_t index = 0;
        while (index < SIZE_EDGES.size() && size >= SIZE_EDGES[index]) ++index;
        ++bins[index];
    }
    double entropy = 0.0;
    for (uint32_t count : bins) {
        if (count == 0) continue;
        double probability = static_cast<double>(count) / sizes.size();
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

} // namespace

uint64_t BehaviorFeatureExtractor::Key(uint32_t deviceId, uint32_t protocolId) {
    return (static_cast<uint64_t>(deviceId) << 32) | protocolId;
}

void BehaviorFeatureExtractor::ResetScenario(State& state,
                                             const std::string& scenario,
                                             double scenarioStart) {
    state = State{};
    state.scenario = scenario;
    state.scenarioStart = scenarioStart;
}

void BehaviorFeatureExtractor::UpdateBaselineBucket(State& state,
                                                    uint32_t count,
                                                    uint32_t dataCount,
                                                    double averageSize) {
    if (!state.baselineReady) return;
    double rateStd = std::max({std::sqrt(state.rateVar),
                              0.05 * std::max(state.baseRate, 1.0), 0.5});
    double sizeStd = std::max({std::sqrt(state.sizeVar),
                              0.05 * std::max(state.baseSize, 1.0), 1.0});
    if (std::abs(static_cast<double>(count) - state.baseRate) > 3.0 * rateStd)
        return;
    if (dataCount > 0 && std::abs(averageSize - state.baseSize) > 3.0 * sizeStd)
        return;

    double oldRate = state.baseRate;
    state.baseRate = ALPHA * count + (1.0 - ALPHA) * state.baseRate;
    state.rateVar = ALPHA * std::pow(count - oldRate, 2.0) +
                    (1.0 - ALPHA) * state.rateVar;
    if (dataCount > 0) {
        double oldSize = state.baseSize;
        state.baseSize = ALPHA * averageSize + (1.0 - ALPHA) * state.baseSize;
        state.sizeVar = ALPHA * std::pow(averageSize - oldSize, 2.0) +
                        (1.0 - ALPHA) * state.sizeVar;
    }
}

void BehaviorFeatureExtractor::AdvanceBuckets(State& state, double t) {
    int64_t target = static_cast<int64_t>(std::floor(t));
    if (!state.hasBucket) {
        state.hasBucket = true;
        state.currentBucket = target;
        return;
    }
    while (state.currentBucket < target) {
        double average = state.dataBucketCount > 0
            ? state.dataBucketSizeSum / state.dataBucketCount : state.baseSize;
        UpdateBaselineBucket(state, state.bucketCount,
                             state.dataBucketCount, average);
        ++state.currentBucket;
        state.bucketCount = 0;
        state.dataBucketCount = 0;
        state.dataBucketSizeSum = 0.0;
    }
}

void BehaviorFeatureExtractor::InitializeBaseline(State& state, double t) {
    if (state.baselineReady) return;
    double duration = std::max(t - state.scenarioStart, 1.0);
    uint32_t nBins = std::max(1u, static_cast<uint32_t>(std::ceil(duration)));
    std::vector<double> counts(nBins, 0.0);
    for (double time : state.warmTimes) {
        int64_t bin = static_cast<int64_t>(std::floor(time - state.scenarioStart));
        bin = std::max<int64_t>(0, std::min<int64_t>(nBins - 1, bin));
        counts[static_cast<size_t>(bin)] += 1.0;
    }

    state.baseRate = state.warmTimes.size() / duration;
    double countMean = std::accumulate(counts.begin(), counts.end(), 0.0) /
                       static_cast<double>(counts.size());
    state.rateVar = PopulationVariance(counts, countMean);
    if (!state.warmSizes.empty()) {
        state.baseSize = std::accumulate(
            state.warmSizes.begin(), state.warmSizes.end(), 0.0) /
            state.warmSizes.size();
        state.sizeVar = PopulationVariance(state.warmSizes, state.baseSize);
    } else {
        state.baseSize = 1.0;
        state.sizeVar = 1.0;
    }
    if (state.warmTimes.size() > 1) {
        state.baseIat = (state.warmTimes.back() - state.warmTimes.front()) /
                        static_cast<double>(state.warmTimes.size() - 1);
    } else {
        state.baseIat = 1.0 / std::max(state.baseRate, EPS);
    }
    state.baselineReady = true;
}

void BehaviorFeatureExtractor::ObserveDownlink(uint32_t deviceId,
                                               uint32_t protocolId,
                                               double t, uint32_t bytes) {
    auto& times = m_downlinkTimes[Key(deviceId, protocolId)];
    times.push_back(t);
    while (!times.empty() && times.front() < t - 1.0) times.pop_front();
    auto& requests = m_requestSizes[Key(deviceId, protocolId)];
    requests.emplace_back(t, bytes);
    while (!requests.empty() && requests.front().first < t - 2.0)
        requests.pop_front();
}

void BehaviorFeatureExtractor::GetRequestStatistics(
    uint32_t deviceId, uint32_t protocolId, double t,
    double statistics[8]) const {
    std::fill(statistics, statistics+8, 0.0);
    statistics[7] = 2.0;
    const auto it = m_requestSizes.find(Key(deviceId, protocolId));
    if (it == m_requestSizes.end()) return;
    std::vector<double> sizes;
    double minimum = 0.0;
    for (const auto& request : it->second) {
        if (request.first >= t-2.0 && request.first <= t && request.second > 0)
            minimum = minimum > 0 ? std::min(minimum,request.second) : request.second;
    }
    for (const auto& request : it->second) {
        if (request.first >= t-2.0 && request.first <= t && minimum > 0
            && request.second > 1.5 * minimum) {
            statistics[6] += 1.0;
            statistics[7] = t-request.first;
        }
        if (request.first >= t-2.0 && request.first <= t
            && request.second >= statistics[4]) {
            statistics[4] = request.second;
            statistics[5] = t-request.first;
        }
        if (request.first >= t-1.0 && request.first <= t) {
            sizes.push_back(request.second);
            statistics[0] = request.second;
        }
    }
    if (sizes.empty()) return;
    statistics[1] = std::accumulate(sizes.begin(), sizes.end(), 0.0)/sizes.size();
    statistics[2] = *std::max_element(sizes.begin(), sizes.end());
    statistics[3] = SampleStd(sizes);
}

bool BehaviorFeatureExtractor::AddUplink(uint32_t deviceId,
                                        uint32_t protocolId,
                                        const std::string& scenario,
                                        double scenarioStart,
                                        bool warmup,
                                        double t,
                                        uint32_t packetSize,
                                        bool dataMessage,
                                        double features[N_FEATURES]) {
    std::fill(features, features + N_FEATURES, 0.0);
    State& state = m_states[Key(deviceId, protocolId)];
    if (state.scenario != scenario ||
        std::abs(state.scenarioStart - scenarioStart) > EPS) {
        ResetScenario(state, scenario, scenarioStart);
    }

    AdvanceBuckets(state, t);
    if (warmup) {
        state.warmTimes.push_back(t);
        if (dataMessage) state.warmSizes.push_back(packetSize);
    } else if (!state.baselineReady) {
        InitializeBaseline(state, t);
    }

    double timeSinceLast = state.hasPrevPacket
        ? std::max(0.0, t - state.prevPacketT) : 0.0;
    state.hasPrevPacket = true;
    state.prevPacketT = t;

    while (!state.history.empty() && state.history.front().first < t - HISTORY_SECONDS)
        state.history.pop_front();
    state.history.emplace_back(t, static_cast<double>(packetSize));

    std::vector<double> times;
    std::vector<double> sizes;
    double previousCount = 0.0;
    for (const auto& sample : state.history) {
        if (sample.first >= t - 1.0) {
            times.push_back(sample.first);
            sizes.push_back(sample.second);
        } else if (sample.first >= t - 2.0) {
            previousCount += 1.0;
        }
    }

    double packetCount = static_cast<double>(sizes.size());
    double byteCount = std::accumulate(sizes.begin(), sizes.end(), 0.0);
    double averageSize = byteCount / std::max(packetCount, 1.0);
    double maximumSize = *std::max_element(sizes.begin(), sizes.end());
    double sizeStd = SampleStd(sizes);

    std::vector<double> iats;
    for (size_t i = 1; i < times.size(); ++i) iats.push_back(times[i] - times[i - 1]);
    double iatMean = iats.empty() ? timeSinceLast :
        std::accumulate(iats.begin(), iats.end(), 0.0) / iats.size();
    double iatMin = iats.empty() ? timeSinceLast :
        *std::min_element(iats.begin(), iats.end());
    double iatStd = SampleStd(iats);

    double burst100 = 0.0;
    double burst500 = 0.0;
    for (double time : times) {
        if (time >= t - 0.100) burst100 += 1.0;
        if (time >= t - 0.500) burst500 += 1.0;
    }

    double currentRatio = 1.0;
    double silentRatio = 0.0;
    double currentSizeZ = 0.0;
    double baselineRateZ = 0.0;
    double baselineSizeZ = 0.0;
    if (state.baselineReady) {
        double rateStd = std::max({std::sqrt(state.rateVar),
                                  0.05 * std::max(state.baseRate, 1.0), 0.5});
        double baselineSizeStd = std::max({std::sqrt(state.sizeVar),
                                          0.05 * std::max(state.baseSize, 1.0), 1.0});
        baselineRateZ = ClippedZ(packetCount, state.baseRate, rateStd);
        baselineSizeZ = ClippedZ(averageSize, state.baseSize, baselineSizeStd);
        currentSizeZ = ClippedZ(packetSize, state.baseSize, baselineSizeStd);
        currentRatio = std::min(packetSize / std::max(state.baseSize, EPS), VALUE_CAP);
        silentRatio = std::min(timeSinceLast / std::max(state.baseIat, EPS), VALUE_CAP);
    }

    auto& downlink = m_downlinkTimes[Key(deviceId, protocolId)];
    while (!downlink.empty() && downlink.front() < t - 1.0) downlink.pop_front();

    features[F_PKT_COUNT_1S] = packetCount;
    features[F_CURRENT_PKT_SIZE] = packetSize;
    features[F_AVG_PKT_SIZE] = averageSize;
    features[F_MAX_PKT_SIZE] = maximumSize;
    features[F_PKT_SIZE_STD] = sizeStd;
    features[F_PKT_SIZE_ENTROPY] = SizeEntropy(sizes);
    features[F_INTER_ARRIVAL_MEAN] = iatMean;
    features[F_INTER_ARRIVAL_MIN] = iatMin;
    features[F_INTER_ARRIVAL_STD] = iatStd;
    features[F_CURRENT_SIZE_BASELINE_RATIO] = currentRatio;
    features[F_TIME_SINCE_LAST_PKT] = timeSinceLast;
    features[F_SILENT_GAP_RATIO] = silentRatio;
    features[F_PKT_RATE_DELTA] = packetCount - previousCount;
    features[F_CURRENT_SIZE_ZSCORE] = currentSizeZ;
    features[F_BURST_COUNT_100MS] = burst100;
    features[F_BURST_COUNT_500MS] = burst500;
    features[F_SHORT_LONG_RATE_RATIO] = burst100 / std::max(packetCount, 1.0);
    features[F_BASELINE_PKT_RATE_ZSCORE] = baselineRateZ;
    features[F_BASELINE_SIZE_ZSCORE] = baselineSizeZ;
    features[F_UPLINK_DOWNLINK_RATIO] = packetCount /
        std::max(1.0, static_cast<double>(downlink.size()));
    features[F_PROTOCOL_ID] = static_cast<double>(protocolId);
    ++state.bucketCount;
    if (dataMessage) {
        ++state.dataBucketCount;
        state.dataBucketSizeSum += packetSize;
    }
    return state.baselineReady;
}

} // namespace ns3
