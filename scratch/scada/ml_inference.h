// =====================================================================
// ml_inference.h - window-based QoS service-class inference
// =====================================================================
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace ns3 {

// This is the runtime side of the Python/C++ feature-order contract. Keep the
// names here independent from the generated model header so static_assert can
// detect an accidental ordering mismatch.
#define SCADA_SERVICE_FEATURES(X) \
    X(F_PKT_COUNT_1S, "pkt_count_1s") \
    X(F_CURRENT_PKT_SIZE, "current_pkt_size") \
    X(F_AVG_PKT_SIZE, "avg_pkt_size") \
    X(F_MAX_PKT_SIZE, "max_pkt_size") \
    X(F_PKT_SIZE_STD, "pkt_size_std") \
    X(F_PKT_SIZE_ENTROPY, "pkt_size_entropy") \
    X(F_INTER_ARRIVAL_MEAN, "inter_arrival_mean") \
    X(F_INTER_ARRIVAL_MIN, "inter_arrival_min") \
    X(F_INTER_ARRIVAL_STD, "inter_arrival_std") \
    X(F_CURRENT_SIZE_BASELINE_RATIO, "current_size_baseline_ratio") \
    X(F_TIME_SINCE_LAST_PKT, "time_since_last_pkt") \
    X(F_SILENT_GAP_RATIO, "silent_gap_ratio") \
    X(F_PKT_RATE_DELTA, "pkt_rate_delta") \
    X(F_CURRENT_SIZE_ZSCORE, "current_size_zscore") \
    X(F_BURST_COUNT_100MS, "burst_count_100ms") \
    X(F_BURST_COUNT_500MS, "burst_count_500ms") \
    X(F_SHORT_LONG_RATE_RATIO, "short_long_rate_ratio") \
    X(F_BASELINE_PKT_RATE_ZSCORE, "baseline_pkt_rate_zscore") \
    X(F_BASELINE_SIZE_ZSCORE, "baseline_size_zscore") \
    X(F_UPLINK_DOWNLINK_RATIO, "uplink_downlink_ratio") \
    X(F_PROTOCOL_ID, "protocol_id")

#define SCADA_FEATURE_ENUM(symbol, name) symbol,
enum FeatureIdx {
    SCADA_SERVICE_FEATURES(SCADA_FEATURE_ENUM)
    N_FEATURES
};
#undef SCADA_FEATURE_ENUM

#define SCADA_FEATURE_NAME(symbol, name) std::string_view{name},
inline constexpr std::array<std::string_view, N_FEATURES> FEATURE_NAMES = {
    SCADA_SERVICE_FEATURES(SCADA_FEATURE_NAME)
};
#undef SCADA_FEATURE_NAME

enum ServiceClassIdx {
    SC_TIME_CRITICAL = 0,
    SC_OPERATIONAL,
    SC_MONITORING,
    N_SERVICE_CLASSES
};

struct ServiceClassPrediction {
    ServiceClassIdx serviceClass = SC_OPERATIONAL;
    std::array<double, N_SERVICE_CLASSES> probability{0.0, 1.0, 0.0};
    double confidence = 0.0;
    // Largest priority score divided by its protocol-specific decision
    // threshold. Values below 1 are useful for a QoS-only uncertainty guard
    // without changing the classifier's reported class.
    double priorityEvidence = 0.0;
    bool modelAvailable = false;
};

ServiceClassPrediction MlPredictServiceClass(
    const std::string& mode,
    const double features[N_FEATURES]);

const char* ServiceClassName(ServiceClassIdx serviceClass);
uint8_t ServiceClassToTos(ServiceClassIdx serviceClass);

} // namespace ns3
