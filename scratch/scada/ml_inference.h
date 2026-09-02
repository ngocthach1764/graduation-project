// =====================================================================
//  ml_inference.h - per-protocol binary message-urgency inference
// =====================================================================
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ns3 {

// ---------------------------------------------------------------------
//  Feature contract - single source of truth.
//
//  This list generates both the FeatureIdx enum and the FEATURE_NAMES
//  table, so an index and its name can never drift apart.
//
//  The names and their order must match FEATURES_BEHAVIOR20 in
//  ml/build_behavior_features.py.  That is checked at compile time in
//  ml_inference.cc against scada_binary_features.h, which is generated
//  next to the model headers by ml/export_binary_models.py.  A reorder
//  on either side therefore breaks the build instead of silently
//  feeding the models a permuted feature vector.
// ---------------------------------------------------------------------
#define SCADA_BEHAVIOR20_FEATURES(X)                                  \
    X(F_PKT_COUNT_1S,                "pkt_count_1s")                  \
    X(F_CURRENT_PKT_SIZE,            "current_pkt_size")              \
    X(F_AVG_PKT_SIZE,                "avg_pkt_size")                  \
    X(F_MAX_PKT_SIZE,                "max_pkt_size")                  \
    X(F_PKT_SIZE_STD,                "pkt_size_std")                  \
    X(F_PKT_SIZE_ENTROPY,            "pkt_size_entropy")              \
    X(F_INTER_ARRIVAL_MEAN,          "inter_arrival_mean")            \
    X(F_INTER_ARRIVAL_MIN,           "inter_arrival_min")             \
    X(F_INTER_ARRIVAL_STD,           "inter_arrival_std")             \
    X(F_CURRENT_SIZE_BASELINE_RATIO, "current_size_baseline_ratio")   \
    X(F_TIME_SINCE_LAST_PKT,         "time_since_last_pkt")           \
    X(F_SILENT_GAP_RATIO,            "silent_gap_ratio")              \
    X(F_PKT_RATE_DELTA,              "pkt_rate_delta")                \
    X(F_CURRENT_SIZE_ZSCORE,         "current_size_zscore")           \
    X(F_BURST_COUNT_100MS,           "burst_count_100ms")             \
    X(F_BURST_COUNT_500MS,           "burst_count_500ms")             \
    X(F_SHORT_LONG_RATE_RATIO,       "short_long_rate_ratio")         \
    X(F_BASELINE_PKT_RATE_ZSCORE,    "baseline_pkt_rate_zscore")      \
    X(F_BASELINE_SIZE_ZSCORE,        "baseline_size_zscore")          \
    X(F_UPLINK_DOWNLINK_RATIO,       "uplink_downlink_ratio")

enum FeatureIdx {
#define SCADA_FEATURE_ENUM_ENTRY(symbol, name) symbol,
    SCADA_BEHAVIOR20_FEATURES(SCADA_FEATURE_ENUM_ENTRY)
#undef SCADA_FEATURE_ENUM_ENTRY
    N_FEATURES
};

inline constexpr std::string_view FEATURE_NAMES[] = {
#define SCADA_FEATURE_NAME_ENTRY(symbol, name) name,
    SCADA_BEHAVIOR20_FEATURES(SCADA_FEATURE_NAME_ENTRY)
#undef SCADA_FEATURE_NAME_ENTRY
};

static_assert(sizeof(FEATURE_NAMES) / sizeof(FEATURE_NAMES[0]) == N_FEATURES,
              "FEATURE_NAMES and FeatureIdx must stay the same length");

struct BinaryUrgencyPrediction {
    bool urgent = false;
    double urgentProbability = 0.0;
    double threshold = 1.0;
    bool modelAvailable = false;
};

BinaryUrgencyPrediction MlPredictUrgency(
    const std::string& mode,
    const std::string& protocol,
    const double features[N_FEATURES]);

// ---------------------------------------------------------------------
//  Experiment-only decision-threshold override.
//
//  Set from the CLI (--mlTauDnp3 / --mlTauIec104 / --mlTauOpcua) to study
//  operating points other than the exported ones.  Scope is deliberately
//  minimal:
//    * no override set (the default) leaves the compile-time thresholds in
//      scada_binary_config.h in force, so results stay bit-for-bit identical
//      to the frozen configuration;
//    * the model headers, the feature vector and the scoring call are
//      untouched - only the final `probability >= threshold` comparison uses
//      the overridden value;
//    * nothing here is written back to any artefact.
//  A negative value means "unset".
// ---------------------------------------------------------------------
void   MlSetThresholdOverride(const std::string& protocol, double threshold);
double MlGetThresholdOverride(const std::string& protocol);

} // namespace ns3
