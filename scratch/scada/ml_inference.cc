// =====================================================================
//  ml_inference.cc - dispatcher for exported binary DT/RF models
// =====================================================================
#include "ml_inference.h"
#include "scada_binary_config.h"
#include "scada_binary_dt_dnp3.h"
#include "scada_binary_dt_iec104.h"
#include "scada_binary_dt_opcua.h"
#include "scada_binary_features.h"
#include "scada_binary_rf_dnp3.h"
#include "scada_binary_rf_iec104.h"
#include "scada_binary_rf_opcua.h"

namespace ns3 {

// The exported models index their feature array positionally, so a runtime
// vector built in a different order than the models were trained on would
// mispredict silently.  scada_binary_features.h is regenerated together with
// the model headers, so any drift on either side fails the build here.
namespace {
constexpr bool FeatureOrderMatchesTraining() {
    if (N_FEATURES != scada_binary_config::TRAINED_N_FEATURES) {
        return false;
    }
    for (int i = 0; i < N_FEATURES; ++i) {
        if (FEATURE_NAMES[i] != scada_binary_config::TRAINED_FEATURE_NAMES[i]) {
            return false;
        }
    }
    return true;
}
} // namespace

static_assert(FeatureOrderMatchesTraining(),
              "Runtime feature layout (SCADA_BEHAVIOR20_FEATURES in "
              "ml_inference.h) no longer matches the order the exported models "
              "were trained on (scada_binary_features.h). Re-run "
              "ml/export_binary_models.py and reconcile the two lists.");

namespace {
// Per-protocol threshold override; negative = unset.  Three entries only,
// matching the three exported per-protocol models.
double g_tauDnp3 = -1.0;
double g_tauIec104 = -1.0;
double g_tauOpcua = -1.0;
}  // namespace

void MlSetThresholdOverride(const std::string& protocol, double threshold) {
    if (protocol == "DNP3")        g_tauDnp3 = threshold;
    else if (protocol == "IEC104") g_tauIec104 = threshold;
    else if (protocol == "OPC-UA") g_tauOpcua = threshold;
}

double MlGetThresholdOverride(const std::string& protocol) {
    if (protocol == "DNP3")        return g_tauDnp3;
    if (protocol == "IEC104")      return g_tauIec104;
    if (protocol == "OPC-UA")      return g_tauOpcua;
    return -1.0;
}

BinaryUrgencyPrediction MlPredictUrgency(
    const std::string& mode,
    const std::string& protocol,
    const double features[N_FEATURES]) {
    BinaryUrgencyPrediction result;
    double scores[2] = {1.0, 0.0};
    int urgentIndex = 1;

    if (mode == "dt") {
        if (protocol == "DNP3") {
            score_binary_dt_dnp3(const_cast<double*>(features), scores);
            urgentIndex = scada_binary_config::DT_DNP3_URGENT_INDEX;
            result.threshold = scada_binary_config::DT_DNP3_THRESHOLD;
        } else if (protocol == "IEC104") {
            score_binary_dt_iec104(const_cast<double*>(features), scores);
            urgentIndex = scada_binary_config::DT_IEC104_URGENT_INDEX;
            result.threshold = scada_binary_config::DT_IEC104_THRESHOLD;
        } else if (protocol == "OPC-UA") {
            score_binary_dt_opcua(const_cast<double*>(features), scores);
            urgentIndex = scada_binary_config::DT_OPCUA_URGENT_INDEX;
            result.threshold = scada_binary_config::DT_OPCUA_THRESHOLD;
        } else {
            return result;
        }
    } else if (mode == "rf") {
        if (protocol == "DNP3") {
            score_binary_rf_dnp3(const_cast<double*>(features), scores);
            urgentIndex = scada_binary_config::RF_DNP3_URGENT_INDEX;
            result.threshold = scada_binary_config::RF_DNP3_THRESHOLD;
        } else if (protocol == "IEC104") {
            score_binary_rf_iec104(const_cast<double*>(features), scores);
            urgentIndex = scada_binary_config::RF_IEC104_URGENT_INDEX;
            result.threshold = scada_binary_config::RF_IEC104_THRESHOLD;
        } else if (protocol == "OPC-UA") {
            score_binary_rf_opcua(const_cast<double*>(features), scores);
            urgentIndex = scada_binary_config::RF_OPCUA_URGENT_INDEX;
            result.threshold = scada_binary_config::RF_OPCUA_THRESHOLD;
        } else {
            return result;
        }
    } else {
        return result;
    }

    result.modelAvailable = true;
    result.urgentProbability = scores[urgentIndex];
    // Only this comparison sees the override; scoring above is unchanged.
    double tauOverride = MlGetThresholdOverride(protocol);
    if (tauOverride >= 0.0) {
        result.threshold = tauOverride;
    }
    result.urgent = result.urgentProbability >= result.threshold;
    return result;
}

} // namespace ns3
