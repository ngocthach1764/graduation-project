// =====================================================================
// ml_inference.cc - pooled DT/RF service classifier dispatcher
// =====================================================================
#include "ml_inference.h"
#include "scada_service_config.h"
#include "scada_service_dt.h"
#include "scada_service_features.h"
#include "scada_service_rf.h"
#include "scada_modbus_dt.h"
#include "scada_modbus_rf.h"

#include <algorithm>

namespace ns3 {
namespace {

constexpr bool FeatureOrderMatchesTraining() {
    if (N_FEATURES != scada_service_config::TRAINED_N_FEATURES) return false;
    for (int i = 0; i < N_FEATURES; ++i) {
        if (scada_service_config::TRAINED_FEATURE_NAMES[i] !=
            FEATURE_NAMES[i]) return false;
    }
    return true;
}

ServiceClassIdx ClassFromModelIndex(int modelIndex) {
    if (modelIndex == scada_service_config::TIME_CRITICAL_INDEX)
        return SC_TIME_CRITICAL;
    if (modelIndex == scada_service_config::OPERATIONAL_INDEX)
        return SC_OPERATIONAL;
    return SC_MONITORING;
}

} // namespace

static_assert(FeatureOrderMatchesTraining(),
              "Runtime service feature layout does not match the exported "
              "DT/RF model. Re-run ml/train_service_classifier.py.");

const char* ServiceClassName(ServiceClassIdx serviceClass) {
    if (serviceClass == SC_TIME_CRITICAL) return "TIME_CRITICAL";
    if (serviceClass == SC_OPERATIONAL) return "OPERATIONAL";
    return "MONITORING";
}

uint8_t ServiceClassToTos(ServiceClassIdx serviceClass) {
    if (serviceClass == SC_TIME_CRITICAL) return 184; // EF
    if (serviceClass == SC_OPERATIONAL) return 104;   // AF31
    return 0;                                         // BE
}

ServiceClassPrediction MlPredictServiceClass(
    const std::string& mode,
    const double features[N_FEATURES]) {
    ServiceClassPrediction result;
    double scores[N_SERVICE_CLASSES] = {0.0, 1.0, 0.0};
    const int protocolId = std::clamp(
        static_cast<int>(features[F_PROTOCOL_ID]), 0,
        scada_service_config::N_PROTOCOL_IDS - 1);
    double timeThreshold = 1.0;
    double operationalThreshold = 1.0;
    if (mode == "dt") {
        if (protocolId == 1) score_modbus_dt(const_cast<double*>(features), scores);
        else score_service_dt(const_cast<double*>(features), scores);
        timeThreshold =
            scada_service_config::DT_TIME_CRITICAL_THRESHOLD[protocolId];
        operationalThreshold =
            scada_service_config::DT_OPERATIONAL_THRESHOLD[protocolId];
    } else if (mode == "rf") {
        if (protocolId == 1) score_modbus_rf(const_cast<double*>(features), scores);
        else score_service_rf(const_cast<double*>(features), scores);
        timeThreshold =
            scada_service_config::RF_TIME_CRITICAL_THRESHOLD[protocolId];
        operationalThreshold =
            scada_service_config::RF_OPERATIONAL_THRESHOLD[protocolId];
    } else {
        return result;
    }

    const double pTime = scores[scada_service_config::TIME_CRITICAL_INDEX];
    const double pOperational = scores[scada_service_config::OPERATIONAL_INDEX];
    const bool timePass = pTime >= timeThreshold;
    const bool operationalPass = pOperational >= operationalThreshold;
    int modelIndex = scada_service_config::MONITORING_INDEX;
    if (timePass && (!operationalPass ||
        pTime / timeThreshold >= pOperational / operationalThreshold)) {
        modelIndex = scada_service_config::TIME_CRITICAL_INDEX;
    } else if (operationalPass) {
        modelIndex = scada_service_config::OPERATIONAL_INDEX;
    }
    result.serviceClass = ClassFromModelIndex(modelIndex);
    result.confidence = scores[modelIndex];
    result.modelAvailable = true;
    result.probability[SC_TIME_CRITICAL] =
        scores[scada_service_config::TIME_CRITICAL_INDEX];
    result.probability[SC_OPERATIONAL] =
        scores[scada_service_config::OPERATIONAL_INDEX];
    result.probability[SC_MONITORING] =
        scores[scada_service_config::MONITORING_INDEX];
    result.priorityEvidence = std::max(
        pTime / std::max(timeThreshold, 1e-12),
        pOperational / std::max(operationalThreshold, 1e-12));
    return result;
}

} // namespace ns3
