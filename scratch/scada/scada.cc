#include "protocols.h"
#include "ml_inference.h"
#include "behavior_features.h"
#include "rl_agent.h"
#include "scada_ddos_rf.h"
#include "station_boundary_routing.h"

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/netanim-module.h"
#include "ns3/mobility-module.h"
#include "ns3/ipv4-queue-disc-item.h"
#include "ns3/ppp-header.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <unordered_map>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ScadaSim");

// =====================================================================
//                         BUILD-TIME CONSTANTS
// =====================================================================
static constexpr double      WINDOW_SIZE        = 1.0;     // s
static constexpr double      SCENARIO_DURATION  = 100.0;   // s per scenario
static constexpr double      BOOTSTRAP_TIME     = 1.0;     // s, master announces "online"
static constexpr double      BOOTSTRAP_ARM_DELAY = 0.25;   // let all HELLO packets arrive first

// Bandwidth defaults — can be overridden via CLI flag --stress=1, which
// tightens bandwidth and queue limits to force congestion.  Under
// congestion, priority queueing decisions (driven by ML DSCP classifier)
// have observable QoS impact; the unloaded default network masks ML effect.
static std::string CORE_BW            = "100Mbps";
static const std::string CORE_DELAY   = "5ms";
static std::string ACCESS_BW          = "10Mbps";
static const std::string ACCESS_DELAY = "2ms";
static std::string BROKER_BW          = "100Mbps";
static const std::string BROKER_DELAY = "5ms";
static const std::string MESH_BW      = "50Mbps";
static const std::string MESH_DELAY   = "3ms";
static constexpr double  MESH_ERR_RATE = 5e-4;

static uint32_t PRIO_QUEUE_LIMIT = 1000;    // packets per band
// NetDevice TxQueue on the core and broker links.  This buffer sits BELOW the
// PrioQueueDisc and is plain FIFO, so whatever fits in it is served without
// any priority.  It must stay small relative to the deadlines, otherwise the
// unavoidable FIFO head of the pipe dominates and priority becomes invisible.
static uint32_t DEV_QUEUE_LIMIT = 100;      // packets (ns-3 p2p default)

// =====================================================================
//                          GLOBAL STATE
// =====================================================================
namespace ns3 {
std::string g_scenario = "normal";       // visible to protocols.cc via extern
std::string g_qosMode  = "private";      // private = DSCP QoS, neutral = FIFO
}

static std::string                       g_outDir      = "output/";
static std::string                       g_mode        = "";
static std::string                       g_rlMode      = "off";
static std::string                       g_rlQTablePath = "";
static double                            g_rlAlpha      = 0.10;
static double                            g_rlGamma      = 0.90;
static double                            g_rlEpsilon    = 0.20;
static double                            g_rlDecisionMs = 100.0;
static double                            g_rlTimeoutMs  = 1500.0;
static bool                              g_rlSafeMask   = true;
static double                            g_rlLossRecoveryMs = 2000.0;
static bool                              g_rlRouteEvidenceGate = false;
static double                            g_rlRouteDelayGapMs = 20.0;
static double                            g_rlRouteLossGap = 0.04;
static bool                              g_rlRouteIntegrity = false;
static double                            g_rlRouteIntegrityMs = 100.0;
static bool                              g_rlDataPlaneFailover = false;
static bool                              g_enableRuntimeMlCsv = true;
static bool                              g_modbusServiceEvents = false;
static bool                              g_modbusMonitoringBursts = false;
static bool                              g_modbusMixedWorkflow = false;
static bool                              g_modbusServiceWorkflow = false;
static double                            g_modbusRoutineWriteProb = 0.02;
static std::string                       g_ddosMeterPolicy = "bounded";
static bool                              g_qosBeFairQueue = false;
static double                            g_serviceRateJitter = 0.15;
static double                            g_modbusOperationalRefreshMs = 100.0;
static bool                              g_qosSafetyPromote = false;
static double                            g_qosSafetyRatio = 0.45;

// DDoS is an independent security axis layered over the three operational
// scenarios (normal/high_load/emergency).  The traffic generator controls
// ground truth only; the detector below sees ingress bytes at Master and must
// infer the security state without reading g_ddosTruthActive.
enum class SecurityState { CLEAN, SUSPECTED, UNDER_ATTACK, RECOVERY };
static const char* SecurityStateName(SecurityState state);
static SecurityState                     g_securityState = SecurityState::CLEAN;
static bool                              g_ddosEnabled = false;
static bool                              g_ddosDetectorEnabled = true;
static std::string                       g_ddosDetectorMode = "rf";
static double                            g_ddosRfThreshold = 0.85;
static double                            g_ddosRfClearThreshold = 0.20;
static bool                              g_ddosTruthActive = false;
static double                            g_ddosStart = -1.0;
static double                            g_ddosDuration = -1.0;
// Calibrated aggregate load used by the primary 2 Mbps-link experiments.
// The old 120 Mbps default was only suitable for an extreme stress run and
// made ordinary NetAnim traces unnecessarily large.
static double                            g_ddosRateMbps = 2.4;
static uint32_t                          g_ddosSources = 18;
static std::string                       g_ddosPattern = "cbr";
static double                            g_ddosBurstFactor = 4.0;
static double                            g_ddosBurstMs = 100.0;
static std::string                       g_ddosPlacement = "distributed";
static double                            g_ddosWindowMs = 500.0;
static double                            g_ddosHighMbps = 20.0;
static double                            g_ddosLowMbps = 5.0;
static uint32_t                          g_ddosAttackWindows = 3;
static uint32_t                          g_ddosClearWindows = 3;
static bool                              g_ddosProtectUrgent = false;
static uint32_t                          g_ddosBeQueueLimit = 10;
static bool g_qosIngressGuard = false;
static bool g_qosSourceLimit = false;
static double g_qosRawSourceKbps = 20.0;
static double g_qosRawStationKbps = 100.0;
static double g_qosRawBurstBytes = 4000.0;
static double g_qosRawStationBurstBytes = 8000.0;
static double g_qosPrioritySourceKbps = 50.0;
static double g_qosPrioritySourceBurstBytes = 4000.0;
static std::array<scada_boundary::Policy,3> g_boundaryPolicies;
static std::ofstream g_boundaryCsv;
static uint64_t                          g_ddosIngressBytes = 0;
static uint64_t                          g_ddosIngressPackets = 0;
static uint64_t                          g_ddosUdpPackets = 0;
static uint64_t                          g_ddosObservedAttackPackets = 0;
static uint64_t                          g_ddosObservedAttackEfPackets = 0; // audit only
static uint64_t                          g_ddosMeterBypassPackets = 0;
static std::unordered_map<uint32_t, uint64_t> g_ddosSourcePackets;
static double                            g_ddosPreviousMbps = 0.0;
static uint32_t                          g_ddosHighCount = 0;
static uint32_t                          g_ddosLowCount = 0;
static std::ofstream                     g_ddosStateCsv;

// Experimental packet-level RIP route-poisoning overlay. It is disabled by
// default so established static/global-routing experiments remain exactly
// reproducible. When enabled, RIP supplies the routing baseline and the
// attacker sends genuine RIP v2 Response packets to one Station.
static bool                              g_ripRouting = false;
static bool                              g_ripPoison = false;
static uint32_t                          g_ripPoisonStation = 1;
static uint32_t                          g_ripPoisonPath = 1;
static double                            g_ripPoisonStart = -1.0;
static double                            g_ripPoisonDuration = -1.0;
static double                            g_ripPoisonPeriod = 1.0;
static uint32_t                          g_ripPoisonMetric = 1;
static std::string                       g_ripDetourBw = "250Kbps";
static std::string                       g_ripDetourDelay = "40ms";
static bool                              g_ripPoisonTruth = false;
static uint64_t                          g_ripPoisonUpdates = 0;
static std::ofstream                     g_ripPoisonCsv;
static std::ofstream                     g_ripRouteCsv;
static std::ofstream                     g_routeIntegrityCsv;

struct RouteFingerprintState {
    bool initialized = false;
    uint32_t expectedGateway = 0;
    int32_t expectedIf = -1;
    uint32_t anomalyCount = 0;
    uint32_t clearCount = 0;
    bool anomalous = false;
};
static std::array<std::array<RouteFingerprintState, 3>, 3>
    g_routeFingerprints{};

static uint32_t                          g_runId       = 1;
static double                            g_simDuration = 0.0;
static double                            g_scenarioDur = SCENARIO_DURATION;
static uint32_t                          g_windowId    = 0;
static Ptr<FlowMonitor>                  g_monitor;
static Ptr<Ipv4FlowClassifier>           g_classifier;

struct FlowSnap { uint64_t txPkts, rxPkts, rxBytes, lostPkts,
                          delaySumNs, jitterSumNs; };
static std::map<FlowId, FlowSnap>        g_prevSnap;

static BehaviorFeatureExtractor          g_behaviorFeatures;
static std::ofstream                     g_runtimeMlCsv;
static uint64_t                          g_runtimeRows = 0;
static uint64_t                          g_runtimeCorrect = 0;

struct CsvRow {
    double      t_start, t_end;
    uint32_t    flow_id;
    std::string src, dst;
    uint16_t    src_port, dst_port;
    uint64_t    pkts_tx, pkts_rx, bytes_rx, pkts_lost;
    double      thr_mbps, mean_delay_ms, jitter_ms;
    uint32_t    app_tx_pkts;
    uint8_t     dscp;
    std::string dscp_class;
    std::string protocol;
    std::string device_role;
    std::string traffic_class;
    uint32_t    protocol_id;
    uint32_t    device_type_id;
    uint32_t    message_family_id;
    uint32_t    is_event_capable;
    uint32_t    is_mixed_device;
    std::string scenario;
};
static std::vector<CsvRow>               g_csvRows;
static std::map<std::string, std::string> g_flowLabelMap;
static std::map<std::string, std::string> g_flowRoleMap;
static std::map<std::string, std::string> g_flowClassMap;
static std::map<std::string, uint32_t>     g_flowProtoIdMap;
static std::map<std::string, uint32_t>     g_flowDeviceTypeMap;
static std::map<std::string, uint32_t>     g_flowMsgFamilyMap;
static std::map<std::string, uint32_t>     g_flowEventCapMap;
static std::map<std::string, uint32_t>     g_flowMixedMap;

// per-app Tx accumulators (key = src ip)
static std::map<std::string, uint32_t>   g_accumByKey;

static constexpr double WARMUP_DURATION  = 20.0;  // s per scenario
// Cua so su co phai phat nhanh gap INCIDENT_RATE_FACTOR lan nhip nen cua
// chinh thiet bi, chan tren la INCIDENT_RATE_CAP ban tin moi giay.
static constexpr double INCIDENT_RATE_FACTOR = 4.0;
static constexpr double INCIDENT_RATE_CAP    = 60.0;
static constexpr double TRANSITION_BUFFER = 1.0;   // s on both incident edges

struct IncidentWindow {
    uint32_t    deviceId;
    double      start;
    double      end;
    std::string label;
};
static std::vector<IncidentWindow> g_incidentWindows;

struct ScadaTraceContext {
    uint32_t    nodeId;
    uint32_t    deviceId;
    uint32_t    protocolId;
    std::string protocol;
    std::string direction;
    std::string deviceRole;
};
static std::map<std::string, ScadaTraceContext> g_traceContexts;

struct PacketRow {
    uint32_t    runId;
    double      t;
    uint32_t    nodeId;
    uint32_t    deviceId;
    uint32_t    protocolId;
    std::string protocol;
    std::string direction;
    uint32_t    pktSize;
    uint32_t    incidentActive;
    uint32_t    isWarmup;
    uint32_t    isTransition;
    uint32_t    trainUsable;
    std::string label;
    std::string messageKind;
    std::string scenario;
    std::string deviceRole;
};
static std::ofstream g_packetCsv;
static uint64_t      g_packetRowCount = 0;

// Application containers — keep references for SetScenario() calls
static std::vector<Ptr<ModbusSlaveApp>>      g_modbusSlaves;
static std::vector<Ptr<ModbusMasterApp>>     g_modbusMasters;
static std::vector<Ptr<Dnp3OutstationApp>>   g_dnp3Outstations;
static std::vector<Ptr<Dnp3MasterApp>>       g_dnp3Masters;
static std::vector<Ptr<Iec104ControlledApp>> g_iecControlled;
static std::vector<Ptr<Iec104ControllingApp>> g_iecControlling;
static std::vector<Ptr<OpcUaServerApp>>      g_opcServers;
static std::vector<Ptr<OpcUaClientApp>>      g_opcClients;
static std::vector<Ptr<MqttPublisherApp>>    g_mqttPubs;

static AnimationInterface*                    g_anim = nullptr;
static bool                                   g_animDashboard = false;
static uint32_t                               g_animThroughputCounter = 0;
static uint32_t                               g_animDelayCounter = 0;
static uint32_t                               g_animLossCounter = 0;
static uint32_t                               g_animFlowCounter = 0;
static std::array<uint32_t, 6>                g_animDashboardNodeIds{};
static std::array<uint64_t, 3>                g_animMlClassWindow{};
static std::array<uint32_t, 3>                g_animLastPath{0, 1, 2};
static uint64_t                               g_animRouteSwitches = 0;
static GatewayRlAgent                         g_gatewayAgents[3];
static std::array<Ptr<QueueDisc>, 3>           g_pathQueues;
// Broker->Master egress disc: the one link every northbound message must
// cross, hence the only bottleneck a routing decision cannot avoid.
static Ptr<QueueDisc>                          g_brkQueue;
// Ground truth is diagnostics-only and stays off the wire.  Flow truth follows
// the same trailing one-second window as DT/RF and is the contract used by
// QoS/RL evaluation.  Message truth preserves the underlying semantic label
// for secondary analysis without leaking it into classification or routing.
static std::unordered_map<uint64_t, uint8_t>   g_msgTrueClass;
static std::unordered_map<uint64_t, uint8_t>   g_msgMessageTrueClass;
// Class requested by the gateway classifier.  In Station-actuator mode the
// wire header carries the class actually served by the edge marker so the
// Broker cannot accidentally promote a demoted message again.  Keep the
// requested class simulator-side for SLA accounting and controller feedback.
static std::unordered_map<uint64_t, uint8_t>   g_msgRequestedClass;
// Class the edge meter actually served each message on.  Filled by the meter
// callback and consumed at the Master, so no field is added to the wire format.
struct QosServiceInfo {
    uint8_t servedClass = 0;
    bool demoted = false;
    bool borrowed = false;
};
static std::unordered_map<uint64_t, QosServiceInfo> g_msgServed;

// Optional loss-aware controller feedback.  A pending entry is resolved by
// either an on-time delivery or its absolute OT-origin deadline.  Expired
// entries remain until a possible late delivery so that one message can never
// contribute two feedback samples.
struct QosDeadlineState {
    uint8_t assignedClass = 0;
    bool expired = false;
};
static std::unordered_map<uint64_t, QosDeadlineState> g_qosDeadlines;
static std::array<uint64_t, 3> g_qosTimeoutFeedback = {0, 0, 0};
static std::array<uint64_t, 3> g_qosOnTimeFeedback = {0, 0, 0};
static std::array<uint64_t, 3> g_qosLateAfterTimeout = {0, 0, 0};
static std::array<uint64_t, 3> g_qosEdgeOffered = {0, 0, 0};
static std::array<uint64_t, 3> g_qosEdgeDemoted = {0, 0, 0};
static std::array<uint64_t, 3> g_qosEdgeBorrowed = {0, 0, 0};

// =====================================================================
//   DYNAMIC QoS CONTROLLER (policer / marker plane)
// =====================================================================
// Closed loop over the per-class traffic profiles of the Broker's meter:
//   sensor      -> offered rate lambda_c and deadline miss rate mu_c per class
//   controller  -> r_c = r_min_c + (C - sum r_min) * w_c / sum w,
//                  with w_c = kappa_c * lambda_c * (1 + beta * mu_c)
//   actuator    -> MqttBrokerApp::SetClassRate
// The severity coefficients kappa_c are the ones the routing agent already
// uses, so the two control loops rank the classes consistently.
//
// Sampling note: the control period must be shorter than the tightest
// deadline (100 ms), but EMERGENCY offers only ~1 message per second, so a
// 100 ms window sees 0.1 messages on average.  The two requirements are in
// direct conflict, so the window only feeds an EWMA whose memory is about
// two seconds, while the actuator still updates every period.
struct QosCtrlClass {
    double bytesInWindow = 0.0;   // offered bytes, current window
    uint32_t delivered = 0;       // deliveries seen in the current window
    uint32_t missed = 0;
    uint32_t offered = 0;         // messages offered to this class
    uint32_t demoted = 0;         // of which re-marked down by the meter
    double lambdaBps = 0.0;       // EWMA of offered rate
    double violationNum = 0.0;    // EWMA numerator: misses or demotions
    double violationDen = 0.0;    // EWMA denominator: deliveries or offers
    double mu = 0.0;              // violationNum / violationDen
    double rateBps = 0.0;         // current profile
};
static std::array<QosCtrlClass, 3> g_qosCtrl;
static bool     g_qosCtrlOn      = false;
static double   g_qosCtrlMs      = 100.0;   // control period
static double   g_qosCtrlMemMs   = 2000.0;  // EWMA memory
static double   g_qosCtrlBudget  = 0.0;     // total budget C, bits/s
static double   g_qosCtrlBeta    = 2.0;     // feedback gain
static double   g_qosCtrlMinFrac = 0.25;    // r_min as a fraction of C/2
static double   g_qosCtrlMaxStep = 0.30;    // max relative change per period
// Which violation signal drives the feedback term. Both signals stay indexed
// by the classifier-assigned class carried in ScadaMqttHeader: broker
// demotion changes the serving socket/DSCP but deliberately does not rewrite
// that header. "miss" is the end-to-end SLA signal; "demote" is a faster local
// leading indicator that the class profile is exhausted.
static bool     g_qosCtrlUseDemote = false;
// When a class is violating its SLA/profile, allocate the shareable budget
// from violation pressure kappa*lambda*mu instead of retaining the baseline
// kappa*lambda term.  With pressure-hold enabled, the controller retains its
// current split while no violation is observed.
static bool     g_qosCtrlPressureOnly = false;
static double   g_qosCtrlPressurePower = 1.0;
static bool     g_qosCtrlPressureHold = false;
static double   g_qosCtrlInitialEfFrac = 0.5;
static bool     g_qosCtrlLossFeedback = false;
static bool     g_qosEmergencyBorrow = false;
static Ptr<MqttBrokerApp> g_broker;
// QoS control-plane location and data-plane actuator are deliberately
// separate.  "broker" preserves the original aggregate Broker->Master
// policer.  "station" keeps the controller centralized but enforces its
// rates in the three Station gateways before DSCP queueing and path choice.
static std::string g_qosActuator = "broker";

struct StationClassMeter {
    bool enabled = false;
    double rateBytesPerSec = 0.0;
    double burstBytes = 0.0;
    double tokens = 0.0;
    Time lastUpdate = Seconds(0);
};

struct StationCtrlClass {
    double bytesInWindow = 0.0;
    double lambdaBps = 0.0;
    double rateBps = 0.0;
    uint64_t offered = 0;
    uint64_t constrained = 0;
    double violationNum = 0.0;
    double violationDen = 0.0;
    double mu = 0.0;
};

struct StationMeterDecision {
    uint8_t served = 0;
    bool demoted = false;
    bool borrowed = false;
};

static std::array<std::array<StationClassMeter, 3>, 3> g_stationMeters;
static std::array<std::array<StationCtrlClass, 3>, 3> g_stationCtrl;
static std::ofstream g_qosCtrlCsv;
// When non-zero, every northbound message carries this DSCP regardless of
// class or prediction.  LIMITED USE: this only restamps the gateway->broker
// leg.  At the broker->master bottleneck the DSCP comes from MqttBrokerApp's
// three fixed per-class sockets, selected by the MQTT header class, so this
// flag does NOT produce an ML-free control arm there - measured 9.94% vs
// 9.98% EMERGENCY miss, i.e. indistinguishable from the static arm.  A real
// blanket arm has to change the broker's socket table or the header class.
static uint32_t                                g_qosBlanketTos = 0;
static std::ofstream                           g_qosQueueCsv;
static double                                  g_qosQueueMs = 10.0;
static std::array<Ptr<RateErrorModel>, 3>      g_pathErrorModels;
static std::vector<Ptr<RateErrorModel>> g_linkErrorModels;
static bool g_normalClean = true;
static std::ofstream                           g_rlTransitionCsv;
static std::ofstream                           g_rlDeliveryCsv;
static bool                                    g_rlDemoRouting = false;
static double                                  g_rlDemoPeriod = 2.0;
static double                                  g_rlDemoLoss = 0.05;
static double                                  g_rlDemoBaseLoss = 0.0;
static uint32_t                                g_rlDemoCycle = 0;
static uint32_t                                g_rlDemoDegradedPath = 3;

// =====================================================================
//                          HELPERS
// =====================================================================
static std::string IpToStr(Ipv4Address ip) {
    std::ostringstream os; ip.Print(os); return os.str();
}

// =====================================================================
//  DEVICE PROFILES  (ML realism improvement)
//  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////────
//  Each field device is assigned a DeviceProfile that captures its
//  intrinsic operational role (FAST control, NORMAL control, TELEMETRY,
//  BULK / historian).  Profile is FIXED for the device lifetime — only
//  scenario modifies behavior via multipliers.  Profile distribution is
//  protocol-specific (e.g., Modbus is mostly *_CTRL, MQTT is mostly
//  TELEMETRY/BULK).  RngSeedManager::SetRun(runId) provides deterministic
//  per-run device populations.
// =====================================================================
enum DeviceProfile {
    PROFILE_FAST_CTRL = 0,
    PROFILE_NORMAL_CTRL,
    PROFILE_TELEMETRY,
    PROFILE_BULK,
    N_PROFILES
};

static const char* ProfileName(DeviceProfile p) {
    static const char* names[] = {"FAST","NORMAL","TELE","BULK"};
    return (p < N_PROFILES) ? names[p] : "?";
}

// Profile baseline parameter ranges
struct ProfileRange {
    double minInt, maxInt;       // seconds, log-uniform
    uint32_t minPay, maxPay;     // bytes, uniform
    double minBurst, maxBurst;   // [0,1] burst probability range (DNP3)
};
static const ProfileRange PROFILE_RANGES[N_PROFILES] = {
    /* FAST   */ { 0.05,  0.20,   50,  150, 0.06, 0.10 },
    /* NORMAL */ { 0.20,  1.00,  100,  300, 0.03, 0.06 },
    /* TELE   */ { 1.00, 10.00,   50,  300, 0.01, 0.03 },
    /* BULK   */ { 2.00, 20.00,  500, 1500, 0.00, 0.02 }
};

// Per-protocol profile distribution (cumulative %).  Order: Modbus, DNP3,
// IEC104, OPC-UA, MQTT.  Each row sums to 100.
static const int PROFILE_DIST[5][N_PROFILES] = {
    /* Modbus */ { 35, 55, 10,  0 },
    /* DNP3   */ { 15, 55, 20, 10 },
    /* IEC104 */ { 50, 50,  0,  0 },
    /* OPC-UA */ { 10, 35, 45, 10 },
    /* MQTT   */ {  0,  5, 75, 20 }
};

static int ProtoIdx(const std::string& p) {
    if (p == "Modbus") return 0;
    if (p == "DNP3")   return 1;
    if (p == "IEC104") return 2;
    if (p == "OPC-UA") return 3;
    if (p == "MQTT")   return 4;
    return -1;
}

// Sample profile from per-protocol distribution.
static DeviceProfile PickProfile(const std::string& proto,
                                 Ptr<UniformRandomVariable> rng) {
    int pi = ProtoIdx(proto);
    if (pi < 0) return PROFILE_NORMAL_CTRL;
    int r = (int)(rng->GetValue() * 100.0);   // [0, 100)
    int cum = 0;
    for (int k = 0; k < N_PROFILES; ++k) {
        cum += PROFILE_DIST[pi][k];
        if (r < cum) return (DeviceProfile)k;
    }
    return PROFILE_NORMAL_CTRL;               // safety fallback
}

// Log-uniform sample in [lo, hi].
static double LogUniform(double lo, double hi,
                         Ptr<UniformRandomVariable> rng) {
    double lLo = std::log(lo);
    double lHi = std::log(hi);
    return std::exp(lLo + rng->GetValue() * (lHi - lLo));
}

// Per-instance baseline parameters derived from profile.
struct DeviceConfig {
    DeviceProfile profile;
    double        baseInt;      // seconds
    uint32_t      basePay;      // bytes
    double        burstProb;    // [0,1], used by DNP3
};

static DeviceConfig SampleDeviceConfig(const std::string& proto,
                                       Ptr<UniformRandomVariable> rng) {
    DeviceConfig c;
    c.profile = PickProfile(proto, rng);
    const ProfileRange& pr = PROFILE_RANGES[c.profile];
    c.baseInt = LogUniform(pr.minInt, pr.maxInt, rng);
    c.basePay = pr.minPay + (uint32_t)(rng->GetValue() * (pr.maxPay - pr.minPay));
    c.burstProb = pr.minBurst + rng->GetValue() * (pr.maxBurst - pr.minBurst);
    return c;
}

// =====================================================================
//  SCENARIO MULTIPLIERS
//  Apply per-(protocol, scenario) on top of per-instance baseline.
//  Interval multiplier acts on time-between-events; payload multiplier
//  scales the bytes-per-message.  These are read at SetScenario() time
//  inside each App and applied to its stored baseline.
// =====================================================================
struct ScenarioMul { double intMul; double payMul; };

namespace ns3 {
// Exposed to protocols.cc via extern declaration in namespace ns3.
std::pair<double,double> GetScenarioMulPair(const std::string& proto,
                                             const std::string& scn) {
    // {intMul, payMul}
    if (proto == "Modbus") {
        if (scn == "high_load") return {0.5, 1.2};
        if (scn == "emergency") return {1.0 / 1.5, 1.0}; // frequency x1.5
        return {1.0, 1.0};
    }
    if (proto == "DNP3") {
        // For DNP3 "interval" represents 1/event_rate.  int×0.5 == rate ×2.
        if (scn == "high_load") return {0.5, 1.2};
        if (scn == "emergency") return {1.0/7.0, 2.0};   // rate ×7, pay ×2
        return {1.0, 1.0};
    }
    if (proto == "IEC104") {
        if (scn == "high_load") return {0.5,  1.0};
        if (scn == "emergency") return {0.25, 1.0};
        return {1.0, 1.0};
    }
    if (proto == "OPC-UA") {
        if (scn == "high_load") return {0.5, 1.5};
        if (scn == "emergency") return {1.0, 1.0};
        return {1.0, 1.0};
    }
    if (proto == "MQTT") {
        // Emergency: shrink interval aggressively (app also enforces a hard
        // 0.1 s ceiling) and grow payload to model richer alarm context.
        if (scn == "emergency") return {0.2, 1.5};
        return {1.0, 1.0};
    }
    return {1.0, 1.0};
}
}  // namespace ns3

// DiffServ TOS byte for each protocol/scenario or traffic-class label.
// DT/RF modes do not restamp these values; they only predict traffic_class
// at the master for evaluation after provider DSCP erasure.
namespace ns3 {
uint8_t LabelToTos(const std::string& label, const std::string& scenario) {
    if (label == "EMERGENCY") return 184;  // EF
    if (label == "IMPORTANT") return 104;  // AF31
    if (label == "NORMAL")    return 0;    // BE

    // Baseline expert rule (scenario-aware): gateway/source DSCP marking.
    if (scenario == "emergency") {
        // Emergency traffic that must reach the master near-instantly.
        if (label == "IEC104" || label == "DNP3" || label == "MQTT")
            return 184;                                          // EF
    }
    if (label == "Modbus" || label == "IEC104" || label == "DNP3")
        return 104;                                              // AF31
    if (label == "OPC-UA")
        return 72;                                               // AF21
    return 0;                                                    // BE
}
}

static std::string DscpClass(uint8_t tos) {
    if (tos >= 168) return "EF";
    if (tos >= 96)  return "AF31";
    if (tos >= 64)  return "AF21";
    return "BE";
}

static const char* RlClassName(uint8_t cls) {
    if (cls >= 2) return "TIME_CRITICAL";
    if (cls == 1) return "OPERATIONAL";
    return "MONITORING";
}

static double RlDeadlineMs(uint8_t cls) {
    if (cls >= 2) return 100.0;
    if (cls == 1) return 300.0;
    return 1000.0;
}

static void ExpireQosDeadline(uint64_t messageId) {
    if (!g_qosCtrlOn || !g_qosCtrlLossFeedback) return;
    auto pending = g_qosDeadlines.find(messageId);
    if (pending == g_qosDeadlines.end() || pending->second.expired) return;
    uint8_t cls = pending->second.assignedClass;
    if (cls > 0 && cls < g_qosCtrl.size()) {
        // "delivered" is the EWMA denominator retained for CSV compatibility;
        // in loss-aware mode it means one resolved SLA outcome, including a
        // message that failed to arrive by its absolute deadline.
        ++g_qosCtrl[cls].delivered;
        ++g_qosCtrl[cls].missed;
        ++g_qosTimeoutFeedback[cls];
    }
    pending->second.expired = true;
}

static void OnMasterDelivery(const ScadaDeliveryInfo& info) {
    if (info.sourceGateway >= 3) return;
    g_gatewayAgents[info.sourceGateway].OnDelivery(
        info.messageId, info.chosenPath, info.delayMs);
    if (g_rlDeliveryCsv.is_open()) {
        uint8_t requestedCls = info.trafficClass;
        auto requested = g_msgRequestedClass.find(info.messageId);
        if (requested != g_msgRequestedClass.end()) {
            requestedCls = requested->second;
            g_msgRequestedClass.erase(requested);
        }
        double deadline = RlDeadlineMs(requestedCls);
        uint8_t trueCls = requestedCls;
        auto it = g_msgTrueClass.find(info.messageId);
        if (it != g_msgTrueClass.end()) {
            trueCls = it->second;
            g_msgTrueClass.erase(it);
        }
        double trueDeadline = RlDeadlineMs(trueCls);
        uint8_t messageTrueCls = trueCls;
        auto messageTruth = g_msgMessageTrueClass.find(info.messageId);
        if (messageTruth != g_msgMessageTrueClass.end()) {
            messageTrueCls = messageTruth->second;
            g_msgMessageTrueClass.erase(messageTruth);
        }
        double messageDeadline = RlDeadlineMs(messageTrueCls);
        if (g_qosCtrlOn && requestedCls < g_qosCtrl.size()) {
            if (g_qosCtrlLossFeedback) {
                auto pending = g_qosDeadlines.find(info.messageId);
                if (pending != g_qosDeadlines.end()) {
                    if (!pending->second.expired) {
                        QosCtrlClass& sensor =
                            g_qosCtrl[pending->second.assignedClass];
                        ++sensor.delivered;
                        if (info.delayMs > deadline) ++sensor.missed;
                        ++g_qosOnTimeFeedback[pending->second.assignedClass];
                    } else {
                        ++g_qosLateAfterTimeout[pending->second.assignedClass];
                    }
                    // If expired, the timeout already contributed exactly one
                    // miss; a late delivery only releases the tracking entry.
                    g_qosDeadlines.erase(pending);
                }
            } else {
                QosCtrlClass& sensor = g_qosCtrl[requestedCls];
                ++sensor.delivered;
                if (info.delayMs > deadline) ++sensor.missed;
            }
        }
        uint8_t servedCls = info.trafficClass;
        bool demoted = false;
        bool borrowed = false;
        auto served = g_msgServed.find(info.messageId);
        if (served != g_msgServed.end()) {
            servedCls = served->second.servedClass;
            demoted = served->second.demoted;
            borrowed = served->second.borrowed;
            g_msgServed.erase(served);
        }
        g_rlDeliveryCsv << std::fixed << std::setprecision(6)
            << Simulator::Now().GetSeconds() << ',' << info.messageId << ','
            << static_cast<uint32_t>(info.sourceGateway) << ','
            << static_cast<uint32_t>(info.chosenPath) << ','
            << RlClassName(requestedCls) << ',' << info.deviceId << ','
            << static_cast<uint32_t>(info.protocolId) << ','
            << info.payloadLength << ',' << info.delayMs << ',' << deadline
            << ',' << (info.delayMs <= deadline ? 1 : 0)
            << ',' << RlClassName(trueCls) << ',' << trueDeadline
            << ',' << (info.delayMs <= trueDeadline ? 1 : 0)
            << ',' << RlClassName(messageTrueCls) << ',' << messageDeadline
            << ',' << (info.delayMs <= messageDeadline ? 1 : 0)
            << ',' << RlClassName(servedCls)
            << ',' << (demoted ? 1 : 0)
            << ',' << (borrowed ? 1 : 0) << '\n';
    }
}

// Per-band occupancy of every bottleneck queue disc.  Written every
// g_qosQueueMs so the calibration can check that queueing delay has a
// continuous distribution instead of the binary 10 ms / RTO behaviour.
// Bands follow ScadaTosFilter: 0 = EF, 1 = AF31, 2 = AF21, 3 = BE.
static void LogQosQueues() {
    if (!g_qosQueueCsv.is_open()) return;
    double now = Simulator::Now().GetSeconds();
    auto dump = [&](const std::string& link, Ptr<QueueDisc> disc) {
        if (!disc) return;
        for (std::size_t band = 0; band < disc->GetNQueueDiscClasses(); ++band) {
            Ptr<QueueDisc> child = disc->GetQueueDiscClass(band)->GetQueueDisc();
            if (!child) continue;
            const QueueDisc::Stats& st = child->GetStats();
            g_qosQueueCsv << std::fixed << std::setprecision(4) << now << ','
                << link << ',' << band << ',' << child->GetNPackets() << ','
                << child->GetNBytes() << ','
                << st.nTotalDroppedPackets << ','
                << st.nTotalEnqueuedPackets << '\n';
        }
        g_qosQueueCsv << std::fixed << std::setprecision(4) << now << ','
            << link << ",root," << disc->GetNPackets() << ','
            << disc->GetNBytes() << ','
            << disc->GetStats().nTotalDroppedPackets << ','
            << disc->GetStats().nTotalEnqueuedPackets << '\n';
    };
    for (uint32_t path = 0; path < g_pathQueues.size(); ++path)
        dump("core" + std::to_string(path), g_pathQueues[path]);
    dump("brk_master", g_brkQueue);

    if (now + g_qosQueueMs / 1000.0 < g_simDuration)
        Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(g_qosQueueMs)),
                            &LogQosQueues);
}

static void SetStationClassProfile(uint32_t gateway, uint32_t trafficClass,
                                   double rateBitsPerSec,
                                   double burstBytes) {
    if (gateway >= g_stationMeters.size() || trafficClass >= 3) return;
    StationClassMeter& meter = g_stationMeters[gateway][trafficClass];
    meter.enabled = rateBitsPerSec > 0.0;
    meter.rateBytesPerSec = rateBitsPerSec / 8.0;
    meter.burstBytes = burstBytes;
    meter.tokens = burstBytes;
    meter.lastUpdate = Simulator::Now();
    g_stationCtrl[gateway][trafficClass].rateBps = rateBitsPerSec;
}

static void SetStationClassRate(uint32_t gateway, uint32_t trafficClass,
                                double rateBitsPerSec) {
    if (gateway >= g_stationMeters.size() || trafficClass >= 3) return;
    StationClassMeter& meter = g_stationMeters[gateway][trafficClass];
    if (!meter.enabled) return;
    Time now = Simulator::Now();
    meter.tokens = std::min(
        meter.burstBytes,
        meter.tokens + (now - meter.lastUpdate).GetSeconds()
                         * meter.rateBytesPerSec);
    meter.lastUpdate = now;
    meter.rateBytesPerSec = rateBitsPerSec / 8.0;
    g_stationCtrl[gateway][trafficClass].rateBps = rateBitsPerSec;
}

static bool ConsumeStationTokens(uint32_t gateway, uint32_t trafficClass,
                                 uint32_t bytes) {
    StationClassMeter& meter = g_stationMeters[gateway][trafficClass];
    Time now = Simulator::Now();
    meter.tokens = std::min(
        meter.burstBytes,
        meter.tokens + (now - meter.lastUpdate).GetSeconds()
                         * meter.rateBytesPerSec);
    meter.lastUpdate = now;
    if (meter.tokens < static_cast<double>(bytes)) return false;
    meter.tokens -= static_cast<double>(bytes);
    return true;
}

static StationMeterDecision ApplyStationMeter(uint32_t gateway,
                                               uint8_t requested,
                                               uint32_t bytes) {
    StationMeterDecision result;
    result.served = std::min<uint8_t>(requested, 2);
    if (gateway >= g_stationMeters.size() || result.served == 0)
        return result;

    const bool protecting = g_ddosProtectUrgent
        && g_securityState != SecurityState::CLEAN;
    // Explicit legacy-only ablation. Bounded mode always consumes tokens.
    if (protecting && g_ddosMeterPolicy == "legacy_bypass") {
        ++g_ddosMeterBypassPackets;
        return result;
    }

    // OP may borrow UNUSED TC tokens during inferred attack, but never mint
    // tokens or exceed the existing two-bucket contract. TC borrowing below
    // already uses the same rule in the opposite direction.
    if (protecting && g_ddosMeterPolicy == "bounded" && result.served == 1
        && g_stationMeters[gateway][1].enabled
        && g_stationMeters[gateway][2].enabled) {
        if (!ConsumeStationTokens(gateway, 1, bytes)) {
            if (ConsumeStationTokens(gateway, 2, bytes)) {
                result.borrowed = true;
            } else {
                result.served = 0;
                result.demoted = true;
            }
        }
        return result;
    }

    if (result.served == 2 && g_qosEmergencyBorrow
        && g_stationMeters[gateway][2].enabled
        && g_stationMeters[gateway][1].enabled) {
        if (!ConsumeStationTokens(gateway, 2, bytes)) {
            if (ConsumeStationTokens(gateway, 1, bytes)) {
                result.borrowed = true;
            } else {
                result.served = 0;
                result.demoted = true;
            }
        }
        return result;
    }

    while (result.served > 0
           && g_stationMeters[gateway][result.served].enabled
           && !ConsumeStationTokens(gateway, result.served, bytes)) {
        --result.served;
        result.demoted = true;
    }
    return result;
}

static void RunQosController() {
    if (!g_qosCtrlOn) return;
    if (g_qosActuator == "broker" && !g_broker) return;
    const double period = g_qosCtrlMs / 1000.0;
    // EWMA weight for a memory of g_qosCtrlMemMs
    const double a = std::clamp(period / (g_qosCtrlMemMs / 1000.0), 0.0, 1.0);
    const double kappa[3] = {1.0, 1.5, 3.0};      // NORMAL, IMPORTANT, EMERGENCY

    // Update per-egress estimators before the aggregate controller clears its
    // observation window.  Mixing feedback from unrelated physical egresses
    // can make one Station's E congestion steal I capacity from another, so
    // each local policy retains its own smoothed pressure signal.
    for (uint32_t gateway = 0; gateway < g_stationCtrl.size(); ++gateway) {
        for (uint32_t c = 1; c < 3; ++c) {
            StationCtrlClass& station = g_stationCtrl[gateway][c];
            const double lambdaNow = station.bytesInWindow * 8.0 / period;
            station.lambdaBps = (1.0 - a) * station.lambdaBps + a * lambdaNow;
            station.violationNum = (1.0 - a) * station.violationNum
                                 + a * static_cast<double>(station.constrained);
            station.violationDen = (1.0 - a) * station.violationDen
                                 + a * static_cast<double>(station.offered);
            station.mu = station.violationDen > 1e-12
                       ? std::clamp(station.violationNum
                                    / station.violationDen, 0.0, 1.0)
                       : 0.0;
            station.bytesInWindow = 0.0;
            station.offered = 0;
            station.constrained = 0;
        }
    }

    double demandWeight[3] = {0.0, 0.0, 0.0};
    double pressureWeight[3] = {0.0, 0.0, 0.0};
    double demandWeightSum = 0.0;
    double pressureWeightSum = 0.0;
    for (uint32_t c = 1; c < 3; ++c) {            // only the metered classes
        QosCtrlClass& s = g_qosCtrl[c];
        double lambdaNow = s.bytesInWindow * 8.0 / period;
        double numeratorNow;
        double denominatorNow;
        if (g_qosCtrlUseDemote) {
            numeratorNow = static_cast<double>(s.demoted);
            denominatorNow = static_cast<double>(s.offered);
        } else {
            numeratorNow = static_cast<double>(s.missed);
            denominatorNow = static_cast<double>(s.delivered);
        }
        s.lambdaBps = (1.0 - a) * s.lambdaBps + a * lambdaNow;
        // Smooth counts separately. An empty 100 ms window decays numerator
        // and denominator equally, so it carries no false "zero miss" sample
        // and preserves the ratio for sparse EMERGENCY traffic.
        s.violationNum = (1.0 - a) * s.violationNum + a * numeratorNow;
        s.violationDen = (1.0 - a) * s.violationDen + a * denominatorNow;
        s.mu = s.violationDen > 1e-12
             ? std::clamp(s.violationNum / s.violationDen, 0.0, 1.0)
             : 0.0;
        s.bytesInWindow = 0.0; s.delivered = 0; s.missed = 0;
        s.offered = 0; s.demoted = 0;
        demandWeight[c] = kappa[c] * s.lambdaBps;
        pressureWeight[c] = kappa[c] * s.lambdaBps * g_qosCtrlBeta
                          * std::pow(s.mu, g_qosCtrlPressurePower);
        demandWeightSum += demandWeight[c];
        pressureWeightSum += pressureWeight[c];
    }

    const bool pressureActive = g_qosCtrlPressureOnly
                             && pressureWeightSum > 1e-12;
    const bool pressureIdleHold = g_qosCtrlPressureOnly
                               && g_qosCtrlPressureHold
                               && !pressureActive;
    const double* weight = pressureActive ? pressureWeight : demandWeight;
    const double weightSum = pressureIdleHold ? 0.0
                           : (pressureActive
                                ? pressureWeightSum : demandWeightSum);
    // Legacy mode includes both demand and violation pressure.  Keeping the
    // expression here makes the new policy strictly opt-in.
    double legacyWeight[3] = {0.0, 0.0, 0.0};
    if (!g_qosCtrlPressureOnly) {
        for (uint32_t c = 1; c < 3; ++c)
            legacyWeight[c] = demandWeight[c] + pressureWeight[c];
        weight = legacyWeight;
    }
    const double activeWeightSum = !g_qosCtrlPressureOnly
        ? legacyWeight[1] + legacyWeight[2] : weightSum;

    const double rMin = std::min(g_qosCtrlBudget / 2.0,
        g_qosCtrlMinFrac * g_qosCtrlBudget / 2.0);
    const double shareable = std::max(0.0, g_qosCtrlBudget - 2.0 * rMin);
    double currentEmergency = g_qosCtrl[2].rateBps > 0.0
        ? g_qosCtrl[2].rateBps : g_qosCtrlBudget / 2.0;
    currentEmergency = std::clamp(currentEmergency, rMin,
                                  g_qosCtrlBudget - rMin);
    const double targetEmergency = activeWeightSum > 0.0
        ? rMin + shareable * weight[2] / activeWeightSum
        : (g_qosCtrlPressureOnly && g_qosCtrlPressureHold
            ? currentEmergency : g_qosCtrlBudget / 2.0);

    // Control one degree of freedom and derive IMPORTANT as C-r_E. Applying
    // slew limits independently used to make the instantaneous sum drift
    // between 3.56 and 4.24 kbps for a nominal 4 kbps experiment.
    const double deadBand = 0.05 * g_qosCtrlBudget;
    const double maxDelta = g_qosCtrlMaxStep * g_qosCtrlBudget / 2.0;
    double nextEmergency = currentEmergency;
    if (std::abs(targetEmergency - currentEmergency) > deadBand) {
        nextEmergency += std::clamp(targetEmergency - currentEmergency,
                                    -maxDelta, maxDelta);
    }
    nextEmergency = std::clamp(nextEmergency, rMin,
                               g_qosCtrlBudget - rMin);
    const double nextImportant = g_qosCtrlBudget - nextEmergency;
    if (g_qosActuator == "station") {
        // C is one aggregate contract shared by all Station egresses.  The
        // previous implementation accidentally gave every Station a complete
        // copy of C, so three Stations could admit 3*C while qos_control.csv
        // reported only C.  First split C between service classes, then split
        // each class across Stations from their local EWMA demand/pressure.
        const uint32_t stationCount = g_stationCtrl.size();
        for (uint32_t c = 1; c < 3; ++c) {
            const double classRate = c == 2
                ? nextEmergency : nextImportant;
            std::vector<double> localWeight(stationCount, 0.0);
            double localWeightSum = 0.0;
            for (uint32_t gateway = 0; gateway < stationCount; ++gateway) {
                const StationCtrlClass& s = g_stationCtrl[gateway][c];
                const double pressure = g_qosCtrlBeta
                    * std::pow(s.mu, g_qosCtrlPressurePower);
                localWeight[gateway] = s.lambdaBps * (1.0 + pressure);
                localWeightSum += localWeight[gateway];
            }
            // Keep a small reserve at every edge so a previously idle Station
            // can transmit its first priority packet and become observable.
            const double reserve = classRate * 0.05;
            const double distributable = std::max(
                0.0, classRate - reserve * stationCount);
            for (uint32_t gateway = 0; gateway < stationCount; ++gateway) {
                const double share = localWeightSum > 1e-12
                    ? localWeight[gateway] / localWeightSum
                    : 1.0 / stationCount;
                SetStationClassRate(
                    gateway, c, reserve + distributable * share);
            }
        }
        g_qosCtrl[2].rateBps = nextEmergency;
        g_qosCtrl[1].rateBps = nextImportant;
    } else {
        g_qosCtrl[2].rateBps = nextEmergency;
        g_qosCtrl[1].rateBps = nextImportant;
        g_broker->SetClassRate(2, nextEmergency);
        g_broker->SetClassRate(1, nextImportant);
    }

    if (g_qosCtrlCsv.is_open()) {
        double now = Simulator::Now().GetSeconds();
        for (uint32_t c = 1; c < 3; ++c) {
            const QosCtrlClass& s = g_qosCtrl[c];
            g_qosCtrlCsv << std::fixed << std::setprecision(4) << now << ','
                << RlClassName(static_cast<uint8_t>(c)) << ','
                << s.lambdaBps / 1000.0 << ',' << s.mu << ','
                << s.rateBps / 1000.0 << ',' << s.violationDen << ','
                << (g_qosCtrl[1].rateBps + g_qosCtrl[2].rateBps) / 1000.0
                << ',' << (g_qosCtrl[1].rateBps + g_qosCtrl[2].rateBps
                           - g_qosCtrlBudget) / 1000.0 << '\n';
        }
    }
    if (Simulator::Now().GetSeconds() + period < g_simDuration)
        Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(g_qosCtrlMs)),
                            &RunQosController);
}

static void UpdateRlPathQueues() {
    // A single DSCP band can saturate at PRIO_QUEUE_LIMIT even while the
    // other three bands are empty.  Normalize against one band so that this
    // congestion is visible to the path-health state.
    double capacity = std::max(1.0, static_cast<double>(PRIO_QUEUE_LIMIT));
    for (uint32_t path = 0; path < g_pathQueues.size(); ++path) {
        double ratio = g_pathQueues[path]
                     ? static_cast<double>(g_pathQueues[path]->GetNPackets())
                       / capacity
                     : 0.0;
        for (auto& agent : g_gatewayAgents) {
            agent.SetPathQueue(path, ratio);
        }
    }
    if (Simulator::Now().GetSeconds() + 0.1 < g_simDuration)
        Simulator::Schedule(MilliSeconds(100), &UpdateRlPathQueues);
}

static void RotateRlDemoPath() {
    if (!g_rlDemoRouting) return;

    if (g_rlDemoDegradedPath < g_pathErrorModels.size()
        && g_pathErrorModels[g_rlDemoDegradedPath]) {
        g_pathErrorModels[g_rlDemoDegradedPath]->SetAttribute(
            "ErrorRate", DoubleValue(g_rlDemoBaseLoss));
    }

    uint32_t path = (g_runId + g_rlDemoCycle) % g_pathErrorModels.size();
    if (g_pathErrorModels[path]) {
        g_pathErrorModels[path]->SetAttribute(
            "ErrorRate", DoubleValue(g_rlDemoLoss));
    }
    g_rlDemoDegradedPath = path;
    ++g_rlDemoCycle;

    NS_LOG_INFO("[RL demo] path " << path << " loss="
                << g_rlDemoLoss << " at t="
                << Simulator::Now().GetSeconds() << "s");

    if (Simulator::Now().GetSeconds() + g_rlDemoPeriod < g_simDuration) {
        Simulator::Schedule(Seconds(g_rlDemoPeriod), &RotateRlDemoPath);
    }
}

static uint8_t TrafficClassToTos(const std::string& trafficClass) {
    if (trafficClass == "TIME_CRITICAL" || trafficClass == "EMERGENCY")
        return 184; // EF
    if (trafficClass == "OPERATIONAL" || trafficClass == "IMPORTANT")
        return 104; // AF31
    if (trafficClass == "MONITORING" || trafficClass == "NORMAL")
        return 0;   // BE
    return 0;
}

static std::string NormalizeServiceClass(const std::string& value) {
    if (value == "TIME_CRITICAL" || value == "EMERGENCY")
        return "TIME_CRITICAL";
    if (value == "OPERATIONAL" || value == "IMPORTANT")
        return "OPERATIONAL";
    return "MONITORING";
}

static std::string DefaultTrafficClass(const std::string& protocol) {
    if (protocol == "Modbus" || protocol == "OPC-UA" || protocol == "MQTT")
        return "MONITORING";
    if (protocol == "DNP3" || protocol == "IEC104")
        return "OPERATIONAL";
    return "MONITORING";
}

static uint32_t ProtocolId(const std::string& protocol) {
    if (protocol == "Modbus") return 1;
    if (protocol == "DNP3")   return 2;
    if (protocol == "IEC104") return 3;
    if (protocol == "OPC-UA") return 4;
    if (protocol == "MQTT")   return 5;
    return 0;
}

static uint32_t DeviceTypeId(const std::string& role) {
    if (role.find("PLC")        != std::string::npos) return 1;
    if (role.find("ALARM")      != std::string::npos) return 2;
    if (role.find("PROTECTION") != std::string::npos) return 3;
    if (role.find("RECLOSER")   != std::string::npos) return 4;
    if (role.find("BAY")        != std::string::npos) return 5;
    if (role.find("RTU")        != std::string::npos) return 6;
    if (role.find("DER")        != std::string::npos) return 7;
    if (role.find("BULK")       != std::string::npos) return 8;
    if (role.find("TELEMETRY")  != std::string::npos) return 9;
    if (role.find("BREAKER")    != std::string::npos) return 10;
    if (role.find("MIXED")      != std::string::npos) return 11;
    return 0;
}

static uint32_t MessageFamilyId(const std::string& family) {
    if (family == "TELEMETRY") return 1;
    if (family == "STATUS")    return 2;
    if (family == "ALARM")     return 3;
    if (family == "TRIP")      return 4;
    if (family == "BULK")      return 5;
    return 0;
}

// =====================================================================
//                  SCADA TOS PACKET FILTER (4-band classifier)
// =====================================================================
// Subclass of Ipv4PacketFilter so PrioQueueDisc can route packets into
// one of 4 priority bands purely based on the IP TOS byte that the App
// stamped via socket->SetIpTos(...).
namespace ns3 {
class ScadaTosFilter : public Ipv4PacketFilter {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::ScadaTosFilter")
            .SetParent<Ipv4PacketFilter>()
            .SetGroupName("TrafficControl")
            .AddConstructor<ScadaTosFilter>();
        return tid;
    }
    ScadaTosFilter() {}
    ~ScadaTosFilter() override {}

private:
    int32_t DoClassify(Ptr<QueueDiscItem> item) const override {
        Ptr<Ipv4QueueDiscItem> ipItem = DynamicCast<Ipv4QueueDiscItem>(item);
        if (!ipItem) return PacketFilter::PF_NO_MATCH;
        uint8_t tos = ipItem->GetHeader().GetTos();
        if (tos >= 168) return 0;   // EF   → highest band
        if (tos >= 96)  return 1;   // AF31 → band 1
        if (tos >= 64)  return 2;   // AF21 → band 2
        return 3;                    // BE   → lowest band
    }
    bool CheckProtocol(Ptr<QueueDiscItem> item) const override {
        return DynamicCast<Ipv4QueueDiscItem>(item) != nullptr;
    }
};
NS_OBJECT_ENSURE_REGISTERED(ScadaTosFilter);
}

// =====================================================================
//                          APP TX TRACE
// =====================================================================
// Every App's "Tx" trace source feeds this; we bin packet counts by
// source-IP key so that the per-window logger can attach an app_tx_pkts
// column to each FlowMonitor flow.
static void OnAppTx(std::string key, Ptr<const Packet>) {
    g_accumByKey[key]++;
}

static double ScenarioStart(double t) {
    if (t < BOOTSTRAP_TIME + g_scenarioDur) return BOOTSTRAP_TIME;
    if (t < BOOTSTRAP_TIME + 2 * g_scenarioDur) return BOOTSTRAP_TIME + g_scenarioDur;
    return BOOTSTRAP_TIME + 2 * g_scenarioDur;
}

static double EffectiveWarmupDuration() {
    return std::min(WARMUP_DURATION, std::max(0.0, g_scenarioDur * 0.20));
}

static void ClassifyPacketTime(uint32_t deviceId, double t,
                               uint32_t& isWarmup,
                               uint32_t& isTransition,
                               uint32_t& trainUsable) {
    isTransition = 0;

    double scStart = ScenarioStart(t);
    isWarmup = ((t - scStart) < EffectiveWarmupDuration()) ? 1 : 0;

    for (const auto& w : g_incidentWindows) {
        if (w.deviceId != deviceId) continue;
        if ((t >= w.start - TRANSITION_BUFFER && t < w.start) ||
                   (t > w.end && t <= w.end + TRANSITION_BUFFER)) {
            isTransition = 1;
        }
    }

    trainUsable = (!isWarmup && !isTransition) ? 1 : 0;
}

static void OnPacketTrace(ScadaTraceContext* ctx, Ptr<const Packet> p) {
    if (!ctx || !p) return;
    double now = Simulator::Now().GetSeconds();
    double featureTime = std::round(now * 1e6) / 1e6;
    uint32_t isWarmup, isTransition, trainUsable;
    ClassifyPacketTime(ctx->deviceId, now, isWarmup,
                       isTransition, trainUsable);
    std::string label = GetScadaServiceClass(p);
    std::string messageKind = GetScadaMessageKind(p);
    uint32_t incidentActive = label == "MONITORING" ? 0 : 1;

    if (ctx->direction == "downlink") {
        g_behaviorFeatures.ObserveDownlink(
            ctx->deviceId, ctx->protocolId, featureTime, p->GetSize());
    }

    if (!g_packetCsv.is_open()) return;
    g_packetCsv << g_runId << ','
                << std::fixed << std::setprecision(6) << now << ','
                << ctx->nodeId << ','
                << ctx->deviceId << ','
                << ctx->protocolId << ','
                << ctx->protocol << ','
                << ctx->direction << ','
                << p->GetSize() << ','
                << incidentActive << ','
                << isWarmup << ','
                << isTransition << ','
                << trainUsable << ','
                << label << ','
                << messageKind << ','
                << g_scenario << ','
                << ScenarioStart(now) << ','
                << ctx->deviceRole << '\n';
    ++g_packetRowCount;
}

// Gateway 1:1 protocol translation hook.  Bound to each field device's slave
// "Tx" trace: every OT data frame the device sends upward triggers exactly one
// MQTT publish on the Station, stamped with the DSCP for (source protocol +
// current scenario).  Preserves the source's timing/burst shape northbound.
struct GatewayPublisherSet {
    uint32_t gw = 0;
    uint32_t deviceId = 0;
    uint32_t protocolId = 0;
    std::string protocol;
    std::array<Ptr<MqttPublisherApp>, 3> pathPub;
};

// Ground truth for classifier evaluation follows the same trailing one-second
// flow window as the observable features.  It is diagnostics-only: neither
// this history nor the packet's semantic label is passed to DT/RF.
struct ServiceWindowTruthState {
    std::string scenario;
    double scenarioStart = 0.0;
    std::deque<std::pair<double, std::string>> history;
};
static std::map<uint64_t, ServiceWindowTruthState> g_serviceWindowTruth;

static std::string ObserveServiceWindowTruth(uint32_t deviceId,
                                             uint32_t protocolId,
                                             double now,
                                             const std::string& messageClass) {
    const uint64_t key = (static_cast<uint64_t>(deviceId) << 32) | protocolId;
    auto& state = g_serviceWindowTruth[key];
    const double scenarioStart = ScenarioStart(now);
    if (state.scenario != g_scenario ||
        std::abs(state.scenarioStart - scenarioStart) > 1e-6) {
        state = ServiceWindowTruthState{};
        state.scenario = g_scenario;
        state.scenarioStart = scenarioStart;
    }
    while (!state.history.empty() && state.history.front().first < now - 1.0)
        state.history.pop_front();
    state.history.emplace_back(now, messageClass);

    bool operational = false;
    for (const auto& sample : state.history) {
        if (sample.second == "TIME_CRITICAL") return "TIME_CRITICAL";
        if (sample.second == "OPERATIONAL") operational = true;
    }
    return operational ? "OPERATIONAL" : "MONITORING";
}

static void OnOtUplink(GatewayPublisherSet* routes, Ptr<const Packet> packet) {
    if (!routes || routes->gw >= 3) return;
    const uint64_t originTimeNs = Simulator::Now().GetNanoSeconds();
    double now = Simulator::Now().GetSeconds();
    double featureTime = std::round(now * 1e6) / 1e6;
    std::string messageKind = GetScadaMessageKind(packet);
    const std::string messageTruthClass = GetScadaServiceClass(packet);
    const std::string windowTruthClass = ObserveServiceWindowTruth(
        routes->deviceId, routes->protocolId, featureTime, messageTruthClass);
    std::string trafficClass;
    std::string rawTrafficClass;
    double features[N_FEATURES] = {};
    ServiceClassPrediction prediction;
    bool baselineReady = false;
    bool qosSafetyPromoted = false;

    if (g_mode == "dt" || g_mode == "rf") {
        uint32_t isWarmup, isTransition, trainUsable;
        ClassifyPacketTime(routes->deviceId, featureTime, isWarmup,
                           isTransition, trainUsable);
        baselineReady = g_behaviorFeatures.AddUplink(
            routes->deviceId, routes->protocolId, g_scenario,
            ScenarioStart(featureTime), isWarmup != 0, featureTime,
            packet->GetSize(), messageKind != "PROTOCOL",
            features);

        if (baselineReady && messageKind != "PROTOCOL") {
            prediction = MlPredictServiceClass(g_mode, features);
            trafficClass = ServiceClassName(prediction.serviceClass);
        } else if (messageKind == "PROTOCOL") {
            trafficClass = "MONITORING";
        } else {
            // A flow without enough observations receives the middle service
            // class.  This avoids sending a newly-seen control flow to BE and
            // avoids granting EF without behavioral evidence.
            trafficClass = "OPERATIONAL";
        }
    } else {
        // Oracle/expert reference mode. Ground truth is never used here when
        // mode is dt or rf.
        trafficClass = GetScadaServiceClass(packet);
    }

    rawTrafficClass = trafficClass;
    if (g_anim && g_animDashboard) {
        const uint8_t dashboardClass = RlTrafficClassId(
            ParseRlTrafficClass(rawTrafficClass));
        if (dashboardClass < g_animMlClassWindow.size()) {
            ++g_animMlClassWindow[dashboardClass];
        }
    }
    if ((g_mode == "dt" || g_mode == "rf") && baselineReady &&
        messageKind != "PROTOCOL" && g_qosMode == "private" &&
        g_qosSafetyPromote && prediction.modelAvailable &&
        prediction.serviceClass == SC_MONITORING &&
        prediction.priorityEvidence >= g_qosSafetyRatio) {
        // This is a service safeguard, not a new ML prediction: uncertain
        // flows receive AF31, never EF, and the raw RF/DT class remains in
        // scada_runtime_ml.csv for an unbiased classifier evaluation.
        trafficClass = "OPERATIONAL";
        qosSafetyPromoted = true;
    }

    // Allocate the routing/message identity before diagnostics are written so
    // generation and end-to-end delivery can be joined exactly, including
    // packets that arrive after an experiment-window boundary.
    RlTrafficClass cls = ParseRlTrafficClass(trafficClass);
    const uint8_t requestedClass = RlTrafficClassId(cls);
    StationMeterDecision stationDecision;
    stationDecision.served = requestedClass;
    const RlTrafficClass evaluationTrueClass =
        ParseRlTrafficClass(windowTruthClass);
    RlDecision decision = g_gatewayAgents[routes->gw].SelectPath(
        cls, packet->GetSize(), evaluationTrueClass);

    if (g_runtimeMlCsv.is_open() && (g_mode == "dt" || g_mode == "rf")) {
        const std::string& truthClass = windowTruthClass;
        bool correct = rawTrafficClass == truthClass;
        bool evaluated = baselineReady && messageKind != "PROTOCOL";
        if (evaluated) {
            ++g_runtimeRows;
            if (correct) ++g_runtimeCorrect;
        }
        g_runtimeMlCsv << std::fixed << std::setprecision(6)
            << now << ',' << decision.messageId << ','
            << routes->deviceId << ',' << routes->protocolId << ','
            << routes->protocol << ',' << messageKind << ','
            << (baselineReady ? 1 : 0) << ','
            << prediction.probability[SC_TIME_CRITICAL] << ','
            << prediction.probability[SC_OPERATIONAL] << ','
            << prediction.probability[SC_MONITORING] << ','
            << prediction.confidence << ',' << rawTrafficClass << ','
            << prediction.priorityEvidence << ','
            << (qosSafetyPromoted ? 1 : 0) << ',' << trafficClass << ','
            << truthClass << ',' << (evaluated ? 1 : 0) << ','
            << (correct ? 1 : 0);
        for (double value : features) g_runtimeMlCsv << ',' << value;
        double requestStatistics[8] = {};
        g_behaviorFeatures.GetRequestStatistics(routes->deviceId,
            routes->protocolId, featureTime, requestStatistics);
        for (double value : requestStatistics) g_runtimeMlCsv << ',' << value;
        g_runtimeMlCsv << '\n';
    }

    // The classifier's requested class remains the routing/SLA identity.  In
    // Station-actuator mode the local meter may assign a lower DSCP service
    // class before the packet enters the selected Station egress queue.
    if (g_rlDeliveryCsv.is_open()) {
        g_msgRequestedClass[decision.messageId] = requestedClass;
        g_msgTrueClass[decision.messageId] =
            RlTrafficClassId(ParseRlTrafficClass(windowTruthClass));
        g_msgMessageTrueClass[decision.messageId] =
            RlTrafficClassId(ParseRlTrafficClass(messageTruthClass));
    }
    uint32_t path = decision.path;
    if (path >= routes->pathPub.size() || !routes->pathPub[path]) {
        path = routes->gw;
    }
    if (g_anim && g_animDashboard) {
        if (path != g_animLastPath[routes->gw]) ++g_animRouteSwitches;
        g_animLastPath[routes->gw] = path;
    }
    if (g_qosActuator == "station") {
        ScadaMqttHeader meterHeader;
        const uint32_t meterBytes = packet->GetSize()
                                  + meterHeader.GetSerializedSize();
        // Meter the selected physical egress path, not merely the source
        // Station.  This matches the router pipeline: classify, route lookup,
        // then egress policing/marking and queueing.
        bool sourceAdmitted = true;
        if (g_qosSourceLimit && g_qosMode == "private" && requestedClass > 0) {
            const uint64_t sourceKey = (uint64_t(routes->deviceId) << 32)
                                     | routes->protocolId;
            sourceAdmitted = g_boundaryPolicies[routes->gw].AdmitPriority(now,sourceKey,meterBytes);
        }
        if (sourceAdmitted) stationDecision = ApplyStationMeter(path,requestedClass,meterBytes);
        else { stationDecision.served=0; stationDecision.demoted=true; stationDecision.borrowed=false; }
        if (g_qosCtrlOn && requestedClass < g_qosCtrl.size()) {
            QosCtrlClass& sensor = g_qosCtrl[requestedClass];
            sensor.bytesInWindow += meterBytes;
            ++sensor.offered;
            if (stationDecision.demoted || stationDecision.borrowed)
                ++sensor.demoted;
            g_stationCtrl[path][requestedClass].bytesInWindow += meterBytes;
            ++g_stationCtrl[path][requestedClass].offered;
            if (stationDecision.demoted || stationDecision.borrowed)
                ++g_stationCtrl[path][requestedClass].constrained;
            ++g_qosEdgeOffered[requestedClass];
            if (stationDecision.demoted)
                ++g_qosEdgeDemoted[requestedClass];
            if (stationDecision.borrowed)
                ++g_qosEdgeBorrowed[requestedClass];
        }
        g_msgServed[decision.messageId] = {
            stationDecision.served,
            stationDecision.demoted,
            stationDecision.borrowed};
        if (g_qosCtrlOn && g_qosCtrlLossFeedback && requestedClass > 0) {
            g_qosDeadlines[decision.messageId] = {requestedClass, false};
            Time expires = NanoSeconds(originTimeNs)
                         + MilliSeconds(static_cast<uint64_t>(
                             RlDeadlineMs(requestedClass)));
            if (expires <= Simulator::Now()) {
                Simulator::ScheduleNow(
                    &ExpireQosDeadline, decision.messageId);
            } else {
                Simulator::Schedule(
                    expires - Simulator::Now(),
                    &ExpireQosDeadline, decision.messageId);
            }
        }
    }
    Ptr<MqttPublisherApp> pub = routes->pathPub[path];
    if (!pub) return;
    const std::string servedTrafficClass =
        RlClassName(stationDecision.served);
    uint8_t stampTos = g_qosBlanketTos
                     ? static_cast<uint8_t>(g_qosBlanketTos)
                     : TrafficClassToTos(servedTrafficClass);
    pub->PublishOnce(stampTos, packet->GetSize(),
                     decision.messageId, routes->deviceId,
                     static_cast<uint8_t>(routes->protocolId),
                     static_cast<uint8_t>(routes->gw),
                     static_cast<uint8_t>(path),
                     g_qosActuator == "station"
                         ? stationDecision.served : requestedClass,
                     originTimeNs);
}

// =====================================================================
//                          WINDOW LOGGER
// =====================================================================
static void OnWindow() {
    double tStart = g_windowId * WINDOW_SIZE;
    double tEnd   = tStart + WINDOW_SIZE;

    uint64_t dashboardRxBytes = 0;
    uint64_t dashboardRxPackets = 0;
    uint64_t dashboardLostPackets = 0;
    uint64_t dashboardDelayNs = 0;
    uint32_t dashboardFlowCount = 0;

    g_monitor->CheckForLostPackets();
    auto stats = g_monitor->GetFlowStats();

    for (auto& kv : stats) {
        FlowId   id = kv.first;
        const auto& fs = kv.second;
        FlowSnap prev = g_prevSnap.count(id) ? g_prevSnap[id]
                                              : FlowSnap{0,0,0,0,0,0};

        uint64_t dTx  = fs.txPackets  - prev.txPkts;
        uint64_t dRx  = fs.rxPackets  - prev.rxPkts;
        uint64_t dBy  = fs.rxBytes    - prev.rxBytes;
        uint64_t dLs  = fs.lostPackets - prev.lostPkts;
        uint64_t dDly = fs.delaySum.GetNanoSeconds()
                        - (int64_t)prev.delaySumNs;
        uint64_t dJit = fs.jitterSum.GetNanoSeconds()
                        - (int64_t)prev.jitterSumNs;

        g_prevSnap[id] = {fs.txPackets, fs.rxPackets, fs.rxBytes,
                          fs.lostPackets,
                          (uint64_t)fs.delaySum.GetNanoSeconds(),
                          (uint64_t)fs.jitterSum.GetNanoSeconds()};

        // ── A1: skip empty windows entirely ──
        if (dTx == 0 && dRx == 0) continue;

        dashboardRxBytes += dBy;
        dashboardRxPackets += dRx;
        dashboardLostPackets += dLs;
        dashboardDelayNs += dDly;
        ++dashboardFlowCount;

        auto ft  = g_classifier->FindFlow(id);
        std::string srcIp = IpToStr(ft.sourceAddress);
        std::string dstIp = IpToStr(ft.destinationAddress);
        uint16_t   sport = ft.sourcePort;
        uint16_t   dport = ft.destinationPort;

        // Lookup label by (dst, dport).  If miss, fall back to (src, sport)
        // so reverse-direction flows (e.g. slave→master responses) get the
        // same label as their forward counterpart.
        std::string lblKey = dstIp + ":" + std::to_string(dport);
        std::string label = g_flowLabelMap.count(lblKey)
                            ? g_flowLabelMap[lblKey] : "";
        std::string role = g_flowRoleMap.count(lblKey)
                           ? g_flowRoleMap[lblKey] : "";
        std::string trafficClass = g_flowClassMap.count(lblKey)
                                   ? g_flowClassMap[lblKey] : "";
        uint32_t protocolId = g_flowProtoIdMap.count(lblKey)
                              ? g_flowProtoIdMap[lblKey] : 0;
        uint32_t deviceTypeId = g_flowDeviceTypeMap.count(lblKey)
                                ? g_flowDeviceTypeMap[lblKey] : 0;
        uint32_t messageFamilyId = g_flowMsgFamilyMap.count(lblKey)
                                   ? g_flowMsgFamilyMap[lblKey] : 0;
        uint32_t isEventCapable = g_flowEventCapMap.count(lblKey)
                                  ? g_flowEventCapMap[lblKey] : 0;
        uint32_t isMixedDevice = g_flowMixedMap.count(lblKey)
                                 ? g_flowMixedMap[lblKey] : 0;
        if (label.empty()) {
            std::string srcKey = srcIp + ":" + std::to_string(sport);
            label = g_flowLabelMap.count(srcKey)
                    ? g_flowLabelMap[srcKey] : "Other";
            role = g_flowRoleMap.count(srcKey)
                   ? g_flowRoleMap[srcKey] : role;
            trafficClass = g_flowClassMap.count(srcKey)
                           ? g_flowClassMap[srcKey] : trafficClass;
            protocolId = g_flowProtoIdMap.count(srcKey)
                         ? g_flowProtoIdMap[srcKey] : protocolId;
            deviceTypeId = g_flowDeviceTypeMap.count(srcKey)
                           ? g_flowDeviceTypeMap[srcKey] : deviceTypeId;
            messageFamilyId = g_flowMsgFamilyMap.count(srcKey)
                              ? g_flowMsgFamilyMap[srcKey] : messageFamilyId;
            isEventCapable = g_flowEventCapMap.count(srcKey)
                             ? g_flowEventCapMap[srcKey] : isEventCapable;
            isMixedDevice = g_flowMixedMap.count(srcKey)
                            ? g_flowMixedMap[srcKey] : isMixedDevice;
        }
        if (role.empty()) role = "UNK";
        if (trafficClass.empty()) trafficClass = DefaultTrafficClass(label);
        if (protocolId == 0) protocolId = ProtocolId(label);
        if (deviceTypeId == 0) deviceTypeId = DeviceTypeId(role);

        double thrMbps  = (dBy * 8.0) / (WINDOW_SIZE * 1e6);
        double meanDlyMs = (dRx > 0) ? (dDly / (double)dRx) / 1e6 : 0.0;
        // Jitter: ns-3 FlowMonitor accumulates per-packet jitter (RFC 3550
        // EWMA estimator).  We report mean per-window in ms.  Need ≥2
        // received packets in the window for jitter to be meaningful.
        double jitMs = (dRx > 1) ? (dJit / (double)(dRx - 1)) / 1e6 : 0.0;

        // app_tx_pkts attribution: key = label + "@" + srcIp so that
        // multi-protocol nodes (e.g. Master running Modbus+DNP3+IEC+OPCUA
        // simultaneously) don't aggregate into a single counter.
        std::string txKey = label + "@" + srcIp;
        uint32_t appTxPkts = g_accumByKey.count(txKey)
                             ? g_accumByKey[txKey] : 0;

        uint8_t tos = TrafficClassToTos(trafficClass);

        CsvRow row;
        row.t_start       = tStart;
        row.t_end         = tEnd;
        row.flow_id       = id;
        row.src           = srcIp;
        row.dst           = dstIp;
        row.src_port      = sport;
        row.dst_port      = dport;
        row.pkts_tx       = dTx;
        row.pkts_rx       = dRx;
        row.bytes_rx      = dBy;
        row.pkts_lost     = dLs;
        row.thr_mbps      = thrMbps;
        row.mean_delay_ms = meanDlyMs;
        row.jitter_ms     = jitMs;
        row.app_tx_pkts   = appTxPkts;
        row.dscp          = tos;
        row.dscp_class    = DscpClass(tos);
        row.protocol      = label;
        row.device_role   = role;
        row.traffic_class = trafficClass;
        row.protocol_id = protocolId;
        row.device_type_id = deviceTypeId;
        row.message_family_id = messageFamilyId;
        row.is_event_capable = isEventCapable;
        row.is_mixed_device = isMixedDevice;
        row.scenario      = g_scenario;

        g_csvRows.push_back(row);
    }

    if (g_anim && g_animDashboard) {
        const double throughputMbps = dashboardRxBytes * 8.0
                                    / (WINDOW_SIZE * 1e6);
        const double averageDelayMs = dashboardRxPackets > 0
            ? dashboardDelayNs / static_cast<double>(dashboardRxPackets) / 1e6
            : 0.0;
        const uint64_t resolvedPackets = dashboardRxPackets
                                       + dashboardLostPackets;
        const double packetLossPct = resolvedPackets > 0
            ? 100.0 * dashboardLostPackets
              / static_cast<double>(resolvedPackets)
            : 0.0;

        std::string phase = "BOOTSTRAP";
        double phaseStart = 0.0;
        double phaseEnd = BOOTSTRAP_TIME;
        if (g_scenario == "normal") {
            phase = "NORMAL";
            phaseStart = BOOTSTRAP_TIME;
            phaseEnd = BOOTSTRAP_TIME + g_scenarioDur;
        } else if (g_scenario == "high_load") {
            phase = "HIGH-LOAD";
            phaseStart = BOOTSTRAP_TIME + g_scenarioDur;
            phaseEnd = BOOTSTRAP_TIME + 2.0 * g_scenarioDur;
        } else if (g_scenario == "emergency") {
            phase = "EMERGENCY";
            phaseStart = BOOTSTRAP_TIME + 2.0 * g_scenarioDur;
            phaseEnd = BOOTSTRAP_TIME + 3.0 * g_scenarioDur;
        }

        auto updateDashboardRow = [](uint32_t row, const std::string& text) {
            g_anim->UpdateNodeDescription(g_animDashboardNodeIds.at(row), text);
        };

        uint32_t routeAnomalies = 0;
        for (const auto& station : g_routeFingerprints) {
            for (const auto& path : station) {
                if (path.anomalous) ++routeAnomalies;
            }
        }
        const bool routingAlert = routeAnomalies > 0;
        std::string security = "NO";
        if (routingAlert && g_securityState != SecurityState::CLEAN) {
            security = "MIXED";
        } else if (routingAlert) {
            security = "RIP_ATTACK";
        } else if (g_securityState == SecurityState::SUSPECTED) {
            security = "SUSPECTED";
        } else if (g_securityState == SecurityState::UNDER_ATTACK) {
            security = "UNDER_ATTACK";
        } else if (g_securityState == SecurityState::RECOVERY) {
            security = "RECOVERY";
        }

        std::ostringstream value;
        value << "SECURITY: " << security;
        updateDashboardRow(0, value.str());

        value.str("");
        value.clear();
        value << "PHASE: " << phase << " [" << std::fixed
              << std::setprecision(0) << phaseStart << '-' << phaseEnd
              << " s]";
        updateDashboardRow(1, value.str());

        value.str("");
        value.clear();
        value << "ML CLASS: TC=" << g_animMlClassWindow[2]
              << " | OP=" << g_animMlClassWindow[1]
              << " | MON=" << g_animMlClassWindow[0];
        updateDashboardRow(2, value.str());

        value.str("");
        value.clear();
        value << "QOS RATE: TC=" << std::fixed << std::setprecision(1)
              << g_qosCtrl[2].rateBps / 1000.0 << " | OP="
              << g_qosCtrl[1].rateBps / 1000.0 << " kbps";
        updateDashboardRow(3, value.str());

        value.str("");
        value.clear();
        value << "ROUTING: ";
        bool alternatePath = false;
        for (uint32_t station = 0; station < g_animLastPath.size(); ++station) {
            if (g_animLastPath[station] == station) continue;
            if (alternatePath) value << " | ";
            value << 'S' << station << "->S" << g_animLastPath[station];
            alternatePath = true;
        }
        if (!alternatePath) value << "HOME";
        value << " | SWITCH=" << g_animRouteSwitches;
        updateDashboardRow(4, value.str());

        value.str("");
        value.clear();
        value << "NET: Delay=" << std::fixed << std::setprecision(3)
              << averageDelayMs << " ms | Loss=" << packetLossPct << " %";
        updateDashboardRow(5, value.str());
        g_anim->UpdateNodeCounter(
            g_animThroughputCounter, 0, throughputMbps);
        g_anim->UpdateNodeCounter(g_animDelayCounter, 0, averageDelayMs);
        g_anim->UpdateNodeCounter(g_animLossCounter, 0, packetLossPct);
        g_anim->UpdateNodeCounter(
            g_animFlowCounter, 0, dashboardFlowCount);
        g_animMlClassWindow.fill(0);
    }

    g_windowId++;
    if (Simulator::Now().GetSeconds() < g_simDuration - 1e-6) {
        Simulator::Schedule(Seconds(WINDOW_SIZE), &OnWindow);
    }
}

// =====================================================================
//                       DDOS SECURITY STATE
// =====================================================================
static const char* SecurityStateName(SecurityState state) {
    switch (state) {
    case SecurityState::CLEAN:        return "CLEAN";
    case SecurityState::SUSPECTED:    return "SUSPECTED";
    case SecurityState::UNDER_ATTACK: return "UNDER_ATTACK";
    case SecurityState::RECOVERY:     return "RECOVERY";
    }
    return "UNKNOWN";
}

static void SetDdosTruth(bool active) {
    g_ddosTruthActive = active;
    std::cout << "[ddos-generator] t=" << std::fixed << std::setprecision(3)
              << Simulator::Now().GetSeconds() << "s truth="
              << (active ? "ATTACK" : "CLEAN") << '\n';
}

static void CountMasterIngress(Ptr<const Packet> packet) {
    if (!packet) return;
    g_ddosIngressBytes += packet->GetSize();
    ++g_ddosIngressPackets;
    Ptr<Packet> copy = packet->Copy();
    PppHeader ppp;
    if (copy->RemoveHeader(ppp) == 0) return;
    Ipv4Header ipv4;
    if (copy->RemoveHeader(ipv4) == 0) return;
    ++g_ddosSourcePackets[ipv4.GetSource().Get()];
    if (ipv4.GetProtocol() == 17) {
        ++g_ddosUdpPackets;
        UdpHeader udp;
        if (copy->PeekHeader(udp) > 0 && udp.GetDestinationPort() == 9400) {
            ++g_ddosObservedAttackPackets;
            if ((ipv4.GetTos() >> 2) == 46) ++g_ddosObservedAttackEfPackets;
        }
    }
}

static void ConfigureDdosBeQueueLimits() {
    if (!g_ddosProtectUrgent) return;
    auto setBeLimit = [&](Ptr<QueueDisc> disc) {
        if (!disc || disc->GetNQueueDiscClasses() < 4) return;
        Ptr<QueueDisc> be = disc->GetQueueDiscClass(3)->GetQueueDisc();
        if (be) be->SetMaxSize(QueueSize(
            std::to_string(g_ddosBeQueueLimit) + "p"));
    };
    for (Ptr<QueueDisc> disc : g_pathQueues) setBeLimit(disc);
    setBeLimit(g_brkQueue);
}

static void SampleStationBoundary() {
    if (g_boundaryCsv.is_open()) {
        for (uint32_t station=0; station<3; ++station) {
            const auto& c=g_boundaryPolicies[station].counters;
            g_boundaryCsv << Simulator::Now().GetSeconds() << ',' << station
                << ',' << g_scenario << ','
                << (g_qosIngressGuard && g_qosMode=="private") << ','
                << (g_qosSourceLimit && g_qosMode=="private") << ','
                << c.rawPackets << ',' << c.rawPrioritySeen << ','
                << c.rawAdmitted << ',' << c.rawDropped << ',' << c.spoofDropped
                << ',' << c.remarked << ',' << c.rawBytes << ','
                << c.rawAdmittedBytes << ',' << c.priorityOffered << ','
                << c.priorityDemotions << '\n';
        }
    }
    if (Simulator::Now().GetSeconds()+0.5<=g_simDuration+1e-9)
        Simulator::Schedule(Seconds(0.5),&SampleStationBoundary);
}

static void SetSecurityState(SecurityState next, double ingressMbps) {
    if (next == g_securityState) return;
    const SecurityState previous = g_securityState;
    g_securityState = next;
    // Evidence belongs to one FSM stage only.  Preserve accumulated high
    // evidence while SUSPECTED, but never let it leak into a later cycle.
    if (next == SecurityState::CLEAN) {
        g_ddosHighCount = 0;
        g_ddosLowCount = 0;
    } else if (next == SecurityState::SUSPECTED) {
        g_ddosLowCount = 0;
    } else {
        g_ddosHighCount = 0;
        g_ddosLowCount = 0;
    }
    std::cout << "[ddos-detector] t=" << std::fixed << std::setprecision(3)
              << Simulator::Now().GetSeconds() << "s "
              << SecurityStateName(previous) << " -> "
              << SecurityStateName(next) << " ingress="
              << ingressMbps << " Mbps defense="
              << (next != SecurityState::CLEAN && g_ddosProtectUrgent
                  ? "ON" : "OFF") << '\n';
}

static void SampleDdosDetector() {
    const double windowSeconds = g_ddosWindowMs / 1000.0;
    const double ingressMbps = g_ddosIngressBytes * 8.0
                             / (windowSeconds * 1e6);
    const uint64_t ingressPackets = g_ddosIngressPackets;
    const double meanPacketBytes = ingressPackets > 0
        ? static_cast<double>(g_ddosIngressBytes) / ingressPackets : 0.0;
    const uint64_t parsedPackets = [&]() {
        uint64_t total = 0;
        for (const auto& entry : g_ddosSourcePackets) total += entry.second;
        return total;
    }();
    double sourceEntropy = 0.0;
    uint64_t dominantPackets = 0;
    for (const auto& entry : g_ddosSourcePackets) {
        dominantPackets = std::max(dominantPackets, entry.second);
        if (parsedPackets > 0) {
            const double p = static_cast<double>(entry.second) / parsedPackets;
            sourceEntropy -= p * std::log(std::max(p, 1e-12));
        }
    }
    const uint32_t uniqueSources = g_ddosSourcePackets.size();
    if (uniqueSources > 1) sourceEntropy /= std::log(uniqueSources);
    const double dominantSourceFrac = parsedPackets > 0
        ? static_cast<double>(dominantPackets) / parsedPackets : 0.0;
    const double udpFrac = ingressPackets > 0
        ? static_cast<double>(g_ddosUdpPackets) / ingressPackets : 0.0;
    const double rateDeltaMbps = ingressMbps - g_ddosPreviousMbps;
    const bool attackObserved = g_ddosObservedAttackPackets > 0;
    const uint64_t attackPackets = g_ddosObservedAttackPackets;
    const uint64_t attackEfPackets = g_ddosObservedAttackEfPackets;
    g_ddosPreviousMbps = ingressMbps;
    double detectorFeatures[8] = {
        ingressMbps, static_cast<double>(ingressPackets), meanPacketBytes,
        static_cast<double>(uniqueSources), sourceEntropy,
        dominantSourceFrac, udpFrac, rateDeltaMbps};
    double detectorOutput[2] = {1.0, 0.0};
    score_ddos_rf(detectorFeatures, detectorOutput);
    const double attackProbability = std::clamp(detectorOutput[1], 0.0, 1.0);
    g_ddosIngressBytes = 0;
    g_ddosIngressPackets = 0;
    g_ddosUdpPackets = 0;
    g_ddosObservedAttackPackets = 0;
    g_ddosObservedAttackEfPackets = 0;
    g_ddosSourcePackets.clear();

    const SecurityState before = g_securityState;
    if (g_ddosDetectorEnabled) {
        const bool highSignal = g_ddosDetectorMode == "rf"
            ? attackProbability >= g_ddosRfThreshold
            : ingressMbps >= g_ddosHighMbps;
        const bool lowSignal = g_ddosDetectorMode == "rf"
            ? attackProbability <= g_ddosRfClearThreshold
            : ingressMbps <= g_ddosLowMbps;
        if (highSignal) {
            ++g_ddosHighCount;
            g_ddosLowCount = 0;
        } else if (lowSignal) {
            ++g_ddosLowCount;
        } else {
            g_ddosLowCount = 0;
        }

        switch (g_securityState) {
        case SecurityState::CLEAN:
            if (g_ddosHighCount >= 1)
                SetSecurityState(SecurityState::SUSPECTED, ingressMbps);
            break;
        case SecurityState::SUSPECTED:
            if (g_ddosHighCount >= g_ddosAttackWindows)
                SetSecurityState(SecurityState::UNDER_ATTACK, ingressMbps);
            else if (g_ddosLowCount >= g_ddosClearWindows)
                SetSecurityState(SecurityState::CLEAN, ingressMbps);
            break;
        case SecurityState::UNDER_ATTACK:
            if (g_ddosLowCount >= g_ddosClearWindows)
                SetSecurityState(SecurityState::RECOVERY, ingressMbps);
            break;
        case SecurityState::RECOVERY:
            if (g_ddosHighCount >= 1)
                SetSecurityState(SecurityState::UNDER_ATTACK, ingressMbps);
            else if (g_ddosLowCount >= g_ddosClearWindows)
                SetSecurityState(SecurityState::CLEAN, ingressMbps);
            break;
        }
    }

    if (g_ddosStateCsv.is_open()) {
        g_ddosStateCsv << std::fixed << std::setprecision(6)
            << Simulator::Now().GetSeconds() << ',' << g_scenario << ','
            << SecurityStateName(g_securityState) << ',' << ingressMbps << ','
            << ingressPackets << ',' << meanPacketBytes << ','
            << uniqueSources << ',' << sourceEntropy << ','
            << dominantSourceFrac << ',' << udpFrac << ','
            << rateDeltaMbps << ',' << attackProbability << ','
            << g_ddosDetectorMode << ','
            << (g_ddosTruthActive ? 1 : 0) << ','
            << (attackObserved ? 1 : 0) << ','
            << (before != g_securityState ? 1 : 0) << ','
            << (g_securityState != SecurityState::CLEAN
                && g_ddosProtectUrgent ? 1 : 0) << ','
            << (g_ddosProtectUrgent ? g_ddosBeQueueLimit
                                    : PRIO_QUEUE_LIMIT) << ',' << attackPackets
            << ',' << g_ddosMeterPolicy << ',' << g_ddosMeterBypassPackets
            << ',' << attackEfPackets
            << '\n';
    }

    if (Simulator::Now().GetSeconds() + windowSeconds
        < g_simDuration + 1e-9) {
        Simulator::Schedule(MilliSeconds(
            static_cast<uint64_t>(g_ddosWindowMs)), &SampleDdosDetector);
    }
}

// =====================================================================
//                          SCENARIO CONTROL
// =====================================================================
static void ConfigureScenario(const std::string& sc) {
    g_scenario = sc;
    // A clean normal phase is an error-free reference, not forced metrics.
    // Restore the configured independent error processes in loaded phases.
    for (auto& model : g_linkErrorModels) {
        if (g_normalClean && sc == "normal") model->Disable();
        else model->Enable();
    }
    NS_LOG_INFO("=== Scenario → " << sc << " at t="
                << Simulator::Now().GetSeconds() << "s ===");

    for (auto& a : g_modbusSlaves)     a->SetScenario(sc);
    for (auto& a : g_modbusMasters)    a->SetScenario(sc);
    for (auto& a : g_dnp3Outstations)  a->SetScenario(sc);
    for (auto& a : g_dnp3Masters)      a->SetScenario(sc);
    for (auto& a : g_iecControlled)    a->SetScenario(sc);
    for (auto& a : g_iecControlling)   a->SetScenario(sc);
    for (auto& a : g_opcServers)       a->SetScenario(sc);
    for (auto& a : g_opcClients)       a->SetScenario(sc);
    for (auto& a : g_mqttPubs)         a->SetScenario(sc);
}

// =====================================================================
//                          CSV EXPORT
// =====================================================================
static void ExportCsv(const std::string& path) {
    std::ofstream ofs(path);
    if (!ofs.is_open()) {
        NS_LOG_ERROR("Cannot open CSV output: " << path);
        return;
    }
    ofs << "t_start,t_end,flow_id,src,dst,src_port,dst_port,"
        << "pkts_tx,pkts_rx,bytes_rx,pkts_lost,thr_mbps,mean_delay_ms,"
        << "jitter_ms,app_tx_pkts,dscp,dscp_class,protocol,scenario,"
        << "device_role,traffic_class,protocol_id,device_type_id,"
        << "message_family_id,is_event_capable,is_mixed_device\n";
    for (auto& r : g_csvRows) {
        ofs << std::fixed << std::setprecision(3)
            << r.t_start  << ',' << r.t_end << ','
            << r.flow_id  << ','
            << r.src      << ',' << r.dst << ','
            << r.src_port << ',' << r.dst_port << ','
            << r.pkts_tx  << ',' << r.pkts_rx << ','
            << r.bytes_rx << ',' << r.pkts_lost << ','
            << std::setprecision(6)
            << r.thr_mbps << ',' << r.mean_delay_ms << ','
            << r.jitter_ms << ','
            << r.app_tx_pkts << ','
            << (uint32_t)r.dscp << ',' << r.dscp_class << ','
            << r.protocol << ',' << r.scenario << ','
            << r.device_role << ',' << r.traffic_class << ','
            << r.protocol_id << ',' << r.device_type_id << ','
            << r.message_family_id << ',' << r.is_event_capable << ','
            << r.is_mixed_device << '\n';
    }
    NS_LOG_INFO("CSV exported: " << path << " (" << g_csvRows.size()
                << " rows)");
}

static void OpenPacketCsv(const std::string& path) {
    g_packetCsv.open(path);
    if (!g_packetCsv.is_open()) {
        NS_LOG_ERROR("Cannot open packet CSV output: " << path);
        return;
    }
    g_packetCsv << "run_id,t,node_id,device_id,protocol_id,protocol,direction,"
                << "pkt_size,incident_active,is_warmup,is_transition,train_usable,"
                << "service_class,message_kind,scenario,scenario_start,device_role\n";
    NS_LOG_INFO("Packet CSV streaming to: " << path);
}

static void OpenRuntimeMlCsv(const std::string& path) {
    if (g_mode != "dt" && g_mode != "rf") return;
    g_runtimeMlCsv.open(path);
    if (!g_runtimeMlCsv.is_open()) {
        NS_LOG_ERROR("Cannot open runtime ML CSV output: " << path);
        return;
    }
    g_runtimeMlCsv
        << "t,message_id,device_id,protocol_id,protocol,message_kind,baseline_ready,"
        << "prob_time_critical,prob_operational,prob_monitoring,confidence,"
        << "pred_service_class,priority_evidence,qos_safety_promoted,"
        << "qos_service_class,true_service_class,evaluated,correct,"
        << "pkt_count_1s,current_pkt_size,avg_pkt_size,max_pkt_size,"
        << "pkt_size_std,pkt_size_entropy,inter_arrival_mean,"
        << "inter_arrival_min,inter_arrival_std,current_size_baseline_ratio,"
        << "time_since_last_pkt,silent_gap_ratio,pkt_rate_delta,"
        << "current_size_zscore,burst_count_100ms,burst_count_500ms,"
        << "short_long_rate_ratio,baseline_pkt_rate_zscore,"
        << "baseline_size_zscore,uplink_downlink_ratio,protocol_id_feature,"
        << "request_last_bytes_1s,request_mean_bytes_1s,request_max_bytes_1s,"
        << "request_size_std_1s,request_max_bytes_2s,request_peak_age_2s,"
        << "request_excess_count_2s,request_excess_age_2s\n";
}

static void ClosePacketCsv() {
    if (g_packetCsv.is_open()) {
        g_packetCsv.flush();
        g_packetCsv.close();
    }
    NS_LOG_INFO("Packet CSV exported (" << g_packetRowCount << " rows)");
}

static void CloseRuntimeMlCsv() {
    if (g_runtimeMlCsv.is_open()) {
        g_runtimeMlCsv.flush();
        g_runtimeMlCsv.close();
    }
    if (g_runtimeRows > 0) {
        NS_LOG_INFO("Runtime ML service-class accuracy="
                    << static_cast<double>(g_runtimeCorrect) / g_runtimeRows
                    << " (" << g_runtimeCorrect << '/' << g_runtimeRows << ")");
    }
}

static void OpenRlCsvs() {
    g_rlTransitionCsv.open(g_outDir + "rl_transitions.csv");
    if (g_rlTransitionCsv.is_open()) {
        g_rlTransitionCsv
            << "t,gateway,window_id,traffic_class_id,state,action,next_state,"
            << "reward,total,delivered,lost,deadline_misses,avg_norm_delay,"
            << "max_norm_delay,queue_at_start,action_health,min_health,"
            << "degraded_fallback,path_switched,route_evidence_hold,"
            << "true_e_total,true_e_misses,true_i_total,true_i_misses,"
            << "q_old,q_new,visit_count\n";
    }
    if (g_qosCtrlOn) {
        g_qosCtrlCsv.open(g_outDir + "qos_control.csv");
        if (g_qosCtrlCsv.is_open())
            g_qosCtrlCsv << "t,class,lambda_kbps,mu,rate_kbps,feedback_mass,"
                         << "total_rate_kbps,budget_error_kbps\n";
    }
    if (g_qosQueueMs > 0.0) {
        g_qosQueueCsv.open(g_outDir + "qos_queues.csv");
        if (g_qosQueueCsv.is_open())
            g_qosQueueCsv << "t,link,band,pkts,bytes,dropped,enqueued\n";
    }
    g_rlDeliveryCsv.open(g_outDir + "rl_deliveries.csv");
    if (g_rlDeliveryCsv.is_open()) {
        g_rlDeliveryCsv
            << "t,message_id,source_gateway,path,traffic_class,device_id,"
            << "protocol_id,payload_bytes,delay_ms,deadline_ms,deadline_met,"
            << "true_class,true_deadline_ms,true_deadline_met,"
            << "message_true_class,message_deadline_ms,message_deadline_met,"
            << "served_class,meter_demoted,meter_borrowed\n";
    }
    if (g_rlRouteIntegrity) {
        g_routeIntegrityCsv.open(g_outDir + "route_integrity.csv");
        if (g_routeIntegrityCsv.is_open()) {
            g_routeIntegrityCsv
                << "t,station,path,target,expected_gateway,observed_gateway,"
                << "expected_if,observed_if,fingerprint_changed,anomalous\n";
        }
    }
}

static void CloseRlCsvs() {
    if (g_rlTransitionCsv.is_open()) g_rlTransitionCsv.close();
    if (g_rlDeliveryCsv.is_open()) g_rlDeliveryCsv.close();
    if (g_qosQueueCsv.is_open()) g_qosQueueCsv.close();
    if (g_qosCtrlCsv.is_open()) g_qosCtrlCsv.close();
    if (g_routeIntegrityCsv.is_open()) g_routeIntegrityCsv.close();
    if (g_qosCtrlLossFeedback) {
        std::ofstream summary(g_outDir + "qos_feedback_summary.csv");
        if (summary.is_open()) {
            summary << "class,edge_offered,edge_demoted,edge_borrowed,"
                    << "on_time_feedback,timeout_feedback,"
                    << "late_after_timeout,unresolved_expired\n";
            for (uint32_t cls = 1; cls < 3; ++cls) {
                uint64_t unresolved = 0;
                for (const auto& item : g_qosDeadlines) {
                    if (item.second.assignedClass == cls
                        && item.second.expired) ++unresolved;
                }
                summary << RlClassName(static_cast<uint8_t>(cls)) << ','
                        << g_qosEdgeOffered[cls] << ','
                        << g_qosEdgeDemoted[cls] << ','
                        << g_qosEdgeBorrowed[cls] << ','
                        << g_qosOnTimeFeedback[cls] << ','
                        << g_qosTimeoutFeedback[cls] << ','
                        << g_qosLateAfterTimeout[cls] << ','
                        << unresolved << '\n';
            }
        }
    }
}

static bool SaveRlQTable(const std::string& path) {
    std::ofstream output(path);
    if (!output.is_open()) {
        NS_LOG_ERROR("Cannot write RL Q-table: " << path);
        return false;
    }
    output << "gateway,state,action,q,visits,state_schema\n";
    for (const auto& agent : g_gatewayAgents) agent.WriteQTable(output);
    NS_LOG_INFO("RL Q-table saved: " << path);
    return true;
}

// =====================================================================
//                          MAIN
// =====================================================================
// Emits standards-shaped RIP v2 Response packets over UDP/520. The malicious
// route is a host route, so it wins longest-prefix matching over RIP's normal
// connected /30 advertisement. Metric 16 withdraws it when the attack ends.
class RipPoisonApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::RipPoisonApp")
            .SetParent<Application>().SetGroupName("Applications")
            .AddConstructor<RipPoisonApp>();
        return tid;
    }

    void Setup(Ipv4Address local, Ipv4Address victim,
               Ipv4Address advertisedHost, Ptr<NetDevice> device,
               uint32_t metric, Time period) {
        m_local = local;
        m_victim = victim;
        m_advertisedHost = advertisedHost;
        m_device = device;
        m_metric = std::clamp(metric, 1u, 15u);
        m_period = std::max(period, MilliSeconds(100));
    }

private:
    void StartApplication() override {
        m_running = true;
        g_ripPoisonTruth = true;
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->BindToNetDevice(m_device);
        if (m_socket->Bind(InetSocketAddress(m_local, 521)) < 0) {
            NS_FATAL_ERROR("Cannot bind RIP poison source on " << m_local);
        }
        m_socket->SetIpTtl(1);
        std::cout << "[rip-poison] t=" << Simulator::Now().GetSeconds()
                  << "s START victim=" << m_victim
                  << " host=" << m_advertisedHost
                  << " metric=" << m_metric << '\n';
        if (g_anim) {
            g_anim->UpdateNodeDescription(GetNode(),
                                           "RIP-Attacker [POISONING]");
            g_anim->UpdateNodeColor(GetNode(), 220, 0, 180);
        }
        SendUpdate(m_metric, "poison");
    }

    void StopApplication() override {
        if (!m_running) return;
        m_running = false;
        Simulator::Cancel(m_sendEvent);
        SendUpdate(16, "withdraw");
        g_ripPoisonTruth = false;
        std::cout << "[rip-poison] t=" << Simulator::Now().GetSeconds()
                  << "s STOP withdrawal_metric=16\n";
        if (g_anim) {
            g_anim->UpdateNodeDescription(GetNode(), "RIP-Attacker [IDLE]");
            g_anim->UpdateNodeColor(GetNode(), 125, 0, 150);
        }
        if (m_socket) {
            m_socket->Close();
            m_socket = nullptr;
        }
    }

    void SendUpdate(uint32_t metric, const char* event) {
        if (!m_socket) return;
        RipRte rte;
        rte.SetPrefix(m_advertisedHost);
        rte.SetSubnetMask(Ipv4Mask("255.255.255.255"));
        rte.SetNextHop(Ipv4Address::GetAny());
        rte.SetRouteTag(0);
        rte.SetRouteMetric(metric);

        RipHeader header;
        header.SetCommand(RipHeader::RESPONSE);
        header.AddRte(rte);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(header);
        const int sent = m_socket->SendTo(
            packet, 0, InetSocketAddress(m_victim, 520));
        if (sent >= 0) ++g_ripPoisonUpdates;
        if (g_ripPoisonCsv.is_open()) {
            g_ripPoisonCsv << std::fixed << std::setprecision(6)
                << Simulator::Now().GetSeconds() << ',' << event << ','
                << m_local << ',' << m_victim << ',' << m_advertisedHost
                << ',' << metric << ',' << (sent >= 0 ? 1 : 0) << '\n';
        }
        if (m_running) {
            m_sendEvent = Simulator::Schedule(
                m_period, &RipPoisonApp::SendUpdate, this, m_metric, "poison");
        }
    }

    Ptr<Socket> m_socket;
    Ptr<NetDevice> m_device;
    EventId m_sendEvent;
    Ipv4Address m_local;
    Ipv4Address m_victim;
    Ipv4Address m_advertisedHost;
    uint32_t m_metric = 1;
    Time m_period = Seconds(1);
    bool m_running = false;
};

NS_OBJECT_ENSURE_REGISTERED(RipPoisonApp);

static void
AuditRipRoute(Ptr<Node> station, uint32_t stationIndex,
              Ipv4Address target, const std::string& phase)
{
    Ptr<Ipv4> ipv4 = station->GetObject<Ipv4>();
    Ptr<Ipv4RoutingProtocol> routing = ipv4->GetRoutingProtocol();
    Ipv4Header header;
    header.SetDestination(target);
    Socket::SocketErrno error = Socket::ERROR_NOTERROR;
    Ptr<Ipv4Route> route = routing->RouteOutput(
        Create<Packet>(), header, nullptr, error);

    std::string gateway = "NONE";
    std::string source = "NONE";
    int32_t outputIf = -1;
    if (route) {
        gateway = IpToStr(route->GetGateway());
        source = IpToStr(route->GetSource());
        outputIf = ipv4->GetInterfaceForDevice(route->GetOutputDevice());
    }
    if (g_ripRouteCsv.is_open()) {
        g_ripRouteCsv << std::fixed << std::setprecision(6)
            << Simulator::Now().GetSeconds() << ',' << phase << ','
            << stationIndex << ',' << target << ',' << gateway << ','
            << source << ',' << outputIf << ',' << static_cast<int>(error)
            << '\n';
    }
    std::cout << "[rip-route] t=" << Simulator::Now().GetSeconds()
              << "s phase=" << phase << " S" << stationIndex
              << " target=" << target << " gateway=" << gateway
              << " if=" << outputIf << '\n';
}

static void
SampleRouteIntegrity(Ptr<Node> station, uint32_t stationIndex,
                     uint32_t path, Ipv4Address target)
{
    Ptr<Ipv4> ipv4 = station->GetObject<Ipv4>();
    Ptr<Ipv4RoutingProtocol> routing = ipv4->GetRoutingProtocol();
    Ipv4Header header;
    header.SetDestination(target);
    Socket::SocketErrno error = Socket::ERROR_NOTERROR;
    Ptr<Ipv4Route> route = routing->RouteOutput(
        Create<Packet>(), header, nullptr, error);

    const uint32_t gateway = route ? route->GetGateway().Get() : 0xffffffffu;
    const int32_t outputIf = route
        ? ipv4->GetInterfaceForDevice(route->GetOutputDevice()) : -1;
    RouteFingerprintState& state =
        g_routeFingerprints[stationIndex][path];

    if (!state.initialized && route) {
        state.initialized = true;
        state.expectedGateway = gateway;
        state.expectedIf = outputIf;
    }

    const bool changed = state.initialized
        && (!route || gateway != state.expectedGateway
                   || outputIf != state.expectedIf);
    if (changed) {
        ++state.anomalyCount;
        state.clearCount = 0;
    } else {
        state.anomalyCount = 0;
        if (state.initialized) ++state.clearCount;
    }

    const bool previous = state.anomalous;
    if (!state.anomalous && state.anomalyCount >= 2) state.anomalous = true;
    if (state.anomalous && state.clearCount >= 3) state.anomalous = false;
    g_gatewayAgents[stationIndex].SetPathRouteAnomaly(path, state.anomalous);

    if (g_routeIntegrityCsv.is_open()) {
        g_routeIntegrityCsv << std::fixed << std::setprecision(6)
            << Simulator::Now().GetSeconds() << ',' << stationIndex << ','
            << path << ',' << target << ','
            << (state.initialized
                ? IpToStr(Ipv4Address(state.expectedGateway)) : "NONE") << ','
            << (route ? IpToStr(Ipv4Address(gateway)) : "NONE") << ','
            << state.expectedIf << ',' << outputIf << ','
            << (changed ? 1 : 0) << ',' << (state.anomalous ? 1 : 0)
            << '\n';
    }
    if (previous != state.anomalous) {
        std::cout << "[route-integrity] t="
                  << Simulator::Now().GetSeconds() << "s S" << stationIndex
                  << " path=" << path << " anomaly=" << state.anomalous
                  << " expected-gw="
                  << IpToStr(Ipv4Address(state.expectedGateway))
                  << " observed-gw="
                  << (route ? IpToStr(Ipv4Address(gateway)) : "NONE")
                  << '\n';
    }

    const double period = g_rlRouteIntegrityMs / 1000.0;
    if (Simulator::Now().GetSeconds() + period < g_simDuration) {
        Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(
            g_rlRouteIntegrityMs)), &SampleRouteIntegrity,
            station, stationIndex, path, target);
    }
}

int main(int argc, char* argv[]) {
    LogComponentEnable("ScadaSim", LOG_LEVEL_INFO);

    //////////////////////////////////////////////// CLI //////////////////////////////////////////////──────
    bool     enableAnim  = false;
    bool     animDashboard = false;
    double   sceneDurCli = SCENARIO_DURATION;
    uint32_t maxPkts     = 0;       // 0 = unlimited
    double   errAccess   = 1e-3;
    double   errCore     = 1e-4;
    double   errMesh     = MESH_ERR_RATE;
    uint32_t runId       = 1;       // RngSeedManager run number
    bool     stressMode  = false;   // force congestion to make
                                     // DSCP differentiation observable
    bool     enablePacketCsv = true;
    bool     enableFeatureCsv = true;
    bool     enableFlowXml = true;
    bool     enablePcap = false;
    bool     rlCongestion = false;
    double   rlBgLoad = 1.15;
    uint32_t rlBgTos = 184;
    // ---- QoS testbed knobs (experiment harness, not a QoS algorithm) ----
    double      rlBgBurst   = 1.0;    // peak/mean rate ratio; 1.0 = CBR
    double      rlBgBurstMs = 5.0;    // mean ON time of a burst (ms)
    // Negative values inherit the common load/burst settings. Scenario
    // overrides keep normal uncongested while high-load is sustained and the
    // emergency phase is transiently bursty.
    double      rlBgLoadNormal = -1.0;
    double      rlBgLoadHigh = -1.0;
    double      rlBgLoadEmergency = -1.0;
    double      rlBgBurstNormal = -1.0;
    double      rlBgBurstHigh = -1.0;
    double      rlBgBurstEmergency = -1.0;
    std::string bgWhere     = "path"; // path | allpaths | master
    bool        bgFull      = false;  // background spans the whole scenario
    std::string coreBwCli   = "";     // e.g. "10Mbps"; empty = keep default
    std::string brokerBwCli = "";     // broker->master capacity
    uint32_t    queueLenCli = 0;      // packets per DSCP band; 0 = keep
    uint32_t    devQueueCli = 0;      // NetDevice TxQueue on core/broker; 0 = keep
    double      qosQueueMs  = 0.0;    // >0 = log per-band occupancy every N ms
    // Traffic profile for the two priority bands at the Broker->Master
    // bottleneck, in kbps.  <=0 disables the meter for that class, which is
    // the default and reproduces the unpoliced behaviour exactly.
    // The profile is deliberately absolute rather than a fraction of link
    // capacity: the two priority bands carry 1.3-4.3 kbps on a 5 Mbps link,
    // so any profile expressed as a percentage of the link is orders of
    // magnitude above the traffic and can never bind.
    double      meterEfKbps   = -1.0;  // EMERGENCY profile
    double      meterAf31Kbps = -1.0;  // IMPORTANT profile
    // Bucket size in bytes.  Must exceed one packet (~190 B here), otherwise
    // the bucket can never hold enough tokens for a single packet and every
    // message is demoted regardless of rate.
    double      meterBurstBytes = 2000.0;
    // Dynamic QoS on the policer/marker plane: one closed loop over per-class
    // profiles.  Off by default.
    bool        qosCtrl        = false;
    bool        qosLossFeedback = false;
    bool        qosShiftWorkload = false;
    double      qosShiftFactor = 3.0;
    // Scenario-specific totals compensate for protocol payload sizes and the
    // RF classifier's scenario-dependent false-positive background. They were
    // calibrated to keep assigned urgent load near 4.5 kbps at sceneDur=40.
    uint32_t    qosShiftReportsNormal = 160;
    uint32_t    qosShiftReportsHigh = 105;
    uint32_t    qosShiftReportsEmergency = 60;
    double      qosCtrlBudget  = 4.0;    // total urgent budget C, kbps
    double      qosCtrlMs      = 100.0;  // control period
    double      qosCtrlMemMs   = 2000.0; // EWMA memory of the estimators
    double      qosCtrlBeta    = 2.0;    // feedback gain on deadline miss
    double      qosCtrlMinFrac = 0.25;   // r_min as a fraction of C/2
    double      qosCtrlMaxStep = 0.30;   // slew-rate limit per period
    bool        qosCtrlDemote   = false; // feedback on demotions, not misses
    bool        qosCtrlPressureOnly = false;
    double      qosCtrlPressurePower = 1.0;
    bool        qosCtrlPressureHold = false;
    double      qosCtrlInitialEfFrac = 0.5;

    // Named profiles keep repeatable demo/test settings in one place while
    // preserving the legacy defaults used by audit scripts. Apply the profile
    // before CommandLine::Parse so every explicit CLI option still wins.
    std::string profile = "default";
    constexpr const char* profilePrefix = "--profile=";
    for (int i = 1; i < argc; ++i) {
        const std::string argument(argv[i]);
        if (argument.rfind(profilePrefix, 0) == 0) {
            profile = argument.substr(std::char_traits<char>::length(profilePrefix));
        }
    }

    if (profile == "qos") {
        // The deployed pooled DT/RF now match the read-only Modbus MON/OP
        // register-scan workflow. No separate socket or write-code shortcut.
        g_modbusServiceEvents = true;
        g_modbusServiceWorkflow = true;
        g_modbusMixedWorkflow = false;
        g_qosIngressGuard = true;
        g_qosSourceLimit = true;
        animDashboard = true;
        g_mode = "rf";
        g_rlMode = "qtable";
        g_rlQTablePath = "rl/outputs/qtable_rf_qos.csv";
        g_rlSafeMask = true;
        // Random 5% packet loss is a separate robustness experiment, not a
        // prerequisite for demonstrating QoS/RL in the primary profile.
        g_rlDemoRouting = false;
        g_rlDemoPeriod = 5.0;
        g_rlDemoLoss = 0.05;
        g_rlRouteEvidenceGate = true;
        g_rlRouteIntegrity = true;
        g_rlDataPlaneFailover = false;
        g_ripRouting = true;
        g_qosMode = "private";
        g_qosActuator = "station";
        qosCtrl = true;
        // The service-flow classifier observes compact TC bursts and batched
        // operational reports. A 100-kbps aggregate marker contract is only
        // 5% of the 2-Mbps bottleneck, but covers the measured priority load.
        qosCtrlBudget = 100.0;
        qosCtrlMs = 100.0;
        qosCtrlMemMs = 2000.0;
        qosCtrlBeta = 2.0;
        // Permit an asymmetric split because AF31 carries batched reports;
        // retain at least 5% of the total contract for either priority band.
        qosCtrlMinFrac = 0.4;
        qosCtrlMaxStep = 0.05;
        qosCtrlDemote = true;
        qosCtrlPressureOnly = true;
        qosCtrlPressurePower = 2.0;
        qosCtrlPressureHold = true;
        qosCtrlInitialEfFrac = 0.20;
        g_qosEmergencyBorrow = true;
        // Preserve the RF class in diagnostics, but keep near-threshold
        // priority flows out of the congested BE band. This protects false
        // negatives without granting EF service to uncertain observations.
        g_qosSafetyPromote = true;
        g_qosSafetyRatio = 0.45;
        g_ddosProtectUrgent = true;
        meterEfKbps = 15.0;
        meterAf31Kbps = 85.0;
        // Absorb short operational bursts without relaxing the sustained
        // token rate enforced by the controller.
        meterBurstBytes = 16000.0;
        qosShiftWorkload = true;
        qosShiftFactor = 3.0;
        // Operational load calibration at the shared Broker->Master edge:
        // normal is uncongested, high-load has sustained bursty BE traffic,
        // and emergency has a lower mean but a sharper transient peak.
        rlCongestion = true;
        bgWhere = "master";
        bgFull = true;
        rlBgTos = 0;  // BE, never falsely mark background as EF
        rlBgLoadNormal = 0.0;
        rlBgLoadHigh = 0.70;
        rlBgLoadEmergency = 0.50;
        rlBgBurstNormal = 1.0;
        rlBgBurstHigh = 2.0;
        rlBgBurstEmergency = 4.0;
        rlBgBurstMs = 20.0;
        coreBwCli = "2Mbps";
        brokerBwCli = "2Mbps";
        queueLenCli = 25;
        devQueueCli = 1;
        qosQueueMs = 100.0;
        g_enableRuntimeMlCsv = true;
        enablePacketCsv = false;
        enableFeatureCsv = false;
        enableFlowXml = false;
        enablePcap = false;
    } else if (profile != "default") {
        std::cerr << "[ERROR] Unknown profile '" << profile
                  << "'. Use default or qos.\n";
        return 2;
    }

    CommandLine cmd;
    cmd.AddValue("profile",
        "Configuration profile: default | qos. Explicit CLI "
        "options override profile values",
        profile);
    cmd.AddValue("anim",      "Enable NetAnim XML export",     enableAnim);
    cmd.AddValue("animDashboard",
        "Show a live scenario and aggregate KPI panel in NetAnim",
        animDashboard);
    cmd.AddValue("sceneDur",  "Per-scenario duration (s)",     sceneDurCli);
    cmd.AddValue("maxPkts",   "FlowMonitor packet sample cap", maxPkts);
    cmd.AddValue("errAccess", "Packet error rate on access links", errAccess);
    cmd.AddValue("normalClean", "Disable link error models during bootstrap/normal only", g_normalClean);
    cmd.AddValue("errCore",   "Packet error rate on core links", errCore);
    cmd.AddValue("errMesh",   "Packet error rate on Station-mesh links", errMesh);
    cmd.AddValue("run",       "RngSeedManager run number",     runId);
    cmd.AddValue("mode",
        "Classification mode: dt | rf  "
        "(omit for baseline = expert-rule reference)",         g_mode);
    cmd.AddValue("rlMode",
        "Station RL forwarding mode: off | heuristic | train | qtable", g_rlMode);
    cmd.AddValue("rlQTable", "RL Q-table CSV to load/save", g_rlQTablePath);
    cmd.AddValue("rlAlpha", "Q-learning alpha", g_rlAlpha);
    cmd.AddValue("rlGamma", "Q-learning gamma", g_rlGamma);
    cmd.AddValue("rlEpsilon", "Training epsilon", g_rlEpsilon);
    cmd.AddValue("rlDecisionMs", "Path decision window (ms)", g_rlDecisionMs);
    cmd.AddValue("rlTimeoutMs", "Delivery timeout (ms)", g_rlTimeoutMs);
    cmd.AddValue("rlSafeMask",
        "Mask paths worse than the healthiest currently available path",
        g_rlSafeMask);
    cmd.AddValue("rlLossRecoveryMs",
        "Exponential recovery time for timeout-derived path loss (0 = legacy)",
        g_rlLossRecoveryMs);
    cmd.AddValue("rlRouteEvidenceGate",
        "Require a path-specific delay/loss advantage before Q-table routing "
        "may switch paths", g_rlRouteEvidenceGate);
    cmd.AddValue("rlRouteDelayGapMs",
        "Minimum current-minus-candidate delay gap that permits an RL switch",
        g_rlRouteDelayGapMs);
    cmd.AddValue("rlRouteLossGap",
        "Minimum current-minus-candidate loss gap that permits an RL switch",
        g_rlRouteLossGap);
    cmd.AddValue("rlRouteIntegrity",
        "Monitor FIB next-hop fingerprints and mask anomalous RL paths",
        g_rlRouteIntegrity);
    cmd.AddValue("rlRouteIntegrityMs",
        "FIB integrity sampling period in milliseconds",
        g_rlRouteIntegrityMs);
    cmd.AddValue("rlDataPlaneFailover",
        "Allow delay/loss evidence (in addition to FIB anomalies) to trigger RL",
        g_rlDataPlaneFailover);
    cmd.AddValue("modbusServiceEvents",
        "Generate finite Modbus operational polling episodes (MON/OP only)",
        g_modbusServiceEvents);
    cmd.AddValue("serviceRateJitter", "Relative event-rate variability (0..0.75)",
        g_serviceRateJitter);
    cmd.AddValue("modbusOperationalRefreshMs", "Modbus-only OP polling target interval in ms (0 keeps committed behavior)",
        g_modbusOperationalRefreshMs);
    cmd.AddValue("modbusMonitoringBursts",
        "Add MON-only fast polling episodes as observable hard negatives",
        g_modbusMonitoringBursts);
    cmd.AddValue("modbusMixedWorkflow",
        "Experimental FC03/FC23 read-write-verification workflow",
        g_modbusMixedWorkflow);
    cmd.AddValue("modbusServiceWorkflow",
        "Experimental read-only monitoring/status-confirmation service workflow",
        g_modbusServiceWorkflow);
    cmd.AddValue("modbusRoutineWriteProb",
        "MON scheduled maintenance read/write probability (0..0.25)",
        g_modbusRoutineWriteProb);
    cmd.AddValue("ddosMeterPolicy",
        "Attack-state token policy: bounded | standard | legacy_bypass",
        g_ddosMeterPolicy);
    cmd.AddValue("qosBeFairQueue", "Experimental per-flow FqCoDel inside BE band",
        g_qosBeFairQueue);
    cmd.AddValue("qosIngressGuard", "Remove untrusted field transit DSCP and validate source binding (private QoS)", g_qosIngressGuard);
    cmd.AddValue("qosSourceLimit", "Bound raw field transit and each authorized priority source (private QoS)", g_qosSourceLimit);
    cmd.AddValue("qosRawSourceKbps", "Raw transit allowance per physical field ingress", g_qosRawSourceKbps);
    cmd.AddValue("qosRawStationKbps", "Aggregate raw transit allowance per Station", g_qosRawStationKbps);
    cmd.AddValue("qosRawBurstBytes", "Raw per-source bucket bytes", g_qosRawBurstBytes);
    cmd.AddValue("qosRawStationBurstBytes", "Aggregate raw bucket bytes per Station", g_qosRawStationBurstBytes);
    cmd.AddValue("qosPrioritySourceKbps", "Shared TC/OP allowance per authorized device/protocol", g_qosPrioritySourceKbps);
    cmd.AddValue("qosPrioritySourceBurstBytes", "Authorized TC/OP source bucket bytes", g_qosPrioritySourceBurstBytes);
    cmd.AddValue("qosSafetyPromote",
        "Promote a near-threshold RF/DT MONITORING decision to OPERATIONAL "
        "service when private QoS is active",
        g_qosSafetyPromote);
    cmd.AddValue("qosSafetyRatio",
        "Minimum normalized priority evidence for the QoS uncertainty guard",
        g_qosSafetyRatio);
    cmd.AddValue("rlDemoRouting",
        "Rotate a lossy northbound path for NetAnim routing demos",
        g_rlDemoRouting);
    cmd.AddValue("rlDemoPeriod",
        "Seconds before rotating the demo bottleneck to the next path",
        g_rlDemoPeriod);
    cmd.AddValue("rlDemoLoss",
        "Packet error rate while a northbound path is degraded in routing demos",
        g_rlDemoLoss);
    cmd.AddValue("runtimeMlCsv",
        "Export per-message runtime ML diagnostics",
        g_enableRuntimeMlCsv);
    cmd.AddValue("qosMode",
        "Transport QoS mode: private = provider/private link honours DSCP "
        "(training/reference); neutral = provider treats all classes equally",
        g_qosMode);   // + fifo: single band, same total buffer
    cmd.AddValue("outDir",    "Output directory",              g_outDir);
    cmd.AddValue("stress",
        "Stress mode: tighten BW + queue + errors to force "
        "congestion so DSCP priority becomes observable",      stressMode);
    cmd.AddValue("packetCsv", "Export raw packet CSV", enablePacketCsv);
    cmd.AddValue("featureCsv", "Export FlowMonitor feature CSV", enableFeatureCsv);
    cmd.AddValue("flowXml", "Export FlowMonitor XML", enableFlowXml);
    cmd.AddValue("pcap", "Capture mesh and northbound links", enablePcap);
    cmd.AddValue("ddos",
        "Generate a distributed UDP flood; this flag does not set detector state",
        g_ddosEnabled);
    cmd.AddValue("ddosDetector",
        "Enable Master-ingress window detector and security state machine",
        g_ddosDetectorEnabled);
    cmd.AddValue("ddosDetectorMode",
        "DDoS detector: rf (source-distribution model) or threshold (Mbps)",
        g_ddosDetectorMode);
    cmd.AddValue("ddosRfThreshold", "RF probability threshold for attack",
        g_ddosRfThreshold);
    cmd.AddValue("ddosRfClearThreshold",
        "RF probability threshold used to clear an attack",
        g_ddosRfClearThreshold);
    cmd.AddValue("ddosStart",
        "Attack start in simulation seconds (<0 = 1 + 1.25*sceneDur, "
        "i.e. 25% into high_load)",
        g_ddosStart);
    cmd.AddValue("ddosDuration",
        "Attack duration in seconds (<0 = 0.5*sceneDur)",
        g_ddosDuration);
    cmd.AddValue("ddosRateMbps", "Aggregate attack rate in Mbps",
        g_ddosRateMbps);
    cmd.AddValue("ddosSources", "Number of distributed field-node attackers",
        g_ddosSources);
    cmd.AddValue("ddosPattern", "Attack emission pattern: cbr | burst | random_burst",
        g_ddosPattern);
    cmd.AddValue("ddosBurstFactor",
        "Burst peak/mean ratio; mean aggregate rate remains ddosRateMbps",
        g_ddosBurstFactor);
    cmd.AddValue("ddosBurstMs", "ON duration of a burst in milliseconds",
        g_ddosBurstMs);
    cmd.AddValue("ddosPlacement",
        "Attacker placement: distributed, station0, station1, or station2",
        g_ddosPlacement);
    cmd.AddValue("ddosWindowMs", "Master-ingress detector window in ms",
        g_ddosWindowMs);
    cmd.AddValue("ddosHighMbps", "Ingress threshold to suspect an attack",
        g_ddosHighMbps);
    cmd.AddValue("ddosLowMbps", "Ingress threshold used to clear an attack",
        g_ddosLowMbps);
    cmd.AddValue("ddosAttackWindows",
        "High-evidence windows required for UNDER_ATTACK; short RF-neutral "
        "gaps are tolerated while SUSPECTED",
        g_ddosAttackWindows);
    cmd.AddValue("ddosClearWindows",
        "Consecutive low windows required to enter RECOVERY",
        g_ddosClearWindows);
    cmd.AddValue("ddosProtectUrgent",
        "Use a bounded BE queue and preserve E/I marking in detector states",
        g_ddosProtectUrgent);
    cmd.AddValue("ddosBeQueue",
        "Fixed BE queue limit per defense-capable priority bottleneck",
        g_ddosBeQueueLimit);
    cmd.AddValue("ripRouting",
        "Use RIP v2 as the Station/Broker routing baseline",
        g_ripRouting);
    cmd.AddValue("ripPoison",
        "Attach a malicious router and inject RIP v2 host-route responses",
        g_ripPoison);
    cmd.AddValue("ripPoisonStation",
        "Station receiving the forged RIP response (0..2)",
        g_ripPoisonStation);
    cmd.AddValue("ripPoisonPath",
        "Broker path host address falsely advertised by the attacker (0..2)",
        g_ripPoisonPath);
    cmd.AddValue("ripPoisonStart",
        "RIP poisoning start time in seconds (<0 = 25% into high_load)",
        g_ripPoisonStart);
    cmd.AddValue("ripPoisonDuration",
        "RIP poisoning duration in seconds (<0 = half one scenario)",
        g_ripPoisonDuration);
    cmd.AddValue("ripPoisonPeriod",
        "Seconds between forged RIP responses",
        g_ripPoisonPeriod);
    cmd.AddValue("ripPoisonMetric",
        "Metric advertised in forged RIP host routes (1..15)",
        g_ripPoisonMetric);
    cmd.AddValue("ripDetourBw",
        "Capacity of each attacker detour link",
        g_ripDetourBw);
    cmd.AddValue("ripDetourDelay",
        "One-way delay of each attacker detour link",
        g_ripDetourDelay);
    cmd.AddValue("rlCongestion",
        "Enable rotating path-specific background congestion", rlCongestion);
    cmd.AddValue("rlBgLoad",
        "RL background load as a fraction of core link capacity", rlBgLoad);
    cmd.AddValue("rlBgTos",
        "IPv4 TOS/DSCP byte for RL background traffic", rlBgTos);
    cmd.AddValue("rlBgBurst",
        "Background peak/mean rate ratio (1.0 = deterministic CBR). A CBR "
        "source is a D/D/1 arrival process and queues nothing below rho=1, "
        "so a value >1 is required for graded congestion", rlBgBurst);
    cmd.AddValue("rlBgBurstMs",
        "Mean ON time of one background burst in ms", rlBgBurstMs);
    cmd.AddValue("rlBgLoadNormal",
        "Normal-phase load fraction; negative inherits rlBgLoad",
        rlBgLoadNormal);
    cmd.AddValue("rlBgLoadHigh",
        "High-load phase load fraction; negative inherits rlBgLoad",
        rlBgLoadHigh);
    cmd.AddValue("rlBgLoadEmergency",
        "Emergency-phase load fraction; negative inherits rlBgLoad",
        rlBgLoadEmergency);
    cmd.AddValue("rlBgBurstNormal",
        "Normal-phase peak/mean ratio; negative inherits rlBgBurst",
        rlBgBurstNormal);
    cmd.AddValue("rlBgBurstHigh",
        "High-load peak/mean ratio; negative inherits rlBgBurst",
        rlBgBurstHigh);
    cmd.AddValue("rlBgBurstEmergency",
        "Emergency peak/mean ratio; negative inherits rlBgBurst",
        rlBgBurstEmergency);
    cmd.AddValue("bgWhere",
        "Where background load is applied: path (one rotating provider link "
        "per scenario) | allpaths (all three at once) | master (broker->master "
        "link, the only bottleneck routing cannot avoid)", bgWhere);
    cmd.AddValue("bgFull",
        "Background covers 10-90% of each scenario instead of 20-70%", bgFull);
    cmd.AddValue("coreBw", "Override gateway<->broker capacity, e.g. 10Mbps",
        coreBwCli);
    cmd.AddValue("brokerBw", "Override broker<->master capacity", brokerBwCli);
    cmd.AddValue("queueLen", "Packets per DSCP band in the PrioQueueDisc",
        queueLenCli);
    cmd.AddValue("devQueue",
        "NetDevice TxQueue (packets) on core and broker links. This FIFO sits "
        "below the priority disc, so it must stay small", devQueueCli);
    cmd.AddValue("meterEfKbps",
        "EMERGENCY traffic profile at the broker->master bottleneck, in kbps "
        "(<=0 = unmetered)", meterEfKbps);
    cmd.AddValue("meterAf31Kbps",
        "IMPORTANT traffic profile, in kbps (<=0 = unmetered)",
        meterAf31Kbps);
    cmd.AddValue("qosCtrl",
        "Enable the closed-loop controller over the per-class profiles",
        qosCtrl);
    cmd.AddValue("qosActuator",
        "QoS rate actuator: broker (legacy aggregate meter) or station "
        "(distributed Station-gateway meters)",
        g_qosActuator);
    cmd.AddValue("qosEmergencyBorrow",
        "Let EMERGENCY borrow unused IMPORTANT tokens while retaining EF",
        g_qosEmergencyBorrow);
    cmd.AddValue("qosLossFeedback",
        "Count an urgent message not received by its OT-origin deadline as "
        "one controller miss", qosLossFeedback);
    cmd.AddValue("qosShiftWorkload",
        "Shift the IMPORTANT/EMERGENCY incident mix between scenarios",
        qosShiftWorkload);
    cmd.AddValue("qosShiftFactor",
        "Dominant/minority urgent-report ratio in a shifted workload",
        qosShiftFactor);
    cmd.AddValue("qosShiftReportsNormal",
        "Scheduled urgent reports in the normal scenario when shift is on",
        qosShiftReportsNormal);
    cmd.AddValue("qosShiftReportsHigh",
        "Scheduled urgent reports in the high-load scenario when shift is on",
        qosShiftReportsHigh);
    cmd.AddValue("qosShiftReportsEmergency",
        "Scheduled urgent reports in the emergency scenario when shift is on",
        qosShiftReportsEmergency);
    cmd.AddValue("qosCtrlBudget",
        "Total budget shared by the two priority classes, in kbps",
        qosCtrlBudget);
    cmd.AddValue("qosCtrlMs", "Control period in ms", qosCtrlMs);
    cmd.AddValue("qosCtrlMemMs",
        "EWMA memory of the rate and miss estimators, in ms", qosCtrlMemMs);
    cmd.AddValue("qosCtrlBeta", "Feedback gain on the deadline miss rate",
        qosCtrlBeta);
    cmd.AddValue("qosCtrlMinFrac",
        "Minimum guaranteed rate per class, as a fraction of C/2",
        qosCtrlMinFrac);
    cmd.AddValue("qosCtrlMaxStep",
        "Maximum relative change of a profile per control period",
        qosCtrlMaxStep);
    cmd.AddValue("qosCtrlDemoteSignal",
        "Use the meter's own demotion rate as the violation signal instead "
        "of the deadline miss rate seen at the master", qosCtrlDemote);
    cmd.AddValue("qosCtrlPressureOnly",
        "When violations exist, allocate shareable rate from violation "
        "pressure only; idle behavior is selected by qosCtrlPressureHold",
        qosCtrlPressureOnly);
    cmd.AddValue("qosCtrlPressurePower",
        "Exponent applied to the violation ratio in pressure allocation",
        qosCtrlPressurePower);
    cmd.AddValue("qosCtrlPressureHold",
        "In pressure mode, retain the current allocation while no violation "
        "is observed instead of reverting to demand weights",
        qosCtrlPressureHold);
    cmd.AddValue("qosCtrlInitialEfFrac",
        "Initial EMERGENCY share of the total dynamic-QoS budget",
        qosCtrlInitialEfFrac);
    cmd.AddValue("meterBurstBytes",
        "Token bucket size in bytes; must exceed one packet",
        meterBurstBytes);
    cmd.AddValue("qosBlanketTos",
        "Stamp every northbound message with this DSCP regardless of class "
        "(0 = off). Gateway->broker leg only; the broker->master bottleneck "
        "is marked from the header class", g_qosBlanketTos);
    cmd.AddValue("qosQueueCsv",
        "Sampling period in ms for qos_queues.csv per-band occupancy "
        "(0 = off)", qosQueueMs);
    cmd.Parse(argc, argv);
    NS_ABORT_MSG_IF(g_modbusServiceWorkflow && g_modbusMixedWorkflow,
        "Select either read-only service workflow or mixed read/write, not both");

    if (g_qosActuator != "broker" && g_qosActuator != "station") {
        std::cerr << "[WARN] qosActuator='" << g_qosActuator
                  << "' invalid; using broker\n";
        g_qosActuator = "broker";
    }

    g_rlDemoPeriod = std::max(0.5, g_rlDemoPeriod);
    g_rlDemoLoss = std::clamp(g_rlDemoLoss, 0.0, 1.0);
    g_rlLossRecoveryMs = std::max(0.0, g_rlLossRecoveryMs);
    g_rlRouteDelayGapMs = std::max(0.0, g_rlRouteDelayGapMs);
    g_rlRouteLossGap = std::clamp(g_rlRouteLossGap, 0.0, 1.0);
    g_rlRouteIntegrityMs = std::clamp(g_rlRouteIntegrityMs, 20.0, 5000.0);
    qosShiftFactor = std::max(1.0, qosShiftFactor);
    qosShiftReportsNormal = std::max(4u, qosShiftReportsNormal);
    qosShiftReportsHigh = std::max(4u, qosShiftReportsHigh);
    qosShiftReportsEmergency = std::max(4u, qosShiftReportsEmergency);

    // Phase 2: apply stress overrides BEFORE topology setup.
    if (stressMode) {
        CORE_BW          = "10Mbps";   // 100 -> 10 (10x tighter)
        ACCESS_BW        = "2Mbps";    // 10 -> 2 (5x tighter)
        PRIO_QUEUE_LIMIT = 100;        // 1000 -> 100 (10x smaller queues)
        // Slightly elevated errors to add retransmission pressure
        if (errAccess <= 1e-3) errAccess = 5e-3;
        if (errCore   <= 1e-4) errCore   = 1e-3;
        std::cout << "*** STRESS MODE ENABLED ***\n"
                  << "    Core BW:   " << CORE_BW   << " (was 100Mbps)\n"
                  << "    Access BW: " << ACCESS_BW << " (was 10Mbps)\n"
                  << "    Queue:     " << PRIO_QUEUE_LIMIT << " pkts/band\n"
                  << "    errAccess: " << errAccess << " errCore: " << errCore
                  << "\n";
    }

    // Explicit capacity/queue flags are applied AFTER the stress block so
    // they win over it, and they do not touch the error rates (--stress
    // raises errCore to 1e-3, which mixes TCP retransmission delay into
    // every QoS measurement).
    if (!coreBwCli.empty())   CORE_BW = coreBwCli;
    if (!brokerBwCli.empty()) BROKER_BW = brokerBwCli;
    if (queueLenCli > 0)      PRIO_QUEUE_LIMIT = queueLenCli;
    if (devQueueCli > 0)      DEV_QUEUE_LIMIT = devQueueCli;
    g_qosQueueMs = std::max(0.0, qosQueueMs);
    g_qosCtrlOn      = qosCtrl;
    g_qosCtrlBudget  = std::max(0.0, qosCtrlBudget) * 1000.0;
    g_qosCtrlMs      = std::clamp(qosCtrlMs, 10.0, 1000.0);
    g_qosCtrlMemMs   = std::max(g_qosCtrlMs, qosCtrlMemMs);
    g_qosCtrlBeta    = std::max(0.0, qosCtrlBeta);
    g_qosCtrlMinFrac = std::clamp(qosCtrlMinFrac, 0.0, 1.0);
    g_qosCtrlMaxStep = std::clamp(qosCtrlMaxStep, 0.01, 1.0);
    g_qosCtrlUseDemote = qosCtrlDemote;
    g_qosCtrlPressureOnly = qosCtrlPressureOnly;
    g_qosCtrlPressurePower = std::clamp(qosCtrlPressurePower, 1.0, 4.0);
    g_qosCtrlPressureHold = qosCtrlPressureHold;
    g_qosCtrlInitialEfFrac = std::clamp(qosCtrlInitialEfFrac, 0.0, 1.0);
    g_qosSafetyRatio = std::clamp(g_qosSafetyRatio, 0.0, 1.0);
    g_qosCtrlLossFeedback = qosLossFeedback;
    rlBgBurst    = std::max(1.0, rlBgBurst);
    rlBgBurstMs  = std::clamp(rlBgBurstMs, 0.1, 1000.0);
    auto clampOptionalLoad = [](double value) {
        return value < 0.0 ? -1.0 : std::clamp(value, 0.0, 2.0);
    };
    auto clampOptionalBurst = [](double value) {
        return value < 0.0 ? -1.0 : std::max(1.0, value);
    };
    rlBgLoadNormal = clampOptionalLoad(rlBgLoadNormal);
    rlBgLoadHigh = clampOptionalLoad(rlBgLoadHigh);
    rlBgLoadEmergency = clampOptionalLoad(rlBgLoadEmergency);
    rlBgBurstNormal = clampOptionalBurst(rlBgBurstNormal);
    rlBgBurstHigh = clampOptionalBurst(rlBgBurstHigh);
    rlBgBurstEmergency = clampOptionalBurst(rlBgBurstEmergency);
    g_ddosRateMbps = std::max(0.0, g_ddosRateMbps);
    g_ddosSources = std::clamp(g_ddosSources, 1u, 24u);
    g_ddosBurstFactor = std::clamp(g_ddosBurstFactor, 1.0, 20.0);
    g_ddosBurstMs = std::clamp(g_ddosBurstMs, 1.0, 5000.0);
    g_serviceRateJitter = std::clamp(g_serviceRateJitter, 0.0, 0.75);
    g_modbusRoutineWriteProb = std::clamp(g_modbusRoutineWriteProb, 0.0, 0.25);
    if (g_ddosMeterPolicy != "bounded" && g_ddosMeterPolicy != "standard"
        && g_ddosMeterPolicy != "legacy_bypass") {
        std::cerr << "[ERROR] Invalid ddosMeterPolicy\n";
        return 1;
    }
    if (g_ddosPattern != "cbr" && g_ddosPattern != "burst"
        && g_ddosPattern != "random_burst") {
        std::cerr << "[WARN] invalid ddosPattern; using cbr\n";
        g_ddosPattern = "cbr";
    }
    if (g_ddosPlacement != "distributed"
        && g_ddosPlacement != "station0"
        && g_ddosPlacement != "station1"
        && g_ddosPlacement != "station2") {
        std::cerr << "[WARN] invalid ddosPlacement; using distributed\n";
        g_ddosPlacement = "distributed";
    }
    g_ddosWindowMs = std::clamp(g_ddosWindowMs, 100.0, 5000.0);
    g_ddosHighMbps = std::max(0.001, g_ddosHighMbps);
    g_ddosLowMbps = std::clamp(g_ddosLowMbps, 0.0, g_ddosHighMbps);
    g_ddosRfThreshold = std::clamp(g_ddosRfThreshold, 0.01, 0.99);
    g_ddosRfClearThreshold = std::clamp(
        g_ddosRfClearThreshold, 0.0, g_ddosRfThreshold);
    if (g_ddosDetectorMode != "rf" && g_ddosDetectorMode != "threshold") {
        std::cerr << "[WARN] invalid ddosDetectorMode; using rf\n";
        g_ddosDetectorMode = "rf";
    }
    g_ddosAttackWindows = std::max(2u, g_ddosAttackWindows);
    g_ddosClearWindows = std::max(2u, g_ddosClearWindows);
    g_ddosBeQueueLimit = std::clamp(g_ddosBeQueueLimit, 1u,
                                    PRIO_QUEUE_LIMIT);
    if (g_ripPoison && !g_ripRouting) {
        std::cout << "[rip] ripPoison=1 enables ripRouting automatically\n";
        g_ripRouting = true;
    }
    g_ripPoisonStation = std::min(g_ripPoisonStation, 2u);
    g_ripPoisonPath = std::min(g_ripPoisonPath, 2u);
    g_ripPoisonPeriod = std::clamp(g_ripPoisonPeriod, 0.1, 30.0);
    g_ripPoisonMetric = std::clamp(g_ripPoisonMetric, 1u, 15u);
    if (bgWhere != "path" && bgWhere != "allpaths" && bgWhere != "master") {
        std::cerr << "[WARN] bgWhere='" << bgWhere << "' invalid - falling "
                  << "back to path. Valid: path | allpaths | master.\n";
        bgWhere = "path";
    }

    /////////////////////////  deterministic-per-run randomness ///////////////////////
    for (double value : {g_qosRawSourceKbps,g_qosRawStationKbps,g_qosRawBurstBytes,
                         g_qosRawStationBurstBytes,g_qosPrioritySourceKbps,
                         g_qosPrioritySourceBurstBytes})
        NS_ABORT_MSG_IF(!std::isfinite(value) || value<=0,"Boundary rates/bursts must be finite and positive");
    for (auto& policy : g_boundaryPolicies)
        policy.Configure(g_qosRawSourceKbps,g_qosRawStationKbps,g_qosRawBurstBytes,
                         g_qosRawStationBurstBytes,g_qosPrioritySourceKbps,
                         g_qosPrioritySourceBurstBytes);
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(runId);
    g_runId = runId;

    // Mode validation: empty = baseline | dt | rf
    if (!g_mode.empty() && g_mode != "dt" && g_mode != "rf") {
        std::cerr << "[WARN] mode='" << g_mode << "' invalid — "
                  << "falling back to baseline. Valid: dt | rf.\n";
        g_mode = "";
    }
    if (g_qosMode != "private" && g_qosMode != "neutral"
        && g_qosMode != "fifo") {
        std::cerr << "[WARN] qosMode='" << g_qosMode << "' invalid - "
                  << "falling back to private. Valid: private | neutral | "
                  << "fifo.\n";
        g_qosMode = "private";
    }
    if (g_rlMode != "off" && g_rlMode != "heuristic"
        && g_rlMode != "train" && g_rlMode != "qtable") {
        std::cerr << "[WARN] rlMode='" << g_rlMode << "' invalid - "
                  << "falling back to off. Valid: off | heuristic | train | qtable.\n";
        g_rlMode = "off";
    }

    // Ensure output directory exists
    try {
        std::filesystem::create_directories(g_outDir);
    } catch (const std::exception& e) {
        std::cerr << "[ERR] cannot create output dir " << g_outDir
                  << ": " << e.what() << '\n';
        return 1;
    }
    if (g_outDir.back() != '/') g_outDir += '/';
    if (g_rlQTablePath.empty()) g_rlQTablePath = g_outDir + "rl_qtable.csv";
    if (enablePacketCsv) OpenPacketCsv(g_outDir + "scada_packets.csv");
    if (g_enableRuntimeMlCsv)
        OpenRuntimeMlCsv(g_outDir + "scada_runtime_ml.csv");
    OpenRlCsvs();

    g_scenarioDur = sceneDurCli;
    g_animDashboard = animDashboard;
    g_simDuration = BOOTSTRAP_TIME + 3 * g_scenarioDur;
    if (g_ddosStart < 0.0)
        g_ddosStart = BOOTSTRAP_TIME + 1.25 * g_scenarioDur;
    if (g_ddosDuration < 0.0)
        g_ddosDuration = 0.5 * g_scenarioDur;
    g_ddosDuration = std::max(0.1, g_ddosDuration);
    if (g_ddosStart < 0.0 || g_ddosStart >= g_simDuration) {
        std::cerr << "[ERROR] ddosStart must lie inside the simulation\n";
        return 2;
    }
    g_ddosDuration = std::min(g_ddosDuration,
                              g_simDuration - g_ddosStart);
    if (g_ripPoisonStart < 0.0)
        g_ripPoisonStart = BOOTSTRAP_TIME + 1.25 * g_scenarioDur;
    if (g_ripPoisonDuration < 0.0)
        g_ripPoisonDuration = 0.5 * g_scenarioDur;
    if (g_ripPoison && (g_ripPoisonStart < 0.5
        || g_ripPoisonStart >= g_simDuration)) {
        std::cerr << "[ERROR] ripPoisonStart must be >=0.5s and inside "
                  << "the simulation\n";
        return 2;
    }
    g_ripPoisonDuration = std::max(0.1, g_ripPoisonDuration);
    g_ripPoisonDuration = std::min(
        g_ripPoisonDuration, g_simDuration - g_ripPoisonStart);
    g_ddosStateCsv.open(g_outDir + "ddos_state.csv");
    if (!g_ddosStateCsv.is_open()) {
        std::cerr << "[ERROR] cannot open ddos_state.csv\n";
        return 1;
    }
    g_ddosStateCsv << "t,scenario,detected_state,ingress_mbps,"
                      "ingress_packets,mean_packet_bytes,unique_sources,"
                      "source_entropy,dominant_source_frac,udp_frac,"
                      "rate_delta_mbps,attack_probability,detector_mode,"
                      "attack_truth,attack_observed,transition,"
                      "defense_active,be_queue_limit,attack_packets,"
                      "meter_policy,meter_bypass_packets,attack_ef_packets\n";
    if (g_ripRouting) {
        g_ripPoisonCsv.open(g_outDir + "rip_poison.csv");
        if (!g_ripPoisonCsv.is_open()) {
            std::cerr << "[ERROR] cannot open rip_poison.csv\n";
            return 1;
        }
        g_ripPoisonCsv << "t,event,attacker_ip,victim_ip,advertised_host,"
                          "metric,send_ok\n";
        g_ripRouteCsv.open(g_outDir + "rip_routes.csv");
        if (!g_ripRouteCsv.is_open()) {
            std::cerr << "[ERROR] cannot open rip_routes.csv\n";
            return 1;
        }
        g_ripRouteCsv << "t,phase,station,target,gateway,source,output_if,error\n";
    }

    NS_LOG_INFO("─── SCADA-Sim v3.3 ───");
    NS_LOG_INFO("run="     << runId
            << "  mode="    << (g_mode.empty() ? "baseline" : g_mode)
            << "  rlMode="  << g_rlMode
            << "  qosMode=" << g_qosMode
            << "  qosActuator=" << g_qosActuator
            << "  outDir="  << g_outDir
            << "  scnDur="  << g_scenarioDur << "s"
            << "  simDur="  << g_simDuration << "s");
    NS_LOG_INFO("DDoS generator=" << g_ddosEnabled
            << " detector=" << g_ddosDetectorEnabled
            << " detectorMode=" << g_ddosDetectorMode
            << " start=" << g_ddosStart << "s"
            << " duration=" << g_ddosDuration << "s"
            << " aggregate=" << g_ddosRateMbps << "Mbps"
            << " sources=" << g_ddosSources
            << " pattern=" << g_ddosPattern
            << " placement=" << g_ddosPlacement);
    NS_LOG_INFO("RL qtable=" << g_rlQTablePath
            << " alpha=" << g_rlAlpha << " gamma=" << g_rlGamma
            << " epsilon=" << g_rlEpsilon
            << " decision=" << g_rlDecisionMs << "ms"
            << " safeMask=" << g_rlSafeMask);
    NS_LOG_INFO("RIP routing=" << g_ripRouting
            << " poison=" << g_ripPoison
            << " victim=S" << g_ripPoisonStation
            << " targetPath=" << g_ripPoisonPath
            << " start=" << g_ripPoisonStart << "s"
            << " duration=" << g_ripPoisonDuration << "s"
            << " metric=" << g_ripPoisonMetric
            << " detour=" << g_ripDetourBw << '/' << g_ripDetourDelay);

    /////////////////////////───────── NODE TOPOLOGY //////////////////////////////////////////////
    // 29 visible SCADA nodes plus one optional RIP attacker. The provider
    // network is modelled as the
    // northbound Station-Broker links, not as a device in the plant topology.
    //    [0] Master (SCADA, ML at ingress),  [1] MQTT Broker (cloud/DMZ)
    //    [2..4] S0..S2    (Stations: gateway function = OT->MQTT translate +
//                      DSCP mark; router function = path choice + queueing)
    //    [5..28] Field devices (24, OT only)
    NodeContainer all; all.Create(29 + (g_ripPoison ? 1 : 0));
    // Display-only nodes form a vertical status panel in NetAnim. They are
    // intentionally excluded from the Internet stack and every link, so they
    // cannot affect SCADA traffic, routing, queues, or QoS measurements.
    NodeContainer dashboardNodes;
    if (g_animDashboard) dashboardNodes.Create(6);
    Ptr<Node> master = all.Get(0);
    Ptr<Node> broker = all.Get(1);
    Ptr<Node> gw[3]  = { all.Get(2), all.Get(3), all.Get(4) };
    Ptr<Node> ripAttacker = g_ripPoison ? all.Get(29) : nullptr;

    // Field-device ownership: 24 devices over the 4 OT protocols, 8 per
    // Station (no MQTT at the device level).  Per-protocol totals are
    // IEC104 x7, DNP3 x8, Modbus x4, OPC-UA x5.
    // S0 (Power)        : IEC104 x2 + DNP3 x4 + Modbus x2
    // S1 (Production)   : Modbus x2 + OPC-UA x3 + IEC104 x2 + DNP3 x1
    // S2 (Distribution) : DNP3 x3 + IEC104 x3 + OPC-UA x2
    struct FieldDesc {
        uint32_t idx;
        uint32_t gw;
        std::string proto;
        std::string role;
        std::string trafficClass;
        std::string messageFamily;
        std::string animLabel;
        bool periodic;
        bool eventDriven;
    };
    std::vector<FieldDesc> fields = {
        // S0 (Power)
        { 5,0,"IEC104","IEC104_BAY_MIXED",   "IMPORTANT","STATUS",   "I-MIX", true,  true },
        { 6,0,"IEC104","IEC104_PROTECTION",  "EMERGENCY","TRIP",     "I-PRT", true,  true },
        { 7,0,"DNP3",  "DNP3_RTU_MIXED",     "IMPORTANT","STATUS",   "D-MIX", true,  true },
        { 8,0,"DNP3",  "DNP3_PROTECTION",    "EMERGENCY","TRIP",     "D-PRT", true,  true },
        { 9,0,"DNP3",  "DNP3_RECLOSER",      "EMERGENCY","TRIP",     "D-REC", true,  true },
        {10,0,"DNP3",  "DNP3_TELEMETRY",     "NORMAL",   "TELEMETRY","D-TEL", true,  false},
        {11,0,"Modbus","MODBUS_PLC",         "NORMAL",   "TELEMETRY","M-MON", true,  false},
        {12,0,"Modbus","MODBUS_ALARM_REG",   "IMPORTANT","ALARM",    "M-OP/MON", true,  false},
        // S1 (Production)
        {13,1,"Modbus","MODBUS_PLC",         "NORMAL",   "TELEMETRY","M-MON", true,  false},
        {14,1,"Modbus","MODBUS_ALARM_REG",   "IMPORTANT","ALARM",    "M-OP/MON", true,  false},
        {15,1,"OPC-UA","OPCUA_MIXED_SERVER", "IMPORTANT","STATUS",   "O-MIX", true,  true },
        {16,1,"OPC-UA","OPCUA_ALARM_SERVER", "IMPORTANT","ALARM",    "O-ALM", true,  true },
        {17,1,"OPC-UA","OPCUA_DER_CTRL",     "IMPORTANT","ALARM",    "O-DER", true,  true },
        {18,1,"IEC104","IEC104_BAY_MIXED",   "IMPORTANT","STATUS",   "I-MIX", true,  true },
        {19,1,"IEC104","IEC104_PROTECTION",  "EMERGENCY","TRIP",     "I-PRT", true,  true },
        {20,1,"DNP3",  "DNP3_RTU_MIXED",     "IMPORTANT","STATUS",   "D-MIX", true,  true },
        // S2 (Distribution)
        {21,2,"DNP3",  "DNP3_RECLOSER",      "EMERGENCY","TRIP",     "D-REC", true,  true },
        {22,2,"DNP3",  "DNP3_RTU_MIXED",     "IMPORTANT","STATUS",   "D-MIX", true,  true },
        {23,2,"DNP3",  "DNP3_PROTECTION",    "EMERGENCY","TRIP",     "D-PRT", true,  true },
        {24,2,"IEC104","IEC104_RTU_MIXED",   "IMPORTANT","STATUS",   "I-RTU", true,  true },
        {25,2,"IEC104","IEC104_PROTECTION",  "EMERGENCY","TRIP",     "I-PRT", true,  true },
        {26,2,"IEC104","IEC104_BAY_MIXED",   "IMPORTANT","STATUS",   "I-MIX", true,  true },
        {27,2,"OPC-UA","OPCUA_DER_CTRL",     "IMPORTANT","ALARM",    "O-DER", true,  true },
        {28,2,"OPC-UA","OPCUA_ALARM_SERVER", "IMPORTANT","ALARM",    "O-ALM", true,  true },
    };

    /////////////////////////───────── INTERNET STACK //////////////////////////////////////////////
    Ipv4StaticRoutingHelper staticHelper;
    InternetStackHelper stack;
    if (g_ripRouting) {
        // RIP is consulted before endpoint static defaults. This also lets a
        // forged /32 beat the victim's normal connected /30 route.
        RipHelper ripHelper;
        Ipv4ListRoutingHelper routingList;
        routingList.Add(ripHelper, 10);
        routingList.Add(staticHelper, 0);
        stack.SetRoutingHelper(routingList);
    }
    stack.Install(all);

    /////////////////////////───────── P2P HELPERS //////////////////////////////////////////////──
    PointToPointHelper p2pCore;
    p2pCore.SetDeviceAttribute("DataRate", StringValue(CORE_BW));
    p2pCore.SetChannelAttribute("Delay",   StringValue(CORE_DELAY));
    p2pCore.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize",
        QueueSizeValue(QueueSize(std::to_string(DEV_QUEUE_LIMIT) + "p")));

    PointToPointHelper p2pAcc;
    p2pAcc.SetDeviceAttribute("DataRate", StringValue(ACCESS_BW));
    p2pAcc.SetChannelAttribute("Delay",   StringValue(ACCESS_DELAY));

    PointToPointHelper p2pBrk;
    p2pBrk.SetDeviceAttribute("DataRate", StringValue(BROKER_BW));
    p2pBrk.SetChannelAttribute("Delay",   StringValue(BROKER_DELAY));
    p2pBrk.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize",
        QueueSizeValue(QueueSize(std::to_string(DEV_QUEUE_LIMIT) + "p")));

    PointToPointHelper p2pMesh;
    p2pMesh.SetDeviceAttribute("DataRate", StringValue(MESH_BW));
    p2pMesh.SetChannelAttribute("Delay",   StringValue(MESH_DELAY));

    // One independent packet-error process per receive direction.  Sharing a
    // RateErrorModel across links couples their RNG stream, while attaching it
    // only to the field side makes access-link errors asymmetric.
    auto makePacketErrorModel = [](double rate) {
        Ptr<RateErrorModel> model = CreateObject<RateErrorModel>();
        model->SetAttribute("ErrorRate", DoubleValue(rate));
        model->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
        if (g_normalClean) model->Disable();
        g_linkErrorModels.push_back(model);
        return model;
    };

    ///////////////////////// ADDRESSING ////////////////////////////////////
    Ipv4AddressHelper ipv4;
    std::map<uint32_t, std::string> nodeIp;       // node index → IP
    std::string gwProviderIp[3];                   // Station IP on provider link
    std::string brokerProviderIp[3];               // broker IP on each Station link
    Ipv4Address meshNextHop[3][3];
    Ipv4Address meshOwnIp[3][3];
    uint32_t meshOutIf[3][3] = {};
    std::array<std::set<uint32_t>, 3> stationRipExclusions;
    std::set<uint32_t> brokerRipExclusions;

    ///////////////////////// 3 MESH LINKS — S ----- S (multipath for RL) ──
    NetDeviceContainer meshDevs;
    struct MeshPair { uint32_t a, b; const char* subnet; };
    MeshPair meshes[] = {
        {0, 1, "10.8.0.0"},   // S0 ↔ S1
        {1, 2, "10.8.1.0"},   // S1 ↔ S2
        {0, 2, "10.8.2.0"},   // S0 ↔ S2
    };
    for (auto& m : meshes) {
        NetDeviceContainer d = p2pMesh.Install(gw[m.a], gw[m.b]);
        d.Get(0)->SetAttribute("ReceiveErrorModel",
                               PointerValue(makePacketErrorModel(errMesh)));
        d.Get(1)->SetAttribute("ReceiveErrorModel",
                               PointerValue(makePacketErrorModel(errMesh)));
        meshDevs.Add(d);
        ipv4.SetBase(m.subnet, "255.255.255.252");
        Ipv4InterfaceContainer meshIfs = ipv4.Assign(d);
        meshNextHop[m.a][m.b] = meshIfs.GetAddress(1);
        meshNextHop[m.b][m.a] = meshIfs.GetAddress(0);
        meshOwnIp[m.a][m.b] = meshIfs.GetAddress(0);
        meshOwnIp[m.b][m.a] = meshIfs.GetAddress(1);
        meshOutIf[m.a][m.b] = gw[m.a]->GetObject<Ipv4>()
            ->GetInterfaceForDevice(d.Get(0));
        meshOutIf[m.b][m.a] = gw[m.b]->GetObject<Ipv4>()
            ->GetInterfaceForDevice(d.Get(1));
    }

    ///////////////////////// 24 ACCESS LINKS — Si ---- field devices (OT) ──
    int accSubnetIdx = 1;
    for (auto& f : fields) {
        NetDeviceContainer d = p2pAcc.Install(gw[f.gw], all.Get(f.idx));
        d.Get(0)->SetAttribute("ReceiveErrorModel",
                               PointerValue(makePacketErrorModel(errAccess)));
        d.Get(1)->SetAttribute("ReceiveErrorModel",
                               PointerValue(makePacketErrorModel(errAccess)));
        std::ostringstream sub; sub << "10.2." << accSubnetIdx++ << ".0";
        ipv4.SetBase(sub.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifs = ipv4.Assign(d);
        nodeIp[f.idx] = IpToStr(ifs.GetAddress(1));   // field-device side IP
        const uint32_t stationIf = gw[f.gw]->GetObject<Ipv4>()
            ->GetInterfaceForDevice(d.Get(0));
        stationRipExclusions[f.gw].insert(stationIf);
        g_boundaryPolicies[f.gw].AddField(stationIf,ifs.GetAddress(1).Get());
        if (g_ripRouting) {
            const uint32_t fieldIf = all.Get(f.idx)->GetObject<Ipv4>()
                ->GetInterfaceForDevice(d.Get(1));
            staticHelper.GetStaticRouting(all.Get(f.idx)->GetObject<Ipv4>())
                ->SetDefaultRoute(ifs.GetAddress(0), fieldIf);
        }
    }

    ///////////////////////// 3 NORTHBOUND LINKS - Si ---- Broker ////////////
    //   Remote Stations reach the cloud broker through provider-managed links.
    //   The provider itself is not a visible SCADA node. The Station's
    //   provider-facing IP + the publisher's fixed source port form the
    //   ground-truth flow label key.
    NetDeviceContainer gwBrokerDevs;
    for (int i = 0; i < 3; ++i) {
        NetDeviceContainer d = p2pCore.Install(gw[i], broker);
        if (g_rlDemoRouting) {
            g_pathErrorModels[i] = CreateObject<RateErrorModel>();
            g_pathErrorModels[i]->SetAttribute("ErrorRate",
                                               DoubleValue(errCore));
            g_pathErrorModels[i]->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
            if (g_normalClean) g_pathErrorModels[i]->Disable();
            g_linkErrorModels.push_back(g_pathErrorModels[i]);
            d.Get(0)->SetAttribute("ReceiveErrorModel",
                                   PointerValue(g_pathErrorModels[i]));
            d.Get(1)->SetAttribute("ReceiveErrorModel",
                                   PointerValue(g_pathErrorModels[i]));
        } else {
            d.Get(0)->SetAttribute("ReceiveErrorModel",
                                   PointerValue(makePacketErrorModel(errCore)));
            d.Get(1)->SetAttribute("ReceiveErrorModel",
                                   PointerValue(makePacketErrorModel(errCore)));
        }
        gwBrokerDevs.Add(d);
        std::ostringstream sub; sub << "10.1." << (i+1) << ".0";
        ipv4.SetBase(sub.str().c_str(), "255.255.255.252");
        Ipv4InterfaceContainer ifs = ipv4.Assign(d);
        gwProviderIp[i] = IpToStr(ifs.GetAddress(0)); // Station side IP
        brokerProviderIp[i] = IpToStr(ifs.GetAddress(1)); // broker side IP
        if (i == 0) nodeIp[1] = brokerProviderIp[i]; // canonical broker IP
    }

    ///////////////////////// Broker ---- Master //////////////////////////////
    NetDeviceContainer brkMasterDev;
    {
        // WAN ↔ Broker (cloud ingress)
        // Broker ↔ Master (SCADA control center)
        NetDeviceContainer d2 = p2pBrk.Install(broker, master);
        d2.Get(0)->SetAttribute("ReceiveErrorModel",
                                PointerValue(makePacketErrorModel(errCore)));
        d2.Get(1)->SetAttribute("ReceiveErrorModel",
                                PointerValue(makePacketErrorModel(errCore)));
        brkMasterDev.Add(d2);
        ipv4.SetBase("10.7.0.0", "255.255.255.252");
        Ipv4InterfaceContainer ifs2 = ipv4.Assign(d2);
        nodeIp[0] = IpToStr(ifs2.GetAddress(1));      // master IP
        const uint32_t brokerMasterIf = broker->GetObject<Ipv4>()
            ->GetInterfaceForDevice(d2.Get(0));
        brokerRipExclusions.insert(brokerMasterIf);
        if (g_ripRouting) {
            const uint32_t masterIf = master->GetObject<Ipv4>()
                ->GetInterfaceForDevice(d2.Get(1));
            staticHelper.GetStaticRouting(master->GetObject<Ipv4>())
                ->SetDefaultRoute(ifs2.GetAddress(0), masterIf);
        }
    }

    // A dual-homed malicious router injects a forged host route at the victim
    // Station, then forwards poisoned traffic through a deliberately slow
    // detour directly to the Broker. This produces
    // measurable delay/queue pressure instead of an artificial drop flag.
    NetDeviceContainer ripDetourDevs;
    Ipv4Address ripAttackerIngress;
    Ipv4Address ripVictimAddress;
    if (g_ripPoison) {
        PointToPointHelper p2pRip;
        p2pRip.SetDeviceAttribute("DataRate", StringValue(g_ripDetourBw));
        p2pRip.SetChannelAttribute("Delay", StringValue(g_ripDetourDelay));
        p2pRip.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize",
            QueueSizeValue(QueueSize(std::to_string(DEV_QUEUE_LIMIT) + "p")));

        NetDeviceContainer ingress = p2pRip.Install(
            gw[g_ripPoisonStation], ripAttacker);
        ipv4.SetBase("10.9.0.0", "255.255.255.252");
        Ipv4InterfaceContainer ingressIfs = ipv4.Assign(ingress);
        ripVictimAddress = ingressIfs.GetAddress(0);
        ripAttackerIngress = ingressIfs.GetAddress(1);
        ripDetourDevs.Add(ingress);

        NetDeviceContainer egress = p2pRip.Install(
            ripAttacker, broker);
        ipv4.SetBase("10.9.1.0", "255.255.255.252");
        Ipv4InterfaceContainer egressIfs = ipv4.Assign(egress);
        ripDetourDevs.Add(egress);

        const uint32_t attackerOutIf = ripAttacker->GetObject<Ipv4>()
            ->GetInterfaceForDevice(egress.Get(0));
        staticHelper.GetStaticRouting(ripAttacker->GetObject<Ipv4>())
            ->AddHostRouteTo(
                Ipv4Address(brokerProviderIp[g_ripPoisonPath].c_str()),
                egressIfs.GetAddress(1), attackerOutIf);
        Ptr<Ipv4> attackerIpv4 = ripAttacker->GetObject<Ipv4>();
        attackerIpv4->SetForwarding(
            attackerIpv4->GetInterfaceForDevice(ingress.Get(1)), true);
        attackerIpv4->SetForwarding(attackerOutIf, true);

        // The second link is data-only. The first remains RIP-active at the
        // victim so it can receive the forged response from UDP/521.
        brokerRipExclusions.insert(
            broker->GetObject<Ipv4>()->GetInterfaceForDevice(egress.Get(1)));
    }

    // Observation point for the security detector.  This is the Master-side
    // receive trace of the Broker-Master link, so it counts all ingress bytes
    // but has no access to the attack generator's ground-truth flag.
    brkMasterDev.Get(1)->TraceConnectWithoutContext(
        "MacRx", MakeCallback(&CountMasterIngress));

    if (!g_ripRouting) {
        Ipv4GlobalRoutingHelper::PopulateRoutingTables();
        // Legacy mode: preserve the three pre-established static paths.
        for (uint32_t source = 0; source < 3; ++source) {
            Ptr<Ipv4StaticRouting> routing = staticHelper.GetStaticRouting(
                gw[source]->GetObject<Ipv4>());
            for (uint32_t path = 0; path < 3; ++path) {
                if (source == path) continue;
                routing->AddHostRouteTo(
                    Ipv4Address(brokerProviderIp[path].c_str()),
                    meshNextHop[source][path], meshOutIf[source][path]);
            }
        }
    } else {
        auto setRipExclusions = [](Ptr<Node> node,
                                   const std::set<uint32_t>& exclusions) {
            Ptr<Rip> rip = node->GetObject<Rip>();
            NS_ABORT_MSG_IF(!rip, "RIP object missing from node");
            rip->SetInterfaceExclusions(exclusions);
        };
        auto excludeAllRipInterfaces = [&setRipExclusions](Ptr<Node> node) {
            std::set<uint32_t> exclusions;
            Ptr<Ipv4> ipv4Node = node->GetObject<Ipv4>();
            for (uint32_t i = 1; i < ipv4Node->GetNInterfaces(); ++i)
                exclusions.insert(i);
            setRipExclusions(node, exclusions);
        };

        for (uint32_t i = 0; i < 3; ++i)
            setRipExclusions(gw[i], stationRipExclusions[i]);
        setRipExclusions(broker, brokerRipExclusions);
        excludeAllRipInterfaces(master);
        for (const auto& f : fields)
            excludeAllRipInterfaces(all.Get(f.idx));
        if (ripAttacker) excludeAllRipInterfaces(ripAttacker);

        if (g_ripPoison) {
            auto poison = CreateObject<RipPoisonApp>();
            poison->Setup(
                ripAttackerIngress, ripVictimAddress,
                Ipv4Address(brokerProviderIp[g_ripPoisonPath].c_str()),
                ripDetourDevs.Get(1), g_ripPoisonMetric,
                Seconds(g_ripPoisonPeriod));
            ripAttacker->AddApplication(poison);
            poison->SetStartTime(Seconds(g_ripPoisonStart));
            poison->SetStopTime(Seconds(
                g_ripPoisonStart + g_ripPoisonDuration));

            const Ipv4Address auditTarget(
                brokerProviderIp[g_ripPoisonPath].c_str());
            const double before = std::max(0.1, g_ripPoisonStart - 0.25);
            const double active = g_ripPoisonStart + 0.20;
            const double restored = g_ripPoisonStart
                + g_ripPoisonDuration + 0.20;
            Simulator::Schedule(Seconds(before), &AuditRipRoute,
                gw[g_ripPoisonStation], g_ripPoisonStation,
                auditTarget, std::string("before"));
            Simulator::Schedule(Seconds(active), &AuditRipRoute,
                gw[g_ripPoisonStation], g_ripPoisonStation,
                auditTarget, std::string("poisoned"));
            if (restored < g_simDuration) {
                Simulator::Schedule(Seconds(restored), &AuditRipRoute,
                    gw[g_ripPoisonStation], g_ripPoisonStation,
                    auditTarget, std::string("restored"));
            }
        }
    }
    RlMode rlMode = ParseRlMode(g_rlMode);
    for (uint32_t i = 0; i < 3; ++i) {
        g_gatewayAgents[i].Setup(i, rlMode, g_rlAlpha, g_rlGamma,
                                 g_rlEpsilon, g_rlDecisionMs,
                                 g_rlTimeoutMs, g_rlSafeMask,
                                 g_rlLossRecoveryMs,
                                 g_rlRouteEvidenceGate,
                                 g_rlRouteDelayGapMs,
                                 g_rlRouteLossGap,
                                 g_rlRouteIntegrity,
                                 g_rlDataPlaneFailover,
                                 &g_rlTransitionCsv);
        if (rlMode == RlMode::TRAIN || rlMode == RlMode::QTABLE) {
            bool loaded = g_gatewayAgents[i].LoadQTable(g_rlQTablePath);
            if (rlMode == RlMode::QTABLE && !loaded) {
                std::cerr << "[ERROR] Q-table is missing, empty, or uses an "
                          << "incompatible state schema: " << g_rlQTablePath
                          << "\nRetrain a new table for health_best_v4_sev.\n";
                return 1;
            }
        }
    }
    if (g_rlRouteIntegrity && g_ripRouting) {
        const double monitorStart = BOOTSTRAP_TIME
            + std::min(2.0, 0.20 * g_scenarioDur);
        for (uint32_t station = 0; station < 3; ++station) {
            for (uint32_t path = 0; path < 3; ++path) {
                Simulator::Schedule(Seconds(monitorStart),
                    &SampleRouteIntegrity, gw[station], station, path,
                    Ipv4Address(brokerProviderIp[path].c_str()));
            }
        }
    }

    /////////////////////////─ PRIO QUEUE DISC INSTALLATION ///////////////////////─────
    //   4-band PrioQueueDisc honours the DSCP that the Stations stamp.
    //   It is installed on the Station's own first hop (S↔WAN) and on the
    //   mesh links always.  The leg DOWNSTREAM of the WAN (WAN↔Broker,
    //   Broker-Master honours DSCP only in private mode. In neutral mode, links
    //   are plain FIFO — modelling routers that ignore/strip DSCP, so priority
    //   is lost exactly at the congested core and the ML must recover it.
    TrafficControlHelper tch;
    uint16_t handle = tch.SetRootQueueDisc("ns3::PrioQueueDisc",
        "Priomap", StringValue("0 1 2 3 3 3 3 3 3 3 3 3 3 3 3 3"));
    TrafficControlHelper::ClassIdList cid =
        tch.AddQueueDiscClasses(handle, 4, "ns3::QueueDiscClass");
    if (g_qosBeFairQueue) {
        TrafficControlHelper::ClassIdList priorityIds(cid.begin(), cid.begin() + 3);
        TrafficControlHelper::ClassIdList beIds(cid.begin() + 3, cid.end());
        tch.AddChildQueueDiscs(handle, priorityIds, "ns3::FifoQueueDisc",
            "MaxSize", QueueSizeValue(QueueSize(
                std::to_string(PRIO_QUEUE_LIMIT) + "p")));
        tch.AddChildQueueDiscs(handle, beIds, "ns3::FqCoDelQueueDisc",
            "MaxSize", QueueSizeValue(QueueSize(
                std::to_string(PRIO_QUEUE_LIMIT) + "p")),
            "DropBatchSize", UintegerValue(1));
    } else {
        tch.AddChildQueueDiscs(handle, cid, "ns3::FifoQueueDisc",
            "MaxSize", QueueSizeValue(QueueSize(
                std::to_string(PRIO_QUEUE_LIMIT) + "p")));
    }
    tch.AddPacketFilter(handle, "ns3::ScadaTosFilter");

    TrafficControlHelper tchDel;
    tchDel.Uninstall(gwBrokerDevs);
    tchDel.Uninstall(meshDevs);
    tchDel.Uninstall(brkMasterDev);
    if (ripDetourDevs.GetN() > 0) tchDel.Uninstall(ripDetourDevs);

    if (g_qosMode == "private") {
        QueueDiscContainer northboundQ = tch.Install(gwBrokerDevs);
        for (uint32_t path = 0; path < 3; ++path) {
            uint32_t index = 2 * path; // gateway-facing device for each link
            if (index < northboundQ.GetN())
                g_pathQueues[path] = northboundQ.Get(index);
        }
        tch.Install(meshDevs);      // mesh priority preserved in private mode
        if (ripDetourDevs.GetN() > 0) tch.Install(ripDetourDevs);
        QueueDiscContainer brkQ = tch.Install(brkMasterDev);
        if (brkQ.GetN() > 0) g_brkQueue = brkQ.Get(0);  // broker-side egress
    }
    else if (g_qosMode == "fifo") {
        // Honest no-QoS baseline: one band, but the SAME total buffer as the
        // four priority bands, on the same devices.  Plain `neutral` removes
        // the queue disc altogether, which leaves only the small NetDevice
        // TxQueue - that changes the buffer size as well as the scheduling
        // discipline, so it cannot isolate the effect of priority.
        TrafficControlHelper tchFifo;
        tchFifo.SetRootQueueDisc("ns3::FifoQueueDisc", "MaxSize",
            QueueSizeValue(QueueSize(
                std::to_string(4 * PRIO_QUEUE_LIMIT) + "p")));
        QueueDiscContainer nb = tchFifo.Install(gwBrokerDevs);
        for (uint32_t path = 0; path < 3; ++path) {
            uint32_t index = 2 * path;
            if (index < nb.GetN()) g_pathQueues[path] = nb.Get(index);
        }
        tchFifo.Install(meshDevs);
        if (ripDetourDevs.GetN() > 0) tchFifo.Install(ripDetourDevs);
        QueueDiscContainer bq = tchFifo.Install(brkMasterDev);
        if (bq.GetN() > 0) g_brkQueue = bq.Get(0);
    }
    // else: public-Internet mode — downstream legs keep default FIFO (no
    // neutral mode keeps the default FIFO queue discs.

    // A defense-capable router keeps a deliberately short BE buffer from
    // startup.  Runtime shrinking is invalid in ns-3 when occupancy already
    // exceeds the requested size.  E/I preservation remains state-driven.
    ConfigureDdosBeQueueLimits();
    // A child FqCoDel does not inherit a root NetDevice automatically.
    // Set its byte quantum explicitly; zero quantum cannot advance DRR.
    if (g_qosBeFairQueue) {
        for (uint32_t n = 0; n < all.GetN(); ++n) {
            Ptr<Node> node = all.Get(n);
            Ptr<TrafficControlLayer> layer = node->GetObject<TrafficControlLayer>();
            if (!layer) continue;
            for (uint32_t d = 0; d < node->GetNDevices(); ++d) {
                Ptr<NetDevice> device = node->GetDevice(d);
                Ptr<QueueDisc> root = layer->GetRootQueueDiscOnDevice(device);
                if (!root || root->GetNQueueDiscClasses() != 4) continue;
                Ptr<FqCoDelQueueDisc> fair = DynamicCast<FqCoDelQueueDisc>(
                    root->GetQueueDiscClass(3)->GetQueueDisc());
                if (fair) fair->SetQuantum(device->GetMtu());
            }
        }
    }

    if (enablePcap) {
        p2pMesh.EnablePcap(g_outDir + "rl-mesh", meshDevs, true);
        p2pCore.EnablePcap(g_outDir + "rl-northbound", gwBrokerDevs, true);
    }
    Simulator::Schedule(MilliSeconds(100), &UpdateRlPathQueues);
    if (g_qosQueueMs > 0.0)
        Simulator::Schedule(MilliSeconds(static_cast<uint64_t>(g_qosQueueMs)),
                            &LogQosQueues);
    if (g_rlDemoRouting) {
        g_rlDemoBaseLoss = errCore;
        g_rlDemoCycle = 0;
        g_rlDemoDegradedPath = 3;
        Simulator::Schedule(Seconds(BOOTSTRAP_TIME + (g_normalClean ? g_scenarioDur : 1.0)),
                            &RotateRlDemoPath);
    }

    // =================================================================
    //                          APPLICATIONS
    // =================================================================
    ///////////////////////// Master sink — MQTT forward only ///////////////////////
    //   The master is now a pure MQTT subscriber: OT protocols terminate at the
    //   gateways, so the master only receives the broker's forwarded stream.
    auto masterSub = CreateObject<ScadaMasterSubscriberApp>();
    masterSub->Setup(PORT_MQTT_FWD, &OnMasterDelivery);
    master->AddApplication(masterSub);
    masterSub->SetStartTime(Seconds(0.0));
    masterSub->SetStopTime(Seconds(g_simDuration + 1));

    // Optional training environment: one northbound path is congested during
    // a rotating window in each scenario. The selected path changes with run
    // id, preventing the Q-table from memorizing an absolute time schedule.
    if (rlCongestion) {
        double boundedLoad = std::clamp(rlBgLoad, 0.0, 2.0);
        const std::array<double, 3> scenarioLoad{
            rlBgLoadNormal < 0.0 ? boundedLoad : rlBgLoadNormal,
            rlBgLoadHigh < 0.0 ? boundedLoad : rlBgLoadHigh,
            rlBgLoadEmergency < 0.0 ? boundedLoad : rlBgLoadEmergency};
        const std::array<double, 3> scenarioBurst{
            rlBgBurstNormal < 0.0 ? rlBgBurst : rlBgBurstNormal,
            rlBgBurstHigh < 0.0 ? rlBgBurst : rlBgBurstHigh,
            rlBgBurstEmergency < 0.0 ? rlBgBurst : rlBgBurstEmergency};
        const double startFrac = bgFull ? 0.10 : 0.20;
        const double stopFrac  = bgFull ? 0.90 : 0.70;

        // Background load generator.  `rlBgBurst` is the peak/mean rate ratio:
        // the source is ON for an exponentially distributed rlBgBurstMs and
        // OFF for rlBgBurstMs*(burst-1), so the mean stays at `meanBps` while
        // the instantaneous rate is meanBps*burst.  With burst = 1 the source
        // is the original deterministic CBR, which is a D/D/1 arrival process
        // and therefore queues nothing at all below rho = 1.
        auto configureBg = [&](OnOffHelper& bg, uint64_t meanBps,
                               double burstFactor) {
            bg.SetAttribute("Tos", UintegerValue(std::min(rlBgTos, 255u)));
            if (burstFactor <= 1.0 + 1e-9) {
                bg.SetConstantRate(DataRate(meanBps), 1200);
                return;
            }
            uint64_t peakBps = static_cast<uint64_t>(meanBps * burstFactor);
            double onS  = rlBgBurstMs / 1000.0;
            double offS = onS * (burstFactor - 1.0);
            std::ostringstream on, off;
            on  << "ns3::ExponentialRandomVariable[Mean=" << onS  << "]";
            off << "ns3::ExponentialRandomVariable[Mean=" << offS << "]";
            bg.SetAttribute("OnTime",  StringValue(on.str()));
            bg.SetAttribute("OffTime", StringValue(off.str()));
            bg.SetAttribute("DataRate", DataRateValue(DataRate(peakBps)));
            bg.SetAttribute("PacketSize", UintegerValue(1200));
        };
        auto installSink = [&](Ptr<Node> node, uint16_t port) {
            PacketSinkHelper sink("ns3::UdpSocketFactory",
                InetSocketAddress(Ipv4Address::GetAny(), port));
            ApplicationContainer sinks = sink.Install(node);
            sinks.Start(Seconds(0.0));
            sinks.Stop(Seconds(g_simDuration + 1));
        };
        auto window = [&](ApplicationContainer& traffic, uint32_t scenario) {
            double scenarioStart = BOOTSTRAP_TIME + scenario * g_scenarioDur;
            traffic.Start(Seconds(scenarioStart + startFrac * g_scenarioDur));
            traffic.Stop(Seconds(scenarioStart + stopFrac * g_scenarioDur));
        };

        if (bgWhere == "master") {
            // The broker->master link carries every northbound message from
            // every path, so no routing decision can avoid this queue.  Load
            // is a fraction of that link's own capacity.
            installSink(master, 9310);
            for (uint32_t scenario = 0; scenario < 3; ++scenario) {
                uint64_t bgBps = static_cast<uint64_t>(
                    DataRate(BROKER_BW).GetBitRate()
                    * scenarioLoad[scenario]);
                if (bgBps == 0) continue;
                OnOffHelper bg("ns3::UdpSocketFactory", InetSocketAddress(
                    Ipv4Address(nodeIp[0].c_str()), 9310));
                configureBg(bg, bgBps, scenarioBurst[scenario]);
                ApplicationContainer traffic = bg.Install(broker);
                window(traffic, scenario);
                NS_LOG_INFO("[bg] broker->master scenario=" << scenario
                            << " mean=" << bgBps / 1e6 << " Mbps burst x"
                            << scenarioBurst[scenario] << " tos " << rlBgTos);
            }
        } else {
            for (uint32_t path = 0; path < 3; ++path)
                installSink(broker, 9300 + path);
            for (uint32_t scenario = 0; scenario < 3; ++scenario) {
                uint64_t bgBps = static_cast<uint64_t>(
                    DataRate(CORE_BW).GetBitRate()
                    * scenarioLoad[scenario]);
                if (bgBps == 0) continue;
                // "path": one rotating provider link per scenario (original
                // behaviour, kept so the RL artefacts stay reproducible).
                // "allpaths": all three at once, so rerouting cannot escape.
                uint32_t first = (g_runId + scenario) % 3;
                uint32_t count = (bgWhere == "allpaths") ? 3 : 1;
                for (uint32_t k = 0; k < count; ++k) {
                    uint32_t path = (first + k) % 3;
                    OnOffHelper bg("ns3::UdpSocketFactory", InetSocketAddress(
                        Ipv4Address(brokerProviderIp[path].c_str()),
                        9300 + path));
                    configureBg(bg, bgBps, scenarioBurst[scenario]);
                    ApplicationContainer traffic = bg.Install(gw[path]);
                    window(traffic, scenario);
                }
                NS_LOG_INFO("[bg] " << bgWhere << " scenario=" << scenario
                            << " mean=" << bgBps / 1e6
                            << " Mbps per link, burst x"
                            << scenarioBurst[scenario] << " tos " << rlBgTos);
            }
        }
    }

    // =================================================================
    //   per-instance device configuration
    //   ////////////////////////////////////////////////////////////////////////////////////////////─────────
    //   Each field device gets:
    //     • a randomly-sampled DeviceProfile (FAST/NORMAL/TELE/BULK)
    //     • baseline (interval, payload) from the profile's range
    //     • burst probability (DNP3 only)
    // =================================================================
    auto profileRng = CreateObject<UniformRandomVariable>();
    std::map<uint32_t, DeviceConfig> deviceCfg;
    NS_LOG_INFO("Per-instance device profiles (run=" << runId << "):");
    for (auto& f : fields) {
        deviceCfg[f.idx] = SampleDeviceConfig(f.proto, profileRng);
        const DeviceConfig& c = deviceCfg[f.idx];
        std::ostringstream os;
        os << "  f" << std::setw(2) << f.idx
           << " " << std::setw(7) << f.proto
           << "  prof=" << std::setw(6) << ProfileName(c.profile)
           << "  base_int=" << std::fixed << std::setprecision(3)
           << c.baseInt << "s"
           << "  base_pay=" << c.basePay << "B";
        if (f.proto == "DNP3") {
            os << "  burst=" << std::setprecision(3) << c.burstProb;
        }
        NS_LOG_INFO(os.str());
    }

    ///////////////////////// Devices (OT) + gateway masters + publishers ////
    //   Per device:  slave/server on the field node; the OT master/client on
    //   its gateway (talks OT over the access link); one on-demand MQTT
    //   publisher on the gateway (fixed source port) that emits exactly one
    //   publish per OT data frame the device sends. OnOtUplink is a zero-delay
    //   translation proxy bound to the slave Tx trace; it is not a second OT
    //   packet traversal through the gateway application.
    std::map<uint32_t, GatewayPublisherSet> devPub;
    std::map<uint32_t, Ptr<Dnp3OutstationApp>> dnpByNode;
    std::map<uint32_t, Ptr<Iec104ControlledApp>> iecByNode;
    std::map<uint32_t, Ptr<OpcUaServerApp>> opcByNode;
    std::map<uint32_t, Ptr<ModbusSlaveApp>> modbusByNode;
    auto traceCtx = [&](const std::string& key, uint32_t nodeId,
                        uint32_t deviceId, const std::string& proto,
                        const std::string& direction,
                        const std::string& role) -> ScadaTraceContext* {
        ScadaTraceContext ctx;
        ctx.nodeId = nodeId;
        ctx.deviceId = deviceId;
        ctx.protocolId = ProtocolId(proto);
        ctx.protocol = proto;
        ctx.direction = direction;
        ctx.deviceRole = role;
        auto res = g_traceContexts.emplace(key, ctx);
        if (!res.second) res.first->second = ctx;
        return &res.first->second;
    };
    auto registerFlowMeta = [&](const std::string& key, const FieldDesc& f) {
        g_flowLabelMap[key] = f.proto;
        g_flowRoleMap[key] = f.role;
        g_flowClassMap[key] = f.trafficClass;
        g_flowProtoIdMap[key] = ProtocolId(f.proto);
        g_flowDeviceTypeMap[key] = DeviceTypeId(f.role);
        g_flowMsgFamilyMap[key] = MessageFamilyId(f.messageFamily);
        g_flowEventCapMap[key] = f.eventDriven ? 1 : 0;
        g_flowMixedMap[key] = (f.periodic && f.eventDriven) ? 1 : 0;
    };
    for (auto& f : fields) {
        const std::string& ip = nodeIp[f.idx];    // field-device IP
        Ptr<Node> node   = all.Get(f.idx);         // field-device node
        Ptr<Node> gwNode = gw[f.gw];               // its gateway
        const std::string& proto = f.proto;
        const DeviceConfig& cfg  = deviceCfg[f.idx];
        uint32_t mqttSz = (cfg.basePay > 0) ? cfg.basePay : 1;

        // ---- on-demand MQTT publishers (hosted on the gateway) ----
        // path 0..2 sends to the broker IP on S0/S1/S2's provider link.
        // Non-local paths traverse the Station mesh first, then that uplink.
        GatewayPublisherSet routes;
        routes.gw = f.gw;
        routes.deviceId = f.idx;
        routes.protocolId = ProtocolId(proto);
        routes.protocol = proto;
        for (uint32_t path = 0; path < 3; ++path) {
            uint16_t lport = (uint16_t)(30000 + f.idx * 10 + path);
            std::string publisherSourceIp = path == f.gw
                ? gwProviderIp[f.gw]
                : IpToStr(meshOwnIp[f.gw][path]);
            auto pub = CreateObject<MqttPublisherApp>();
            pub->Setup(InetSocketAddress(Ipv4Address(brokerProviderIp[path].c_str()), PORT_MQTT),
                       publisherSourceIp);
            pub->SetOnDemand(true);
            pub->SetLocalPort(lport);
            pub->SetBaseline(cfg.baseInt, mqttSz);
            gwNode->AddApplication(pub);
            pub->SetStartTime(Seconds(1.0));
            pub->SetStopTime(Seconds(g_simDuration));
            pub->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnAppTx, proto + "@" + publisherSourceIp));
            pub->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("mqtt:" + std::to_string(f.idx) + ":" + std::to_string(path),
                             f.gw + 2, f.idx, "MQTT", "northbound", f.role)));
            g_mqttPubs.push_back(pub);
            routes.pathPub[path] = pub;

            // northbound ground-truth label: gatewayProviderIp:fixedSrcPort -> protocol
            registerFlowMeta(publisherSourceIp + ":" + std::to_string(lport), f);
        }
        devPub[f.idx] = routes;

        // ---- OT slave/server on the device, OT master/client on the gateway -
        if (proto == "Modbus") {
            auto slv = CreateObject<ModbusSlaveApp>();
            slv->Setup(ip);
            slv->SetBaseline(cfg.basePay);
            slv->EnableMixedWorkflow(g_modbusMixedWorkflow);
            slv->EnableServiceWorkflow(g_modbusServiceWorkflow);
            node->AddApplication(slv);
            slv->SetStartTime(Seconds(1.0));
            slv->SetStopTime(Seconds(g_simDuration));
            slv->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnAppTx, std::string("Modbus@") + ip));
            slv->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("modbus-u:" + std::to_string(f.idx),
                             f.idx, f.idx, proto, "uplink", f.role)));
            slv->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnOtUplink, &devPub[f.idx]));
            g_modbusSlaves.push_back(slv);
            modbusByNode[f.idx] = slv;
            registerFlowMeta(ip + ":" + std::to_string(PORT_MODBUS), f);

            auto mst = CreateObject<ModbusMasterApp>();
            mst->Setup(InetSocketAddress(Ipv4Address(ip.c_str()), PORT_MODBUS),
                       gwProviderIp[f.gw]);
            mst->SetBaseline(cfg.baseInt);
            mst->EnableMixedWorkflow(g_modbusMixedWorkflow,
                static_cast<uint16_t>(std::clamp(
                    (static_cast<int>(cfg.basePay)-9)/2, 4, 100)),
                g_modbusRoutineWriteProb);
            mst->EnableServiceWorkflow(g_modbusServiceWorkflow);
            mst->SetOperationalRefresh(g_modbusOperationalRefreshMs / 1000.0);
            gwNode->AddApplication(mst);
            mst->SetStartTime(Seconds(1.5));
            mst->SetStopTime(Seconds(g_simDuration));
            mst->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("modbus-d:" + std::to_string(f.idx),
                             f.gw + 2, f.idx, proto, "downlink", f.role)));
            g_modbusMasters.push_back(mst);
        }
        else if (proto == "DNP3") {
            auto out = CreateObject<Dnp3OutstationApp>();
            out->Setup(ip);
            double baseRate = (cfg.baseInt > 0) ? 1.0 / cfg.baseInt : 0.1;
            out->SetBaseline(baseRate, cfg.basePay, cfg.burstProb);
            if (f.eventDriven && !f.periodic) {
                out->SetBaseline(std::max(baseRate, 2.0), cfg.basePay,
                                 std::max(cfg.burstProb, 0.20));
            }
            out->SetUnsolicitedEnabled(f.eventDriven);
            node->AddApplication(out);
            out->SetStartTime(Seconds(1.0));
            out->SetStopTime(Seconds(g_simDuration));
            out->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnAppTx, std::string("DNP3@") + ip));
            out->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("dnp3-u:" + std::to_string(f.idx),
                             f.idx, f.idx, proto, "uplink", f.role)));
            out->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnOtUplink, &devPub[f.idx]));
            g_dnp3Outstations.push_back(out);
            dnpByNode[f.idx] = out;
            registerFlowMeta(ip + ":" + std::to_string(PORT_DNP3), f);

            auto mst = CreateObject<Dnp3MasterApp>();
            mst->Setup(InetSocketAddress(Ipv4Address(ip.c_str()), PORT_DNP3),
                       gwProviderIp[f.gw]);
            mst->SetPollingEnabled(f.periodic);
            gwNode->AddApplication(mst);
            mst->SetStartTime(Seconds(1.5));
            mst->SetStopTime(Seconds(g_simDuration));
            mst->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("dnp3-d:" + std::to_string(f.idx),
                             f.gw + 2, f.idx, proto, "downlink", f.role)));
            g_dnp3Masters.push_back(mst);
        }
        else if (proto == "IEC104") {
            auto ctd = CreateObject<Iec104ControlledApp>();
            ctd->Setup(ip);
            ctd->SetBaseline(cfg.baseInt);
            ctd->SetPeriodicEnabled(f.periodic);
            ctd->SetEventModel(f.eventDriven, f.eventDriven ? 0.5 : 0.0);
            node->AddApplication(ctd);
            ctd->SetStartTime(Seconds(1.0));
            ctd->SetStopTime(Seconds(g_simDuration));
            ctd->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnAppTx, std::string("IEC104@") + ip));
            ctd->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("iec-u:" + std::to_string(f.idx),
                             f.idx, f.idx, proto, "uplink", f.role)));
            ctd->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnOtUplink, &devPub[f.idx]));
            g_iecControlled.push_back(ctd);
            iecByNode[f.idx] = ctd;
            registerFlowMeta(ip + ":" + std::to_string(PORT_IEC104), f);

            auto ctl = CreateObject<Iec104ControllingApp>();
            ctl->Setup(InetSocketAddress(Ipv4Address(ip.c_str()), PORT_IEC104),
                       gwProviderIp[f.gw]);
            gwNode->AddApplication(ctl);
            ctl->SetStartTime(Seconds(1.5));
            ctl->SetStopTime(Seconds(g_simDuration));
            ctl->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("iec-d:" + std::to_string(f.idx),
                             f.gw + 2, f.idx, proto, "downlink", f.role)));
            g_iecControlling.push_back(ctl);
        }
        else if (proto == "OPC-UA") {
            auto srv = CreateObject<OpcUaServerApp>();
            srv->Setup(ip);
            srv->SetBaseline(cfg.baseInt, cfg.basePay);
            node->AddApplication(srv);
            srv->SetStartTime(Seconds(1.0));
            srv->SetStopTime(Seconds(g_simDuration));
            srv->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnAppTx, std::string("OPC-UA@") + ip));
            srv->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("opc-u:" + std::to_string(f.idx),
                             f.idx, f.idx, proto, "uplink", f.role)));
            srv->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnOtUplink, &devPub[f.idx]));
            g_opcServers.push_back(srv);
            opcByNode[f.idx] = srv;
            registerFlowMeta(ip + ":" + std::to_string(PORT_OPCUA), f);

            auto cli = CreateObject<OpcUaClientApp>();
            cli->Setup(InetSocketAddress(Ipv4Address(ip.c_str()), PORT_OPCUA),
                       gwProviderIp[f.gw]);
            gwNode->AddApplication(cli);
            cli->SetStartTime(Seconds(1.5));
            cli->SetStopTime(Seconds(g_simDuration));
            cli->TraceConnectWithoutContext("Tx",
                MakeBoundCallback(&OnPacketTrace,
                    traceCtx("opc-d:" + std::to_string(f.idx),
                             f.gw + 2, f.idx, proto, "downlink", f.role)));
            g_opcClients.push_back(cli);
        }
    }

    ///////////////////////// MQTT Broker (Role A server + Role B client) ──────
    auto brk = CreateObject<MqttBrokerApp>();
    brk->Setup(InetSocketAddress(Ipv4Address(nodeIp[0].c_str()),
                                  PORT_MQTT_FWD), nodeIp[1]);
    broker->AddApplication(brk);
    {
        g_broker = brk;
        brk->SetEmergencyBorrow(g_qosEmergencyBorrow);
        double burst = std::max(500.0, meterBurstBytes);
        // The controller shares a total budget C between the two priority
        // classes. The initial split is configurable for controller startup;
        // both rates still sum exactly to C.
        if (g_qosCtrlOn) {
            double rMin = std::min(g_qosCtrlBudget / 2.0,
                g_qosCtrlMinFrac * g_qosCtrlBudget / 2.0);
            double initialEf = std::clamp(
                g_qosCtrlInitialEfFrac * g_qosCtrlBudget,
                rMin, g_qosCtrlBudget - rMin);
            double initialAf = g_qosCtrlBudget - initialEf;
            meterEfKbps = initialEf / 1000.0;
            meterAf31Kbps = initialAf / 1000.0;
            g_qosCtrl[2].rateBps = initialEf;
            g_qosCtrl[1].rateBps = initialAf;
            std::cout << "[qosCtrl] budget " << g_qosCtrlBudget / 1000.0
                      << " kbps, period " << g_qosCtrlMs << " ms, memory "
                      << g_qosCtrlMemMs << " ms, beta " << g_qosCtrlBeta
                      << ", rmin " << g_qosCtrlMinFrac << "*C/2, maxstep "
                      << g_qosCtrlMaxStep << '\n';
        }
        bool anyMeter = false;
        for (auto& kv : {std::make_pair(2u, meterEfKbps),
                         std::make_pair(1u, meterAf31Kbps)}) {
            if (kv.second <= 0.0) continue;
            if (g_qosActuator == "station") {
                const double stationCount = static_cast<double>(
                    std::max<size_t>(1, g_stationMeters.size()));
                const double stationRate = kv.second * 1000.0 / stationCount;
                const double stationBurst = burst / stationCount;
                for (uint32_t gateway = 0;
                     gateway < g_stationMeters.size(); ++gateway) {
                    SetStationClassProfile(
                        gateway, kv.first, stationRate, stationBurst);
                }
                std::cout << "[meter] distributed Station class " << kv.first
                          << " aggregate profile " << kv.second
                          << " kbps; initial per-egress "
                          << stationRate / 1000.0 << " kbps, bucket "
                          << stationBurst << " B each\n";
            } else {
                brk->SetClassProfile(kv.first, kv.second * 1000.0, burst);
                std::cout << "[meter] Broker class " << kv.first
                          << " profile " << kv.second << " kbps, bucket "
                          << burst << " B\n";
            }
            anyMeter = true;
        }
        if (anyMeter && g_qosActuator == "broker") {
            brk->SetMeterCallback([](uint64_t id, uint8_t requested,
                                     uint8_t served, bool demoted,
                                     bool borrowed, uint32_t bytes,
                                     uint64_t originTimeNs) {
                g_msgServed[id] = {served, demoted, borrowed};
                if (g_qosCtrlOn && requested < g_qosCtrl.size()) {
                    QosCtrlClass& sensor = g_qosCtrl[requested];
                    sensor.bytesInWindow += bytes;
                    ++sensor.offered;
                    // A successful EMERGENCY borrow protects the packet's EF
                    // service, but it still proves that the class's own
                    // profile was exhausted. Feed that scarcity to the
                    // controller so borrowing does not hide the need to
                    // rebalance future rates.
                    if (demoted || borrowed) ++sensor.demoted;
                    ++g_qosEdgeOffered[requested];
                    if (demoted) ++g_qosEdgeDemoted[requested];
                    if (borrowed) ++g_qosEdgeBorrowed[requested];
                    if (g_qosCtrlLossFeedback && requested > 0) {
                        g_qosDeadlines[id] = {requested, false};
                        Time expires = NanoSeconds(originTimeNs)
                            + MilliSeconds(static_cast<uint64_t>(
                                RlDeadlineMs(requested)));
                        if (expires <= Simulator::Now()) {
                            Simulator::ScheduleNow(&ExpireQosDeadline, id);
                        } else {
                            Simulator::Schedule(expires - Simulator::Now(),
                                                &ExpireQosDeadline, id);
                        }
                    }
                }
            });
        }
        if (g_qosEmergencyBorrow)
            std::cout << "[qos] EMERGENCY one-way token borrowing enabled\n";
        if (g_qosCtrlLossFeedback)
            std::cout << "[qosCtrl] OT-origin loss-aware feedback enabled\n";
        if (g_qosCtrlPressureOnly)
            std::cout << "[qosCtrl] violation-pressure allocation enabled\n";
        if (g_qosCtrlOn && anyMeter)
            Simulator::Schedule(MilliSeconds(
                static_cast<uint64_t>(g_qosCtrlMs)), &RunQosController);
    }
    brk->SetStartTime(Seconds(0.5));
    brk->SetStopTime(Seconds(g_simDuration));
    brk->TraceConnectWithoutContext("Tx",
        MakeBoundCallback(&OnAppTx, std::string("MQTT@") + nodeIp[1]));
    // Broker -> Master forwarded (aggregate) flow.
    g_flowLabelMap[nodeIp[0] + ":" + std::to_string(PORT_MQTT_FWD)] = "MQTT";
    g_flowRoleMap[nodeIp[0] + ":" + std::to_string(PORT_MQTT_FWD)] = "BROKER";
    g_flowClassMap[nodeIp[0] + ":" + std::to_string(PORT_MQTT_FWD)] = "NORMAL";

    // =================================================================
    //                       BOOTSTRAP SIGNALLING
    //   Master broadcasts a small UDP "HELLO" packet at t=BOOTSTRAP_TIME
    //   to every field node.  Listeners on each node arm their gated apps
    //   (DNP3 unsolicited, IEC-104 spontaneous, MQTT publish) so no
    //   field-initiated traffic flows until the master signals it is online.
    //   (Station heartbeat/status removed — Stations no longer have gated apps.)
    // =================================================================
    {
        // Master announce app
        auto announce = CreateObject<BootstrapAnnounceApp>();
        announce->Setup(Seconds(BOOTSTRAP_TIME));
        master->AddApplication(announce);
        announce->SetStartTime(Seconds(0.1));   // before BOOTSTRAP_TIME
        announce->SetStopTime(Seconds(g_simDuration));

        // Per-field listener: arm the device's gateway publisher (all 24) and,
        // for spontaneous OT senders, the slave/outstation too.
        size_t dnpIdx = 0, iecIdx = 0;
        for (auto& f : fields) {
            Ptr<Node> node = all.Get(f.idx);
            auto lst = CreateObject<BootstrapListenerApp>();
            lst->Setup(9100);

            GatewayPublisherSet routes = devPub[f.idx];
            if (f.proto == "DNP3") {
                Ptr<Dnp3OutstationApp> app = g_dnp3Outstations[dnpIdx++];
                lst->RegisterArm([routes, app]() {
                    Simulator::Schedule(Seconds(BOOTSTRAP_ARM_DELAY),
                        [routes, app]() {
                            for (auto p : routes.pathPub) if (p) p->Arm();
                            app->Arm();
                        });
                });
            } else if (f.proto == "IEC104") {
                Ptr<Iec104ControlledApp> app = g_iecControlled[iecIdx++];
                lst->RegisterArm([routes, app]() {
                    Simulator::Schedule(Seconds(BOOTSTRAP_ARM_DELAY),
                        [routes, app]() {
                            for (auto p : routes.pathPub) if (p) p->Arm();
                            app->Arm();
                        });
                });
            } else {
                // Modbus / OPC-UA: only the publisher is gated.
                lst->RegisterArm([routes]() {
                    Simulator::Schedule(Seconds(BOOTSTRAP_ARM_DELAY),
                        [routes]() {
                            for (auto p : routes.pathPub) if (p) p->Arm();
                        });
                });
            }

            node->AddApplication(lst);
            lst->SetStartTime(Seconds(0.0));
            lst->SetStopTime(Seconds(g_simDuration));
            announce->AddTarget(Ipv4Address(nodeIp[f.idx].c_str()), 9100);
        }

        NS_LOG_INFO("[Bootstrap] announce at t=" << BOOTSTRAP_TIME << "s, "
                    << fields.size() << " devices; gated: 24 Station publishers "
                    << "+ DNP3/IEC104 spontaneous senders; arm delay="
                    << BOOTSTRAP_ARM_DELAY << "s");
    }

    // =================================================================
    //                       INCIDENT WINDOWS
    //   Scenario multipliers still model background load. These windows
    //   model physical/operational events: a field device reports a finite
    //   burst, the gateway/master receives it, and protocol ACK/confirm
    //   lets the device resolve instead of sending forever.
    // =================================================================
    auto scnT = [&](uint32_t scnIdx, double frac) {
        return BOOTSTRAP_TIME + scnIdx * g_scenarioDur + frac * g_scenarioDur;
    };
    Ptr<UniformRandomVariable> incidentRng = CreateObject<UniformRandomVariable>();
    // Toc do phat nen thuc te cua mot thiet bi tai thoi diem t, sau khi da ap
    // he so kich ban (va tran chu ky cua OPC-UA o high_load).
    auto liveBaseRate = [&](uint32_t idx, const std::string& proto, double t) {
        auto it = deviceCfg.find(idx);
        if (it == deviceCfg.end() || it->second.baseInt <= 0.0) return 0.0;
        uint32_t scnIdx = static_cast<uint32_t>(std::max(0.0,
            std::floor((t - BOOTSTRAP_TIME) / g_scenarioDur)));
        const char* names[3] = {"normal", "high_load", "emergency"};
        std::string scn = names[std::min(scnIdx, 2u)];
        double interval = it->second.baseInt * GetScenarioMulPair(proto, scn).first;
        if (proto == "OPC-UA" && scn == "high_load")
            interval = std::min(interval, 0.1);          // tran cua OPC-UA
        return interval > 0.0 ? 1.0 / interval : 0.0;
    };

    // Baseline report totals from the fixed incident schedule below, including
    // bounded Modbus alarm responses: [scenario][IMPORTANT, EMERGENCY].
    const double baseIncidentReports[3][2] = {
        {42.0, 14.0}, {62.0, 58.0}, {72.0, 117.0}};
    const double targetIncidentReports[3] = {
        static_cast<double>(qosShiftReportsNormal),
        static_cast<double>(qosShiftReportsHigh),
        static_cast<double>(qosShiftReportsEmergency)};
    double reportCarry[3][2] = {};
    auto randomizeIncident = [&](uint32_t idx, double plannedT,
                                 double& dur, double& rate,
                                 uint32_t& reports,
                                 const std::string& label,
                                 const std::string& proto) -> double {
        double scStart = ScenarioStart(plannedT);
        double scEnd = scStart + g_scenarioDur;
        double jitter = (incidentRng->GetValue() - 0.5) * 0.20 * g_scenarioDur;
        double t = plannedT + jitter;
        dur *= 0.75 + incidentRng->GetValue() * 0.50;
        const double rateVariability = 1.0 - g_serviceRateJitter
            + incidentRng->GetValue() * 2.0 * g_serviceRateJitter;
        // Service classes are contracts over observable flow behaviour.  A
        // TIME_CRITICAL burst is therefore deliberately sharper than an
        // OPERATIONAL burst relative to the same device's live baseline.
        // Exact application semantics are not read by the classifier.
        double live = liveBaseRate(idx, proto, t);
        if (live > 0.0) {
            const bool timeCritical = label == "TIME_CRITICAL";
            const double factor = timeCritical ? 12.0 : 2.25;
            const double scheduleScale = timeCritical ? 1.50 : 0.75;
            rate = std::min(INCIDENT_RATE_CAP,
                            std::max(rate * scheduleScale, live * factor));
        }
        // Vary physical event intensity independently of the truth class.
        rate = std::min(INCIDENT_RATE_CAP, rate * rateVariability);
        if (qosShiftWorkload) {
            const uint32_t scn = std::min(2u, static_cast<uint32_t>(std::max(
                0.0, std::floor((scStart - BOOTSTRAP_TIME) / g_scenarioDur))));
            const uint32_t cls = label == "TIME_CRITICAL" ? 1u : 0u;
            const double dominantShare = qosShiftFactor / (1.0 + qosShiftFactor);
            const double targetShare = scn == 1 ? 0.5
                : ((scn == 0 && cls == 0) || (scn == 2 && cls == 1))
                    ? dominantShare : 1.0 - dominantShare;
            const double multiplier = targetIncidentReports[scn] * targetShare
                                    / baseIncidentReports[scn][cls];
            const double scaled = reports * multiplier + reportCarry[scn][cls];
            reports = std::max(1u, static_cast<uint32_t>(std::floor(scaled)));
            reportCarry[scn][cls] = scaled - std::floor(scaled);
            if (proto != "Modbus")
                rate = std::min(INCIDENT_RATE_CAP, rate * multiplier);
        } else {
            int delta = static_cast<int>(incidentRng->GetValue() * 3.0) - 1;
            reports = static_cast<uint32_t>(std::max(1, (int)reports + delta));
        }
        // Give the generator enough time to emit its bounded report count.
        // Scaling reports and rate by the same factor preserves burst shape.
        dur = std::max(dur, 1.25 * reports / std::max(0.1, rate));
        dur = std::min(dur, std::max(1.0, 0.35 * g_scenarioDur));

        const double minStart = scStart + EffectiveWarmupDuration()
                              + TRANSITION_BUFFER;
        double maxStart = scEnd - std::max(dur, 1.0) - TRANSITION_BUFFER;
        if (maxStart < minStart) maxStart = minStart;
        t = std::min(std::max(t, minStart), maxStart);

        g_incidentWindows.push_back({idx, t, t + dur, label});
        return t;
    };
    auto winDur = [&](double frac, double floorSec) {
        return std::max(floorSec, g_scenarioDur * frac);
    };
    auto schedDnp = [&](uint32_t idx, double t, double dur,
                        double rate, uint32_t reports,
                        const std::string& label,
                        const std::string& semanticCategory) {
        auto it = dnpByNode.find(idx);
        if (it != dnpByNode.end()) {
            const std::string serviceClass = NormalizeServiceClass(label);
            t = randomizeIncident(idx, t, dur, rate, reports, serviceClass,
                                  "DNP3");
            Simulator::Schedule(Seconds(t),
                &Dnp3OutstationApp::TriggerIncident, it->second,
                dur, rate, reports, serviceClass, semanticCategory);
        }
    };
    auto schedIec = [&](uint32_t idx, double t, double dur,
                        double rate, uint32_t reports,
                        const std::string& label,
                        const std::string& semanticCategory) {
        auto it = iecByNode.find(idx);
        if (it != iecByNode.end()) {
            const std::string serviceClass = NormalizeServiceClass(label);
            t = randomizeIncident(idx, t, dur, rate, reports, serviceClass,
                                  "IEC104");
            Simulator::Schedule(Seconds(t),
                &Iec104ControlledApp::TriggerIncident, it->second,
                dur, rate, reports, serviceClass, semanticCategory);
        }
    };
    auto schedOpc = [&](uint32_t idx, double t, double dur,
                        double rate, uint32_t reports,
                        const std::string& label,
                        const std::string& semanticCategory) {
        auto it = opcByNode.find(idx);
        if (it != opcByNode.end()) {
            const std::string serviceClass = NormalizeServiceClass(label);
            t = randomizeIncident(idx, t, dur, rate, reports, serviceClass,
                                  "OPC-UA");
            Simulator::Schedule(Seconds(t),
                &OpcUaServerApp::TriggerIncident, it->second,
                dur, rate, reports, serviceClass, semanticCategory);
        }
    };
    auto schedModbus = [&](uint32_t idx, double t, double dur,
                           uint32_t reports, const std::string& label,
                           const std::string& semanticCategory) {
        auto it = modbusByNode.find(idx);
        if (it != modbusByNode.end() && g_modbusServiceEvents) {
            double rate = std::max(0.1, liveBaseRate(idx, "Modbus", t));
            // Modbus models monitoring plus operational status/alarm checks,
            // not protection-grade unsolicited trips. Both labels scheduled
            // by old experiments now correspond to this OP workflow.
            const std::string serviceClass = "OPERATIONAL";
            t = randomizeIncident(idx, t, dur, rate, reports, serviceClass,
                                  "Modbus");
            if (g_modbusOperationalRefreshMs > 0.0 && g_modbusServiceWorkflow) {
                // Reserve enough exchanges to observe physical settling and
                // two stable status confirmations. Duration remains bounded;
                // read count, register map and response size do not change.
                const double interval = std::max(0.02, std::min(
                    g_modbusOperationalRefreshMs / 1000.0,
                    0.25 / std::max(0.1, liveBaseRate(idx, "Modbus", t))));
                reports = std::max(reports, static_cast<uint32_t>(
                    std::ceil(dur / interval)) + 2u);
            }
            const double pollingFactor = 0.25 + incidentRng->GetValue() * 0.40;
            const auto field = std::find_if(fields.begin(), fields.end(),
                [idx](const FieldDesc& f) { return f.idx == idx; });
            if (field != fields.end()) {
                const size_t position = std::distance(fields.begin(), field);
                size_t modbusPosition = 0;
                for (size_t n = 0; n < position; ++n)
                    if (fields[n].proto == "Modbus") ++modbusPosition;
                Simulator::Schedule(Seconds(t),
                    &ModbusMasterApp::TriggerOperationalPolling,
                    g_modbusMasters.at(modbusPosition), dur, pollingFactor,
                    reports);
            }
            Simulator::Schedule(Seconds(t),
                &ModbusSlaveApp::TriggerIncident, it->second, dur, serviceClass,
                reports, semanticCategory);
        }
    };

    // Every scenario contains both urgency classes. This prevents the model
    // from learning "scenario == emergency" instead of message urgency.
    schedModbus(12, scnT(0, 0.40), winDur(0.08, 1.0), 6, "IMPORTANT", "ALARM");
    schedModbus(14, scnT(0, 0.74), winDur(0.06, 1.0), 4, "EMERGENCY", "CONTROL");
    schedIec(5,  scnT(0, 0.28), winDur(0.04, 1.0), 2.0, 6, "IMPORTANT", "STATUS");
    schedDnp(7,  scnT(0, 0.48), winDur(0.05, 1.0), 3.0, 6, "IMPORTANT", "STATUS");
    schedDnp(21, scnT(0, 0.58), winDur(0.05, 1.0), 2.5, 6, "IMPORTANT", "STATUS");
    schedOpc(16, scnT(0, 0.36), winDur(0.04, 1.0), 2.5, 6, "IMPORTANT", "ALARM");
    schedOpc(15, scnT(0, 0.66), winDur(0.05, 1.0), 2.0, 6, "IMPORTANT", "STATUS");
    schedOpc(27, scnT(0, 0.76), winDur(0.04, 1.0), 3.0, 6, "EMERGENCY", "CONTROL");
    schedDnp(23, scnT(0, 0.72), winDur(0.05, 1.0), 3.0, 6, "IMPORTANT", "STATUS");
    schedIec(19, scnT(0, 0.82), winDur(0.04, 1.0), 3.0, 4, "EMERGENCY", "PROTECTION");

    schedDnp(20, scnT(1, 0.16), winDur(0.08, 1.0), 4.0, 10, "IMPORTANT", "STATUS");
    schedDnp(21, scnT(1, 0.30), winDur(0.08, 1.0), 5.0, 10, "EMERGENCY", "PROTECTION");
    schedOpc(16, scnT(1, 0.32), winDur(0.07, 1.0), 4.5, 8, "EMERGENCY", "ALARM");
    schedDnp(8,  scnT(1, 0.38), winDur(0.07, 1.0), 3.5, 8, "IMPORTANT", "STATUS");
    schedIec(18, scnT(1, 0.43), winDur(0.08, 1.0), 4.0, 10, "IMPORTANT", "STATUS");
    schedOpc(17, scnT(1, 0.56), winDur(0.08, 1.0), 4.0, 10, "IMPORTANT", "ALARM");
    schedOpc(28, scnT(1, 0.70), winDur(0.07, 1.0), 4.0, 8, "IMPORTANT", "ALARM");
    schedOpc(27, scnT(1, 0.80), winDur(0.07, 1.0), 4.5, 8, "EMERGENCY", "CONTROL");
    schedDnp(9,  scnT(1, 0.62), winDur(0.07, 1.0), 3.5, 8, "IMPORTANT", "STATUS");
    schedIec(5,  scnT(1, 0.68), winDur(0.07, 1.0), 5.0, 8, "EMERGENCY", "CONTROL");
    schedDnp(7,  scnT(1, 0.78), winDur(0.07, 1.0), 5.0, 8, "EMERGENCY", "CONTROL");
    schedOpc(15, scnT(1, 0.88), winDur(0.07, 1.0), 5.0, 8, "EMERGENCY", "CONTROL");
    schedModbus(12, scnT(1, 0.36), winDur(0.10, 1.0), 8, "EMERGENCY", "CONTROL");
    schedModbus(14, scnT(1, 0.72), winDur(0.08, 1.0), 8, "IMPORTANT", "ALARM");

    schedDnp(23, scnT(2, 0.10), winDur(0.12, 1.0), 7.0, 18, "EMERGENCY", "PROTECTION");
    schedDnp(8,  scnT(2, 0.21), winDur(0.12, 1.0), 7.0, 18, "EMERGENCY", "PROTECTION");
    schedDnp(9,  scnT(2, 0.32), winDur(0.10, 1.0), 6.0, 14, "EMERGENCY", "PROTECTION");
    schedIec(25, scnT(2, 0.43), winDur(0.10, 1.0), 6.0, 14, "EMERGENCY", "PROTECTION");
    schedIec(19, scnT(2, 0.54), winDur(0.12, 1.0), 6.0, 16, "EMERGENCY", "PROTECTION");
    schedIec(26, scnT(2, 0.64), winDur(0.10, 1.0), 5.0, 12, "IMPORTANT", "STATUS");
    schedDnp(21, scnT(2, 0.68), winDur(0.08, 1.0), 4.0, 10, "IMPORTANT", "STATUS");
    schedOpc(16, scnT(2, 0.73), winDur(0.10, 1.0), 5.0, 12, "IMPORTANT", "ALARM");
    schedOpc(28, scnT(2, 0.82), winDur(0.12, 1.0), 6.0, 15, "EMERGENCY", "ALARM");
    schedOpc(27, scnT(2, 0.34), winDur(0.08, 1.0), 4.5, 10, "IMPORTANT", "ALARM");
    schedOpc(17, scnT(2, 0.58), winDur(0.10, 1.0), 5.5, 12, "EMERGENCY", "CONTROL");
    schedOpc(15, scnT(2, 0.92), winDur(0.06, 1.0), 4.0, 8, "IMPORTANT", "STATUS");
    schedDnp(7,  scnT(2, 0.90), winDur(0.06, 1.0), 5.0, 10, "IMPORTANT", "STATUS");
    schedModbus(12, scnT(2, 0.28), winDur(0.12, 1.0), 10, "EMERGENCY", "CONTROL");
    schedModbus(14, scnT(2, 0.78), winDur(0.10, 1.0), 10, "IMPORTANT", "ALARM");

    // Monitoring may also temporarily poll faster (e.g. diagnostic scans).
    // No incident label is created. Keep these optional episodes clear of
    // operational windows and their one-second truth-history tails, including
    // on alarm-register devices. The model never receives this schedule.
    if (g_modbusMonitoringBursts) {
        size_t modbusPosition = 0;
        for (const auto& field : fields) {
            if (field.proto != "Modbus") continue;
            for (uint32_t phase = 0; phase < 3; ++phase) {
                const double start = BOOTSTRAP_TIME + phase * g_scenarioDur;
                const double duration = std::min(2.0, 0.10 * g_scenarioDur);
                const double earliest = start + EffectiveWarmupDuration() + 1.5;
                const double latest = start + g_scenarioDur - duration - 1.5;
                for (double t = earliest; t <= latest; t += 0.5) {
                    bool overlaps = false;
                    for (const auto& window : g_incidentWindows) {
                        if (window.deviceId == field.idx
                            && t < window.end + 1.25
                            && t + duration + 1.25 > window.start) {
                            overlaps = true;
                            break;
                        }
                    }
                    if (overlaps) continue;
                    const double factor = 0.45 + incidentRng->GetValue() * 0.40;
                    Simulator::Schedule(Seconds(t),
                        &ModbusMasterApp::TriggerOperationalPolling,
                        g_modbusMasters.at(modbusPosition), duration, factor, 0u);
                    break;
                }
            }
            ++modbusPosition;
        }
    }

    // Create the optional DDoS overlay only after all SCADA applications and
    // incident randomisation have been configured.  This preserves identical
    // RNG stream allocation between ddos=0 and ddos=1, which is required for
    // a fair paired comparison with the same --run value.
    if (g_ddosEnabled) {
        constexpr uint16_t ddosPort = 9400;
        PacketSinkHelper sink("ns3::UdpSocketFactory",
            InetSocketAddress(Ipv4Address::GetAny(), ddosPort));
        ApplicationContainer sinkApp = sink.Install(master);
        sinkApp.Start(Seconds(0.0));
        sinkApp.Stop(Seconds(g_simDuration + 1.0));

        std::vector<size_t> candidates;
        for (size_t index = 0; index < fields.size(); ++index) {
            bool selected = g_ddosPlacement == "distributed";
            if (!selected && g_ddosPlacement.rfind("station", 0) == 0) {
                const uint32_t station = static_cast<uint32_t>(
                    g_ddosPlacement.back() - '0');
                selected = fields[index].gw == station;
            }
            if (selected) candidates.push_back(index);
        }
        const uint32_t effectiveSources = std::min<uint32_t>(
            g_ddosSources, candidates.size());
        const uint64_t perSourceBps = static_cast<uint64_t>(
            g_ddosRateMbps * 1e6 / effectiveSources);
        for (uint32_t source = 0; source < effectiveSources; ++source) {
            const size_t candidate = source * candidates.size()
                                   / effectiveSources;
            const uint32_t nodeIndex = fields.at(candidates.at(candidate)).idx;
            OnOffHelper flood("ns3::UdpSocketFactory", InetSocketAddress(
                Ipv4Address(nodeIp[0].c_str()), ddosPort));
            if (g_ddosPattern == "burst" || g_ddosPattern == "random_burst") {
                const uint64_t peakBps = static_cast<uint64_t>(
                    perSourceBps * g_ddosBurstFactor);
                const double onSeconds = g_ddosBurstMs / 1000.0;
                const double offSeconds = onSeconds
                                        * (g_ddosBurstFactor - 1.0);
                std::ostringstream onTime, offTime;
                const bool randomized = g_ddosPattern == "random_burst";
                onTime << (randomized ? "ns3::ExponentialRandomVariable[Mean="
                                      : "ns3::ConstantRandomVariable[Constant=")
                       << onSeconds << ']';
                offTime << (randomized && offSeconds > 0.0
                    ? "ns3::ExponentialRandomVariable[Mean="
                    : "ns3::ConstantRandomVariable[Constant=")
                        << offSeconds << ']';
                flood.SetAttribute("OnTime", StringValue(onTime.str()));
                flood.SetAttribute("OffTime", StringValue(offTime.str()));
                flood.SetAttribute("DataRate", DataRateValue(DataRate(peakBps)));
                flood.SetAttribute("PacketSize", UintegerValue(1200));
            } else {
                flood.SetConstantRate(DataRate(perSourceBps), 1200);
            }
            // Spoofed EF (DSCP 46). These remain ATTACK packets, not OT TC
            // ground-truth samples; the UDP source bypasses the OT classifier.
            flood.SetAttribute("Tos", UintegerValue(184));
            ApplicationContainer traffic = flood.Install(all.Get(nodeIndex));
            traffic.Start(Seconds(g_ddosStart));
            traffic.Stop(Seconds(g_ddosStart + g_ddosDuration));
        }
        Simulator::Schedule(Seconds(g_ddosStart), &SetDdosTruth, true);
        Simulator::Schedule(Seconds(g_ddosStart + g_ddosDuration),
                            &SetDdosTruth, false);
        std::cout << "[ddos-generator] configured " << effectiveSources
                  << " sources, aggregate=" << g_ddosRateMbps
                  << " Mbps mean, pattern=" << g_ddosPattern
                  << ", placement=" << g_ddosPlacement
                  << ", interval=[" << g_ddosStart << ','
                  << g_ddosStart + g_ddosDuration << ")s, DSCP=EF (46)\n";
    }

    // =================================================================
    //                          MOBILITY  +  NETANIM
    // =================================================================
    MobilityHelper mob;
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    // Layout: triangle topology
    //   Master at top-center, Broker right of Master
    //   S1 (Production)   top-center under Master
    //   S0 (Power)        bottom-left
    //   S2 (Distribution) bottom-right
    pos->Add(Vector(50, 5,  0));    // [0] Master
    pos->Add(Vector(80, 14, 0));    // [1] Broker
    pos->Add(Vector(18, 38, 0));    // [2] S0
    pos->Add(Vector(50, 30, 0));    // [3] S1
    pos->Add(Vector(82, 38, 0));    // [4] S2

    // Field nodes arranged in fans under their parent Station
    // S0 (idx 5..12) — 8 nodes, fan from (5..30, 60..80)
    double xs0[8] = { 4, 10, 16, 22,  4, 10, 16, 22};
    double ys0[8] = {55, 55, 55, 55, 75, 75, 75, 75};
    for (int i = 0; i < 8; ++i) pos->Add(Vector(xs0[i], ys0[i], 0));
    // S1 (idx 13..20) — 8 nodes under center
    double xs1[8] = {35, 41, 47, 53, 35, 41, 47, 53};
    double ys1[8] = {43, 43, 43, 43, 63, 63, 63, 63};
    for (int i = 0; i < 8; ++i) pos->Add(Vector(xs1[i], ys1[i], 0));
    // S2 (idx 21..28) — 8 nodes bottom-right
    double xs2[8] = {68, 74, 80, 86, 68, 74, 80, 86};
    double ys2[8] = {55, 55, 55, 55, 75, 75, 75, 75};
    for (int i = 0; i < 8; ++i) pos->Add(Vector(xs2[i], ys2[i], 0));
    if (ripAttacker) {
        const double attackerX[3] = {30.0, 50.0, 70.0};
        pos->Add(Vector(attackerX[g_ripPoisonStation], 18, 0));
    }

    mob.SetPositionAllocator(pos);
    mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mob.Install(all);

    if (g_animDashboard) {
        Ptr<ListPositionAllocator> dashboardPos =
            CreateObject<ListPositionAllocator>();
        // Keep the first row fixed and use a compact 5-unit row spacing.
        const double dashboardY[6] = {4.0, 9.0, 14.0, 19.0, 24.0, 29.0};
        for (double y : dashboardY) dashboardPos->Add(Vector(1.5, y, 0));

        MobilityHelper dashboardMobility;
        dashboardMobility.SetPositionAllocator(dashboardPos);
        dashboardMobility.SetMobilityModel(
            "ns3::ConstantPositionMobilityModel");
        dashboardMobility.Install(dashboardNodes);

        for (uint32_t i = 0; i < dashboardNodes.GetN(); ++i) {
            g_animDashboardNodeIds.at(i) = dashboardNodes.Get(i)->GetId();
        }
    }

    if (enableAnim) {
        g_anim = new AnimationInterface(g_outDir + "scada_netanim.xml");
        if (maxPkts > 0) g_anim->SetMaxPktsPerTraceFile(maxPkts);

        g_anim->UpdateNodeDescription(master, "Master");
        g_anim->UpdateNodeColor(master, 255, 0, 0);            // red

        if (g_animDashboard) {
            std::ostringstream initialQos;
            initialQos << "QOS RATE: TC=" << std::fixed
                       << std::setprecision(1)
                       << g_qosCtrl[2].rateBps / 1000.0 << " | OP="
                       << g_qosCtrl[1].rateBps / 1000.0 << " kbps";
            const std::array<std::string, 6> dashboardLabels = {
                "SECURITY: NO",
                "PHASE: BOOTSTRAP [0-1 s]",
                "ML CLASS: TC=0 | OP=0 | MON=0",
                initialQos.str(),
                "ROUTING: HOME | SWITCH=0",
                "NET: Delay=0.000 ms | Loss=0.000 %"
            };
            for (uint32_t i = 0; i < dashboardNodes.GetN(); ++i) {
                Ptr<Node> row = dashboardNodes.Get(i);
                g_anim->UpdateNodeDescription(row, dashboardLabels.at(i));
                g_anim->UpdateNodeColor(row, 255, 255, 255);
                g_anim->UpdateNodeSize(row->GetId(), 0.1, 0.1);
            }

            g_animThroughputCounter = g_anim->AddNodeCounter(
                "SCADA Throughput (Mbps)",
                AnimationInterface::DOUBLE_COUNTER);
            g_animDelayCounter = g_anim->AddNodeCounter(
                "SCADA Avg Delay (ms)",
                AnimationInterface::DOUBLE_COUNTER);
            g_animLossCounter = g_anim->AddNodeCounter(
                "SCADA Packet Loss (%)",
                AnimationInterface::DOUBLE_COUNTER);
            g_animFlowCounter = g_anim->AddNodeCounter(
                "SCADA Active Flow Count",
                AnimationInterface::UINT32_COUNTER);
            g_anim->UpdateNodeCounter(g_animThroughputCounter, 0, 0.0);
            g_anim->UpdateNodeCounter(g_animDelayCounter, 0, 0.0);
            g_anim->UpdateNodeCounter(g_animLossCounter, 0, 0.0);
            g_anim->UpdateNodeCounter(g_animFlowCounter, 0, 0.0);
        }

        g_anim->UpdateNodeDescription(broker, "Broker");
        g_anim->UpdateNodeColor(broker, 255, 130, 0);          // dark orange

        if (ripAttacker) {
            g_anim->UpdateNodeDescription(ripAttacker,
                                           "RIP-Attacker [IDLE]");
            g_anim->UpdateNodeColor(ripAttacker, 125, 0, 150);
            g_anim->UpdateNodeSize(ripAttacker->GetId(), 2.0, 2.0);
        }

        for (int i = 0; i < 3; ++i) {
            std::ostringstream lbl;
            lbl << "S" << i;
            g_anim->UpdateNodeDescription(gw[i], lbl.str());
            g_anim->UpdateNodeColor(gw[i], 0, 150, 255);       // blue
        }

        auto classColor = [](const std::string& cls,
                             uint8_t& r, uint8_t& g, uint8_t& b) {
            if (cls == "EMERGENCY")      { r=255; g= 60; b= 60; }
            else if (cls == "IMPORTANT") { r=255; g=170; b= 40; }
            else if (cls == "NORMAL")    { r= 80; g=200; b=120; }
            else                         { r=180; g=180; b=180; }
        };

        for (auto& f : fields) {
            g_anim->UpdateNodeDescription(all.Get(f.idx), f.animLabel);
            uint8_t r, g, b;
            classColor(f.trafficClass, r, g, b);
            g_anim->UpdateNodeColor(all.Get(f.idx), r, g, b);
        }
    }

    // =================================================================
    //                          FLOW MONITOR
    // =================================================================
    // Install only after staticHelper/RIP setup: existing lookup and protocol
    // behavior are delegated, not replaced by a new routing policy.
    if (g_qosMode=="private" && (g_qosIngressGuard || g_qosSourceLimit)) {
        for (uint32_t station=0; station<3; ++station) {
            Ptr<Ipv4> ip=gw[station]->GetObject<Ipv4>();
            auto boundary=CreateObject<StationBoundaryRouting>();
            boundary->Setup(ip->GetRoutingProtocol(),&g_boundaryPolicies[station],
                            g_qosIngressGuard,g_qosSourceLimit);
            ip->SetRoutingProtocol(boundary);
        }
    }
    g_boundaryCsv.open(g_outDir+"station_boundary.csv");
    g_boundaryCsv << "t,station,scenario,guard_enabled,limit_enabled,raw_packets,raw_priority_seen,raw_admitted,raw_dropped,spoof_dropped,remarked,raw_bytes,raw_admitted_bytes,priority_offered,priority_demotions\n";
    Simulator::Schedule(Seconds(0.5),&SampleStationBoundary);
    FlowMonitorHelper fmh;
    g_monitor = fmh.InstallAll();
    g_classifier = DynamicCast<Ipv4FlowClassifier>(fmh.GetClassifier());

    // =================================================================
    //                          SCENARIO SCHEDULE
    //   Scenarios shifted by BOOTSTRAP_TIME so each scenario gets a
    //   full g_scenarioDur of data after the field nodes are armed.
    // =================================================================
    Simulator::Schedule(Seconds(BOOTSTRAP_TIME),
        &ConfigureScenario, std::string("normal"));
    Simulator::Schedule(Seconds(BOOTSTRAP_TIME + g_scenarioDur),
        &ConfigureScenario, std::string("high_load"));
    Simulator::Schedule(Seconds(BOOTSTRAP_TIME + 2 * g_scenarioDur),
        &ConfigureScenario, std::string("emergency"));

    Simulator::Schedule(Seconds(WINDOW_SIZE), &OnWindow);
    Simulator::Schedule(MilliSeconds(
        static_cast<uint64_t>(g_ddosWindowMs)), &SampleDdosDetector);

    Simulator::Stop(Seconds(g_simDuration + 0.5));
    Simulator::Run();

    // =================================================================
    //                          EXPORT
    // =================================================================
    g_monitor->CheckForLostPackets();
    for (auto& agent : g_gatewayAgents) agent.Finish();
    if (rlMode == RlMode::TRAIN) SaveRlQTable(g_rlQTablePath);
    if (enableFlowXml)
        g_monitor->SerializeToXmlFile(g_outDir + "scada_flows.xml", true, true);
    if (enableFeatureCsv) ExportCsv(g_outDir + "scada_features.csv");
    ClosePacketCsv();
    CloseRuntimeMlCsv();
    CloseRlCsvs();
    if (g_ddosStateCsv.is_open()) g_ddosStateCsv.close();
    if (g_ripPoisonCsv.is_open()) g_ripPoisonCsv.close();
    if (g_ripRouteCsv.is_open()) g_ripRouteCsv.close();

    // Disconnect AnimationInterface trace hooks and flush the closing XML tag
    // while the simulator objects it references are still alive.
    if (g_anim) {
        delete g_anim;
        g_anim = nullptr;
    }
    Simulator::Destroy();
    NS_LOG_INFO("DONE.");
    return 0;
}
