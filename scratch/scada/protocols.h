// =====================================================================
//  protocols.h  —  SCADA Multi-Protocol App declarations
//  =====================================================================
//  Companion header for protocols.cc.  Declares all Application classes
//  used by the SCADA simulation, the shared port constants, and the
//  externally-visible scenario/state interface implemented in scada.cc.
// =====================================================================
#pragma once

#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/traced-callback.h"
#include "ns3/random-variable-stream.h"
#include "ns3/data-rate.h"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/tag.h"
#include "ns3/header.h"

#include <array>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <ostream>

namespace ns3 {

// Hash functor enabling Ptr<T> as key in unordered_map / unordered_set.
struct PtrHash {
    template<typename T>
    std::size_t operator()(const Ptr<T>& p) const noexcept {
        return std::hash<const T*>()(PeekPointer(p));
    }
};

// ─────────────────────────── PORT CONSTANTS ──────────────────────────
// Shared between scada.cc (flow label map) and protocols.cc (socket bind).
inline constexpr uint16_t PORT_MODBUS    = 502;
inline constexpr uint16_t PORT_DNP3      = 20000;
inline constexpr uint16_t PORT_IEC104    = 2404;
inline constexpr uint16_t PORT_OPCUA     = 4840;
inline constexpr uint16_t PORT_MQTT      = 1883;
inline constexpr uint16_t PORT_MQTT_FWD  = 1884;  // Broker → Master subscription
// (Station heartbeat/status removed — liveness now via MQTT keep-alive + LWT)

// ─────────────────────────── SHARED STATE ────────────────────────────
// Defined in scada.cc; read by App classes when stamping DSCP/TOS.
extern std::string g_scenario;
extern std::string g_qosMode;

// Defined in scada.cc.  Maps (protocol label, scenario) → TOS byte.
uint8_t LabelToTos(const std::string& label, const std::string& scenario);

// Simulator-only ground truth. PacketTag metadata does not add wire bytes and
// is deliberately excluded from the DT/RF feature vector.
class ScadaMessageTag : public Tag {
public:
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(TagBuffer buffer) const override;
    void Deserialize(TagBuffer buffer) override;
    void Print(std::ostream& os) const override;

    void SetUrgency(uint8_t urgency);
    void SetKind(uint8_t kind);
    void SetSemanticCategory(uint8_t category);
    uint8_t GetUrgency() const;
    uint8_t GetKind() const;
    uint8_t GetSemanticCategory() const;

private:
    uint8_t m_urgency = 0;  // 0=NORMAL, 1=IMPORTANT, 2=EMERGENCY
    uint8_t m_kind = 0;     // 0=PROTOCOL, 1=TELEMETRY, 2=EVENT
    // Observable protocol meaning, not a QoS label:
    // 0=NONE, 1=STATUS, 2=ALARM, 3=CONTROL, 4=PROTECTION.
    uint8_t m_semanticCategory = 0;
};

void SetScadaMessageMetadata(Ptr<Packet> packet,
                             const std::string& urgency,
                             const std::string& kind,
                             const std::string& semanticCategory = "NONE");
std::string GetScadaUrgency(Ptr<const Packet> packet);
std::string GetScadaServiceClass(Ptr<const Packet> packet);
std::string GetScadaMessageKind(Ptr<const Packet> packet);
uint8_t GetScadaSemanticCategory(Ptr<const Packet> packet);

// Wire-visible framing used on the translated MQTT stream. TCP does not
// preserve application message boundaries, so the broker and master parse
// this fixed-size header before consuming each payload.
class ScadaMqttHeader : public Header {
public:
    static constexpr uint32_t MAGIC = 0x53434144; // "SCAD"

    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    bool IsValid() const;
    void SetPayloadLength(uint32_t value);
    void SetMessageId(uint64_t value);
    void SetSendTimeNs(uint64_t value);
    void SetDeviceId(uint32_t value);
    void SetSourceGateway(uint8_t value);
    void SetChosenPath(uint8_t value);
    void SetTrafficClass(uint8_t value);
    void SetProtocolId(uint8_t value);
    uint32_t GetPayloadLength() const;
    uint64_t GetMessageId() const;
    uint64_t GetSendTimeNs() const;
    uint32_t GetDeviceId() const;
    uint8_t GetSourceGateway() const;
    uint8_t GetChosenPath() const;
    uint8_t GetTrafficClass() const;
    uint8_t GetProtocolId() const;

private:
    uint32_t m_magic = MAGIC;
    uint32_t m_payloadLength = 0;
    uint64_t m_messageId = 0;
    uint64_t m_sendTimeNs = 0;
    uint32_t m_deviceId = 0;
    uint8_t m_sourceGateway = 0;
    uint8_t m_chosenPath = 0;
    uint8_t m_trafficClass = 0;
    uint8_t m_protocolId = 0;
};

struct ScadaDeliveryInfo {
    uint64_t messageId = 0;
    uint64_t sendTimeNs = 0;
    uint32_t deviceId = 0;
    uint32_t payloadLength = 0;
    uint8_t sourceGateway = 0;
    uint8_t chosenPath = 0;
    uint8_t trafficClass = 0;
    uint8_t protocolId = 0;
    double delayMs = 0.0;
};

// =====================================================================
//  ModbusSlaveApp  —  Modbus TCP server on RTU/PLC (port 502)
// =====================================================================
class ModbusSlaveApp : public Application {
public:
    static TypeId GetTypeId();
    ModbusSlaveApp();
    ~ModbusSlaveApp() override;

    void Setup(std::string selfIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);
    void SetBaseline(uint32_t respSz);             // Phase 2: per-instance
    void TriggerIncident(double duration, const std::string& label,
                         uint32_t responses,
                         const std::string& semanticCategory);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnAccept(Ptr<Socket> ns, const Address&);
    void OnRecv(Ptr<Socket> sock);
    void SendResp(Ptr<Socket> sock, uint32_t transactionId);
    void OnClose(Ptr<Socket> sock);
    void EndIncident();

    Ptr<Socket>                            m_listenSock;
    std::unordered_map<Ptr<Socket>, std::vector<uint8_t>, PtrHash> m_rxBuf;
    uint32_t                                 m_baseRespSz;       // Phase 2 baseline
    uint32_t                                 m_respSz;
    std::string                              m_selfIp;
    std::string                              m_incidentLabel;
    std::string                              m_incidentSemanticCategory;
    uint32_t                                 m_incidentResponsesLeft;
    EventId                                  m_incidentEndEv;
};

// =====================================================================
//  ModbusMasterApp  —  Modbus TCP client on master node
// =====================================================================
class ModbusMasterApp : public Application {
public:
    static TypeId GetTypeId();
    ModbusMasterApp();
    ~ModbusMasterApp() override;

    void Setup(Address peer, std::string masterIp);
    void SetScenario(const std::string& sc);
    void SetBaseline(double pollInt);             // Phase 2: per-instance
    void RestampTos(uint8_t tos);                 // Phase B: ML override apply

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnConn(Ptr<Socket>);
    void OnFail(Ptr<Socket>);
    void Poll();
    void OnRecv(Ptr<Socket> sock);
    void OnTimeout();                         // A2: response timeout retry

    Ptr<Socket>  m_sock;
    Address      m_peer;
    std::string  m_masterIp;
    double       m_baseInt;                   // Phase 2: per-instance baseline
    double       m_pollInt;                   // = baseInt * scenarioMul
    EventId      m_pollEv;
    EventId      m_timeoutEv;                 // A2
    std::vector<uint8_t> m_rxBytes;           // MBAP-like framed response stream
    uint32_t     m_nextTransactionId;
    uint32_t     m_outstandingTransactionId;
    uint32_t     m_retryCount;
    bool         m_waitingResponse;
    bool         m_conn;
    bool         m_run;
};

// =====================================================================
//  Dnp3OutstationApp  —  DNP3 TCP server on IED/RTU (port 20000)
// =====================================================================
class Dnp3OutstationApp : public Application {
public:
    static TypeId GetTypeId();
    Dnp3OutstationApp();
    ~Dnp3OutstationApp() override;

    void Setup(std::string selfIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);
    void Arm();                              // Bootstrap: enable unsolicited
    void SetBaseline(double baseRate, uint32_t basePay, double burstProb);
    void SetUnsolicitedEnabled(bool enabled);
    void TriggerIncident(double duration, double rate, uint32_t reports,
                         std::string urgency, std::string semanticCategory);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnAccept(Ptr<Socket> ns, const Address&);
    void OnRecv(Ptr<Socket> sock);
    void GenerateEvent();
    void GenerateBurst();                     // Phase 2: emit 3-8 events
    void ScheduleNextEvent();
    void SendUnsolicited();
    void EndIncident();
    void SendFrame(uint8_t type, uint32_t payloadLen,
                   const std::string& urgency = "NORMAL",
                   const std::string& kind = "PROTOCOL",
                   const std::string& semanticCategory = "NONE");

    Ptr<Socket>   m_listenSock;
    Ptr<Socket>   m_sessSock;
    std::string   m_selfIp;
    std::vector<uint8_t> m_rxBytes;            // length-prefixed frame reassembly buffer
    uint32_t      m_evtBuffer;
    bool          m_pendingConfirm;
    bool          m_armed;                    // Bootstrap gate (unsolicited)
    double        m_baseRate;                 // Phase 2 baseline event rate
    uint32_t      m_basePay;                  // Phase 2 baseline unsol size
    double        m_burstProb;                // Phase 2 per-instance burst %
    double        m_evtRate;                  // = baseRate * scenMul (events/s)
    uint32_t      m_unsolSz;                  // = basePay * scenMul payload
    EventId       m_evtEv;
    EventId       m_incidentEndEv;
    Ptr<ExponentialRandomVariable> m_rng;
    Ptr<UniformRandomVariable>     m_rngU;    // burst probability sampler
    bool          m_unsolicitedEnabled;
    bool          m_incidentActive;
    uint32_t      m_incidentReportsLeft;
    double        m_incidentRate;
    std::string   m_incidentUrgency;
    std::string   m_incidentSemanticCategory;
};

// =====================================================================
//  Dnp3MasterApp  —  DNP3 TCP client on master node
// =====================================================================
class Dnp3MasterApp : public Application {
public:
    static TypeId GetTypeId();
    Dnp3MasterApp();
    ~Dnp3MasterApp() override;

    void Setup(Address peer, std::string masterIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);
    void SetPollingEnabled(bool enabled);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnConn(Ptr<Socket>);
    void OnFail(Ptr<Socket>);
    void Poll();
    void OnRecv(Ptr<Socket> sock);
    void OnTimeout();                         // A3: poll-response timeout
    void SendFrame(uint8_t type, uint32_t payloadLen);  // length-prefixed framing

    Ptr<Socket>  m_sock;
    Address      m_peer;
    std::string  m_masterIp;
    double       m_pollInt;
    bool         m_pollEnabled;
    std::vector<uint8_t> m_rxBytes;           // length-prefixed frame reassembly buffer
    bool         m_waitingPollResp;           // tracks an outstanding integrity poll (timeout logic)
    EventId      m_pollEv;
    EventId      m_timeoutEv;                 // A3
    bool         m_conn;
    bool         m_run;
};

// =====================================================================
//  Iec104ControlledApp  —  IEC-104 TCP server on RTU (port 2404)
// =====================================================================
class Iec104ControlledApp : public Application {
    enum State { STOPPED, STARTED };
public:
    static TypeId GetTypeId();
    Iec104ControlledApp();
    ~Iec104ControlledApp() override;

    void Setup(std::string selfIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);
    void Arm();                              // Bootstrap: enable spontaneous
    void SetBaseline(double baseInt);        // Phase 2: per-instance
    void SetPeriodicEnabled(bool enabled);
    void SetEventModel(bool enabled, double baseRate);
    void TriggerIncident(double duration, double rate, uint32_t reports,
                         std::string urgency, std::string semanticCategory);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnAccept(Ptr<Socket> ns, const Address&);
    void OnRecv(Ptr<Socket> sock);
    void SendIFrame();
    void ScheduleNextEvent();
    void SendEventFrame();
    void ScheduleIncidentFrame();
    void SendIncidentFrame();
    void EndIncident();
    void SendFrame(uint8_t type, uint32_t payloadLen,
                   const std::string& urgency = "NORMAL",
                   const std::string& kind = "PROTOCOL",
                   const std::string& semanticCategory = "NONE");
    void SendGiResponse();                    // General Interrogation response burst
    void SendTestfr();
    void NoteAck();                           // peer acknowledged our I-frames
    void NoteIFrameReceived();                // received an I-frame (w / t2 acking)
    void ArmT1();                             // (re)arm t1 while I-frames outstanding
    void RearmT3();                           // reset idle test-frame timer
    void OnT1Timeout();                       // t1: unacked I-frame -> close
    void OnT2Timeout();                       // t2: ack the remainder

    Ptr<Socket>   m_listen;
    Ptr<Socket>   m_sess;
    State         m_state;
    std::string   m_selfIp;
    std::vector<uint8_t> m_rxBytes;           // length-prefixed frame reassembly buffer
    uint32_t      m_ssn;                       // send sequence counter
    uint32_t      m_rsn;                       // receive sequence counter
    uint32_t      m_acked;                     // highest own SSN acknowledged by peer (k flow control)
    uint32_t      m_rxSinceAck;                // received I-frames since last S-frame (w)
    bool          m_armed;                    // Bootstrap gate (spontaneous)
    bool          m_periodicEnabled;
    bool          m_eventEnabled;
    double        m_baseInt;                  // Phase 2 baseline (s)
    double        m_iframeInt;                // = baseInt * scenarioMul
    double        m_baseEventRate;            // spontaneous breaker/status events/s
    double        m_eventRate;
    EventId       m_iEv;
    EventId       m_eventEv;
    EventId       m_incidentEv;
    EventId       m_incidentEndEv;
    EventId       m_t1Ev;
    EventId       m_t2Ev;
    EventId       m_t3Ev;
    Ptr<ExponentialRandomVariable> m_eventRng;
    bool          m_incidentActive;
    bool          m_incidentWaitingAck;
    uint32_t      m_incidentReportsLeft;
    double        m_incidentRate;
    std::string   m_incidentUrgency;
    std::string   m_incidentSemanticCategory;
};

// =====================================================================
//  Iec104ControllingApp  —  IEC-104 TCP client on master
// =====================================================================
class Iec104ControllingApp : public Application {
public:
    static TypeId GetTypeId();
    Iec104ControllingApp();
    ~Iec104ControllingApp() override;

    void Setup(Address peer, std::string masterIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnConn(Ptr<Socket>);
    void OnFail(Ptr<Socket>);
    void OnRecv(Ptr<Socket> sock);
    void SendIFrame();
    void SendGi();                            // periodic General Interrogation request
    void SendFrame(uint8_t type, uint32_t payloadLen);  // length-prefixed framing
    void SendTestfr();
    void NoteAck();
    void NoteIFrameReceived();
    void ArmT1();
    void RearmT3();
    void OnT1Timeout();
    void OnT2Timeout();

    Ptr<Socket>   m_sock;
    Address       m_peer;
    std::string   m_masterIp;
    std::vector<uint8_t> m_rxBytes;           // length-prefixed frame reassembly buffer
    uint32_t      m_ssn;                       // send sequence counter
    uint32_t      m_rsn;                       // receive sequence counter
    uint32_t      m_acked;                     // highest own SSN acknowledged by peer (k flow control)
    uint32_t      m_rxSinceAck;                // received I-frames since last S-frame (w)
    double        m_cmdInt;                   // scenario-aware command interval
    EventId       m_ev;                        // command I-frame timer
    EventId       m_giEv;                      // periodic GI timer
    EventId       m_t1Ev;
    EventId       m_t2Ev;
    EventId       m_t3Ev;
    bool          m_conn;
    bool          m_run;
    bool          m_started;
};

// =====================================================================
//  OpcUaServerApp  —  OPC-UA TCP server on PLC/Data Server (port 4840)
// =====================================================================
class OpcUaServerApp : public Application {
    enum State { IDLE, WAIT_OPN, WAIT_SESSION, SESSION_CREATED,
                 ACTIVE, SUBSCRIBED, RUNNING };
public:
    static TypeId GetTypeId();
    OpcUaServerApp();
    ~OpcUaServerApp() override;

    void Setup(std::string selfIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);
    void SetBaseline(double baseInt, uint32_t basePay);  // Phase 2
    void TriggerIncident(double duration, double rate, uint32_t reports,
                         std::string urgency, std::string semanticCategory);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnAccept(Ptr<Socket> ns, const Address&);
    void OnRecv(Ptr<Socket> sock);
    void SendPublish();
    void SendAlarmPublish();
    void TrySendAlarmPublish();
    void ScheduleAlarmPublish();
    void EndIncident();
    void Send(uint8_t type, uint32_t payloadLen,
              const std::string& urgency = "NORMAL",
              const std::string& kind = "PROTOCOL",
              const std::string& semanticCategory = "NONE");

    Ptr<Socket>   m_listen;
    Ptr<Socket>   m_sess;
    State         m_state;
    std::string   m_selfIp;
    std::vector<uint8_t> m_rxBytes;           // type+length framed TCP stream
    double        m_baseInt;                  // Phase 2 baseline (s)
    uint32_t      m_basePay;                  // Phase 2 baseline payload
    uint32_t      m_pubSz;                    // = basePay * scenMul
    double        m_pubInt;                   // = baseInt * scenMul (PublishingInterval)
    EventId       m_pubEv;
    EventId       m_alarmEv;
    EventId       m_alarmEndEv;
    uint32_t      m_pubTokens;                // queued PublishRequests (publish flow control)
    bool          m_alarmActive;
    bool          m_alarmReady;               // event notification queued by monitored item
    uint32_t      m_alarmReportsLeft;
    double        m_alarmRate;
    std::string   m_incidentUrgency;
    std::string   m_incidentSemanticCategory;
};

// =====================================================================
//  OpcUaClientApp  —  OPC-UA TCP client on master node
// =====================================================================
class OpcUaClientApp : public Application {
    enum Phase { P_CONNECT, P_HEL, P_WAIT_ACK, P_WAIT_OPN, P_WAIT_SESSION,
                 P_WAIT_ACTIVATE, P_WAIT_SUB, P_WAIT_MONITOR, P_RUNNING };
public:
    static TypeId GetTypeId();
    OpcUaClientApp();
    ~OpcUaClientApp() override;

    void Setup(Address peer, std::string masterIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnConn(Ptr<Socket>);
    void OnFail(Ptr<Socket>);
    void SendHello();
    void OnRecv(Ptr<Socket> sock);
    void SendOpn();
    void SendCreateSession();
    void SendActivate();
    void SendCreateSub();
    void SendCreateMonitored();
    void SendPublishRequest();
    void SendRead();
    void Send(uint8_t type, uint32_t payloadLen);

    Ptr<Socket>   m_sock;
    Address       m_peer;
    std::string   m_masterIp;
    std::string   m_scenario;
    Phase         m_phase;
    EventId       m_ev;
    bool          m_conn;
    bool          m_run;
    bool          m_readPending;
    std::vector<uint8_t> m_rxBytes;           // type+length framed TCP stream
    EventId       m_readEv;                   // periodic Read timer
};

// =====================================================================
//  MqttPublisherApp  —  MQTT publisher (sensor → Broker)
// =====================================================================
class MqttPublisherApp : public Application {
    enum PubState { WAIT_CONNACK, IDLE, WAIT_PUBACK };
public:
    static TypeId GetTypeId();
    MqttPublisherApp();
    ~MqttPublisherApp() override;

    void Setup(Address brokerAddr, std::string selfIp);
    void SetScenario(const std::string& sc);
    void RestampTos(uint8_t tos);
    void Arm();                              // Bootstrap gate; on-demand connects lazily
    void SetBaseline(double baseInt, uint32_t basePay);  // Phase 2
    void SetOnDemand(bool b);                // gateway aggregator: no periodic loop
    void SetLocalPort(uint16_t p);           // fixed source port (ground-truth label)
    void PublishOnce(uint8_t tos, uint32_t sz, uint64_t messageId,
                     uint32_t deviceId, uint8_t protocolId,
                     uint8_t sourceGateway, uint8_t chosenPath,
                     uint8_t trafficClass, uint64_t originTimeNs);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    struct PendingPublish {
        uint8_t tos;
        uint32_t size;
        uint64_t messageId;
        uint32_t deviceId;
        uint8_t protocolId;
        uint8_t sourceGateway;
        uint8_t chosenPath;
        uint8_t trafficClass;
        uint64_t originTimeNs;
    };

    void StartApplication() override;
    void StopApplication() override;
    void EnsureConnected();
    void FlushPending();
    void OnConn(Ptr<Socket>);
    void OnFail(Ptr<Socket>);
    void OnRecv(Ptr<Socket> sock);
    void Publish();
    void Ping();
    void OnPubAckTimeout();                   // A3: PUBACK timeout
    void Send(uint32_t sz, const std::string& urgency = "NORMAL",
              const std::string& kind = "PROTOCOL");
    void SendFramed(uint8_t tos, uint32_t sz, uint64_t messageId,
                    uint32_t deviceId, uint8_t protocolId,
                    uint8_t sourceGateway, uint8_t chosenPath,
                    uint8_t trafficClass, uint64_t originTimeNs);

    Ptr<Socket>   m_sock;
    Address       m_peer;
    std::string   m_selfIp;
    double        m_baseInt;                  // Phase 2 baseline (s)
    uint32_t      m_basePay;                  // Phase 2 baseline payload
    double        m_pubInt;                   // = baseInt * scenMul
    uint32_t      m_pubSz;                    // = basePay * scenMul
    uint32_t      m_rxBuf;                    // A4: byte accumulator
    PubState      m_pubState;                 // A4: state-aware parsing
    EventId       m_pubEv;
    EventId       m_pingEv;
    EventId       m_ackTimeoutEv;             // A3
    EventId       m_reconnectEv;
    std::deque<PendingPublish> m_pendingPublishes;
    bool          m_conn;
    bool          m_run;
    bool          m_armed;                    // Bootstrap gate (publish)
    bool          m_qos1;
    bool          m_onDemand;                 // true = gateway aggregator (no loop)
    uint16_t      m_localPort;                // fixed source port (0 = ephemeral)
};

// =====================================================================
//  MqttBrokerApp  —  MQTT broker (Role A: server for publishers,
//                                Role B: client forwarding to master)
// =====================================================================
class MqttBrokerApp : public Application {
public:
    static TypeId GetTypeId();
    MqttBrokerApp();
    ~MqttBrokerApp() override;

    void Setup(Address masterAddr, std::string brokerIp);

    // ---- RFC 3290 meter + re-marking marker on the Broker->Master leg ----
    // Declares a traffic profile for one class.  A message that arrives when
    // the profile is exhausted is re-marked DOWN one class instead of being
    // admitted to its band, which is what gives an over-classification a
    // non-zero cost.  A class with no profile declared is never metered, so
    // the default configuration behaves exactly as before.
    void SetClassProfile(uint32_t trafficClass, double rateBitsPerSec,
                         double burstBytes);
    // Change only the rate of an already-declared profile.  Unlike
    // SetClassProfile this does NOT refill the bucket, so a controller may
    // call it every control period without erasing the meter's memory.
    void SetClassRate(uint32_t trafficClass, double rateBitsPerSec);
    double GetClassRate(uint32_t trafficClass) const;
    // Allow EMERGENCY to consume unused IMPORTANT tokens while retaining EF.
    // Disabled by default so existing experiments are unchanged.
    void SetEmergencyBorrow(bool enabled);
    // Reports every forwarded message to the controller:
    //   (messageId, requested class, served class, demoted, borrowed,
    //    size in bytes, original OT transmit time)
    // The requested class and the size are what a controller needs to
    // estimate the offered rate of each class.
    void SetMeterCallback(
        std::function<void(uint64_t, uint8_t, uint8_t, bool, bool, uint32_t,
                           uint64_t)>
            callback);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    struct PubData {
        Ptr<Packet> rxPacket;
        bool     connected;
    };
    struct ClassMeter {
        bool   enabled = false;
        double rateBytesPerSec = 0.0;
        double burstBytes = 0.0;
        double tokens = 0.0;
        Time   lastUpdate = Seconds(0);
        uint64_t inProfile = 0;
        uint64_t outOfProfile = 0;
    };
    bool ConsumeTokens(uint32_t trafficClass, uint32_t bytes);

    void StartApplication() override;
    void StopApplication() override;
    void OnAccept(Ptr<Socket> ns, const Address&);
    void OnPubData(Ptr<Socket> pubSock);
    void OnMasterConn(Ptr<Socket>);
    void OnMasterFail(Ptr<Socket>);
    void Forward(const ScadaMqttHeader& header, Ptr<Packet> payload);

    Ptr<Socket>                              m_listen;
    std::unordered_map<Ptr<Socket>, PubData, PtrHash> m_sessions;
    std::array<Ptr<Socket>, 3>               m_toMaster;
    std::array<bool, 3>                      m_masterConn;
    Address                                  m_masterAddr;
    std::string                              m_brokerIp;
    std::array<ClassMeter, 3>                m_meter;
    bool                                    m_emergencyBorrow = false;
    std::function<void(uint64_t, uint8_t, uint8_t, bool, bool, uint32_t,
                       uint64_t)> m_meterCb;
};

// Master-side framed MQTT subscriber. Delivery callbacks are simulator-side
// control telemetry; they do not add data-plane packets or expose ground truth
// to the gateway classifier.
class ScadaMasterSubscriberApp : public Application {
public:
    static TypeId GetTypeId();
    ScadaMasterSubscriberApp();
    ~ScadaMasterSubscriberApp() override;

    void Setup(uint16_t port,
               std::function<void(const ScadaDeliveryInfo&)> deliveryCallback);
    TracedCallback<Ptr<const Packet>> m_rx;

private:
    struct Session {
        Ptr<Packet> rxPacket;
    };

    void StartApplication() override;
    void StopApplication() override;
    void OnAccept(Ptr<Socket> socket, const Address& from);
    void OnData(Ptr<Socket> socket);

    uint16_t m_port;
    Ptr<Socket> m_listen;
    std::unordered_map<Ptr<Socket>, Session, PtrHash> m_sessions;
    std::function<void(const ScadaDeliveryInfo&)> m_deliveryCallback;
};

// =====================================================================
//  BootstrapAnnounceApp  —  Master-side "I am online" UDP announcer.
//  ─────────────────────────────────────────────────────────────────────
//  At the configured time (typically t=1.0 s), sends one small UDP
//  packet to every registered target.  Listeners on those nodes use
//  the packet as a signal to Arm() their field-initiating apps.
// =====================================================================
class BootstrapAnnounceApp : public Application {
public:
    static TypeId GetTypeId();
    BootstrapAnnounceApp();
    ~BootstrapAnnounceApp() override;

    void Setup(Time fireAt);                       // when to emit
    void AddTarget(Ipv4Address addr, uint16_t port = 9100);

    TracedCallback<Ptr<const Packet>> m_tx;

private:
    void StartApplication() override;
    void StopApplication() override;
    void Fire();

    Ptr<Socket>                  m_sock;
    std::vector<InetSocketAddress> m_targets;
    Time                         m_fireAt;
    EventId                      m_ev;
};

// =====================================================================
//  BootstrapListenerApp  —  Field/GW-side UDP listener.
//  ─────────────────────────────────────────────────────────────────────
//  Listens on port 9100 (default).  On first packet received, invokes
//  every registered std::function<void()> callback once and ignores
//  subsequent packets (idempotent arm).
// =====================================================================
class BootstrapListenerApp : public Application {
public:
    static TypeId GetTypeId();
    BootstrapListenerApp();
    ~BootstrapListenerApp() override;

    void Setup(uint16_t port = 9100);
    void RegisterArm(std::function<void()> cb);

private:
    void StartApplication() override;
    void StopApplication() override;
    void OnRecv(Ptr<Socket> sock);

    Ptr<Socket>                       m_sock;
    uint16_t                          m_port;
    bool                              m_received;
    std::vector<std::function<void()>> m_callbacks;
};

} // namespace ns3
