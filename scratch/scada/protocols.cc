// =====================================================================
//  protocols.cc  —  SCADA Multi-Protocol App implementations
//  ─────────────────────────────────────────────────────────────────────
//  Implements ns-3 Application classes declared in protocols.h:
//      Modbus       : ModbusSlaveApp,        ModbusMasterApp
//      DNP3         : Dnp3OutstationApp,     Dnp3MasterApp
//      IEC-104      : Iec104ControlledApp,   Iec104ControllingApp
//      OPC-UA       : OpcUaServerApp,        OpcUaClientApp
//      MQTT         : MqttPublisherApp,      MqttBrokerApp
// =====================================================================

#include "protocols.h"

#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket.h"
#include "ns3/inet-socket-address.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"

#include <algorithm>
#include <utility>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("ScadaProtocols");

NS_OBJECT_ENSURE_REGISTERED(ScadaMessageTag);
NS_OBJECT_ENSURE_REGISTERED(ScadaMqttHeader);

TypeId ScadaMessageTag::GetTypeId() {
    static TypeId tid = TypeId("ns3::ScadaMessageTag")
        .SetParent<Tag>()
        .SetGroupName("Applications")
        .AddConstructor<ScadaMessageTag>();
    return tid;
}
TypeId ScadaMessageTag::GetInstanceTypeId() const { return GetTypeId(); }
uint32_t ScadaMessageTag::GetSerializedSize() const { return 3; }
void ScadaMessageTag::Serialize(TagBuffer buffer) const {
    buffer.WriteU8(m_urgency);
    buffer.WriteU8(m_kind);
    buffer.WriteU8(m_semanticCategory);
}
void ScadaMessageTag::Deserialize(TagBuffer buffer) {
    m_urgency = buffer.ReadU8();
    m_kind = buffer.ReadU8();
    m_semanticCategory = buffer.ReadU8();
}
void ScadaMessageTag::Print(std::ostream& os) const {
    os << "urgency=" << static_cast<uint32_t>(m_urgency)
       << ",kind=" << static_cast<uint32_t>(m_kind)
       << ",semanticCategory=" << static_cast<uint32_t>(m_semanticCategory);
}
void ScadaMessageTag::SetUrgency(uint8_t urgency) { m_urgency = urgency; }
void ScadaMessageTag::SetKind(uint8_t kind) { m_kind = kind; }
void ScadaMessageTag::SetSemanticCategory(uint8_t category) {
    m_semanticCategory = category;
}
uint8_t ScadaMessageTag::GetUrgency() const { return m_urgency; }
uint8_t ScadaMessageTag::GetKind() const { return m_kind; }
uint8_t ScadaMessageTag::GetSemanticCategory() const {
    return m_semanticCategory;
}

void SetScadaMessageMetadata(Ptr<Packet> packet,
                             const std::string& urgency,
                             const std::string& kind,
                             const std::string& semanticCategory) {
    if (!packet) return;
    ScadaMessageTag tag;
    tag.SetUrgency((urgency == "TIME_CRITICAL" || urgency == "EMERGENCY") ? 2 :
                   (urgency == "OPERATIONAL" || urgency == "IMPORTANT") ? 1 : 0);
    tag.SetKind(kind == "EVENT" ? 2 : kind == "TELEMETRY" ? 1 : 0);
    // Coarse meaning decoded by the translating gateway.  The category is not
    // an N/I/E answer: the incident schedule deliberately contains overlap
    // between semantic categories and final service classes.
    uint8_t category = semanticCategory == "PROTECTION" ? 4 :
                       semanticCategory == "CONTROL" ? 3 :
                       semanticCategory == "ALARM" ? 2 :
                       semanticCategory == "STATUS" ? 1 : 0;
    tag.SetSemanticCategory(kind == "EVENT" ? category : 0);
    packet->ReplacePacketTag(tag);
}

std::string GetScadaUrgency(Ptr<const Packet> packet) {
    ScadaMessageTag tag;
    if (!packet || !packet->PeekPacketTag(tag)) return "NORMAL";
    return tag.GetUrgency() == 2 ? "EMERGENCY" :
           tag.GetUrgency() == 1 ? "IMPORTANT" : "NORMAL";
}

std::string GetScadaServiceClass(Ptr<const Packet> packet) {
    ScadaMessageTag tag;
    if (!packet || !packet->PeekPacketTag(tag)) return "MONITORING";
    return tag.GetUrgency() == 2 ? "TIME_CRITICAL" :
           tag.GetUrgency() == 1 ? "OPERATIONAL" : "MONITORING";
}

std::string GetScadaMessageKind(Ptr<const Packet> packet) {
    ScadaMessageTag tag;
    if (!packet || !packet->PeekPacketTag(tag)) return "PROTOCOL";
    return tag.GetKind() == 2 ? "EVENT" :
           tag.GetKind() == 1 ? "TELEMETRY" : "PROTOCOL";
}

uint8_t GetScadaSemanticCategory(Ptr<const Packet> packet) {
    ScadaMessageTag tag;
    if (!packet || !packet->PeekPacketTag(tag)) return 0;
    return tag.GetSemanticCategory();
}

TypeId ScadaMqttHeader::GetTypeId() {
    static TypeId tid = TypeId("ns3::ScadaMqttHeader")
        .SetParent<Header>()
        .SetGroupName("Applications")
        .AddConstructor<ScadaMqttHeader>();
    return tid;
}
TypeId ScadaMqttHeader::GetInstanceTypeId() const { return GetTypeId(); }
uint32_t ScadaMqttHeader::GetSerializedSize() const { return 32; }
void ScadaMqttHeader::Serialize(Buffer::Iterator i) const {
    i.WriteHtonU32(m_magic);
    i.WriteHtonU32(m_payloadLength);
    i.WriteHtonU64(m_messageId);
    i.WriteHtonU64(m_sendTimeNs);
    i.WriteHtonU32(m_deviceId);
    i.WriteU8(m_sourceGateway);
    i.WriteU8(m_chosenPath);
    i.WriteU8(m_trafficClass);
    i.WriteU8(m_protocolId);
}
uint32_t ScadaMqttHeader::Deserialize(Buffer::Iterator i) {
    m_magic = i.ReadNtohU32();
    m_payloadLength = i.ReadNtohU32();
    m_messageId = i.ReadNtohU64();
    m_sendTimeNs = i.ReadNtohU64();
    m_deviceId = i.ReadNtohU32();
    m_sourceGateway = i.ReadU8();
    m_chosenPath = i.ReadU8();
    m_trafficClass = i.ReadU8();
    m_protocolId = i.ReadU8();
    return GetSerializedSize();
}
void ScadaMqttHeader::Print(std::ostream& os) const {
    os << "id=" << m_messageId << ",len=" << m_payloadLength
       << ",gw=" << static_cast<uint32_t>(m_sourceGateway)
       << ",path=" << static_cast<uint32_t>(m_chosenPath)
       << ",class=" << static_cast<uint32_t>(m_trafficClass);
}
bool ScadaMqttHeader::IsValid() const { return m_magic == MAGIC; }
void ScadaMqttHeader::SetPayloadLength(uint32_t v) { m_payloadLength = v; }
void ScadaMqttHeader::SetMessageId(uint64_t v) { m_messageId = v; }
void ScadaMqttHeader::SetSendTimeNs(uint64_t v) { m_sendTimeNs = v; }
void ScadaMqttHeader::SetDeviceId(uint32_t v) { m_deviceId = v; }
void ScadaMqttHeader::SetSourceGateway(uint8_t v) { m_sourceGateway = v; }
void ScadaMqttHeader::SetChosenPath(uint8_t v) { m_chosenPath = v; }
void ScadaMqttHeader::SetTrafficClass(uint8_t v) { m_trafficClass = v; }
void ScadaMqttHeader::SetProtocolId(uint8_t v) { m_protocolId = v; }
uint32_t ScadaMqttHeader::GetPayloadLength() const { return m_payloadLength; }
uint64_t ScadaMqttHeader::GetMessageId() const { return m_messageId; }
uint64_t ScadaMqttHeader::GetSendTimeNs() const { return m_sendTimeNs; }
uint32_t ScadaMqttHeader::GetDeviceId() const { return m_deviceId; }
uint8_t ScadaMqttHeader::GetSourceGateway() const { return m_sourceGateway; }
uint8_t ScadaMqttHeader::GetChosenPath() const { return m_chosenPath; }
uint8_t ScadaMqttHeader::GetTrafficClass() const { return m_trafficClass; }
uint8_t ScadaMqttHeader::GetProtocolId() const { return m_protocolId; }

// ─────────────────── NOISE FLOOR JITTER ────────────────────
// Apply ±10% multiplicative jitter to event intervals to model scheduler
// drift, TCP retransmission timing, PLC scan variation, queue delay.
static Ptr<UniformRandomVariable> g_jitterRng;
static double JitteredInterval(double base) {
    if (!g_jitterRng) g_jitterRng = CreateObject<UniformRandomVariable>();
    return base * (0.9 + g_jitterRng->GetValue() * 0.2);    // 0.9 - 1.1
}

// So doi tuong thong tin (information object / data point) trong mot khung.
// Ban tin do luong chu ky mang NHIEU doi tuong khong co nhan thoi gian; ban
// tin su kien mang IT doi tuong nhung moi doi tuong co them nhan thoi gian.
// Hai phan bo kich thuoc vi vay trum lan nhau: kich thuoc mot minh KHONG xac
// dinh duoc ban tin thuoc loai nao, dung nhu tren mang thuc.
static uint32_t ObjectCount(uint32_t lo, uint32_t hi) {
    if (!g_jitterRng) g_jitterRng = CreateObject<UniformRandomVariable>();
    if (hi <= lo) return lo;
    return lo + static_cast<uint32_t>(
        g_jitterRng->GetValue() * static_cast<double>(hi - lo + 1) * 0.999999);
}

static uint32_t JitteredPayloadSize(uint32_t base, double fraction = 0.15) {
    if (!g_jitterRng) g_jitterRng = CreateObject<UniformRandomVariable>();
    double factor = 1.0 - fraction + 2.0 * fraction * g_jitterRng->GetValue();
    return static_cast<uint32_t>(std::max(1.0, base * factor));
}

// Observable service-profile variation used by the flow classifier.  A
// time-critical control/protection service carries a compact value set and
// relies on a sharper burst, whereas an operational event batches more
// status fields.  The factors intentionally overlap through ObjectCount and
// per-device payload variation; they are not exact message-type identifiers.
static double ServicePayloadScale(const std::string& serviceClass) {
    if (serviceClass == "TIME_CRITICAL" || serviceClass == "EMERGENCY")
        return 0.25;
    if (serviceClass == "OPERATIONAL" || serviceClass == "IMPORTANT")
        return 3.25;
    return 1.0;
}

// External scenario multiplier helper (defined in scada.cc).
extern std::pair<double,double> GetScenarioMulPair(const std::string& proto,
                                                    const std::string& scn);

// ─────────────────────────── PRIVATE CONSTANTS ───────────────────────

// ---- Modbus TCP frame sizes ----
static constexpr uint32_t MODBUS_REQ_SZ      = 12;   // MBAP(7)+FC(1)+Addr(2)+Qty(2)
static constexpr uint32_t MODBUS_RESP_SZ_NRM = 73;   // 32 holding registers
static constexpr uint32_t MODBUS_RESP_SZ_HLD = 137;  // 64 holding registers
static constexpr double   MODBUS_TIMEOUT     = 1.2;  // s, response wait timeout
static constexpr uint32_t MODBUS_HDR_SZ      = 8;    // transaction-id + frame length

static inline void ModbusWriteU32(uint8_t* b, uint32_t v) {
    b[0] = static_cast<uint8_t>((v >> 24) & 0xff);
    b[1] = static_cast<uint8_t>((v >> 16) & 0xff);
    b[2] = static_cast<uint8_t>((v >> 8) & 0xff);
    b[3] = static_cast<uint8_t>(v & 0xff);
}
static inline uint32_t ModbusReadU32(const uint8_t* b) {
    return (static_cast<uint32_t>(b[0]) << 24) |
           (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) |
            static_cast<uint32_t>(b[3]);
}

// ---- DNP3 application-message PAYLOAD sizes (the "Length" field value) ----
// The DNP3 Primer specifies frame/fragment bounds (link frame <= 292 octets,
// app fragment ~2048-4096), not exact per-message byte counts, so these are
// representative values consistent with the document.
static constexpr uint32_t DNP3_POLL_SZ        = 20;
static constexpr uint32_t DNP3_RESP_SZ        = 120;
// Mo hinh kich thuoc response theo so data point.
static constexpr uint32_t DNP3_APP_HDR_SZ     = 12;  // app header + IIN
static constexpr uint32_t DNP3_POINT_SZ       = 6;   // Class-0 point + flags
static constexpr uint32_t DNP3_EVT_POINT_SZ   = 11;  // + nhan thoi gian 48 bit
static constexpr uint32_t DNP3_C0_POINT_MIN   = 1;
static constexpr uint32_t DNP3_C0_POINT_MAX   = 16;
static constexpr uint32_t DNP3_EVT_POINT_MIN  = 1;
static constexpr uint32_t DNP3_EVT_POINT_MAX  = 8;
static constexpr uint32_t DNP3_UNSOL_SZ       = 300;
static constexpr uint32_t DNP3_CONFIRM_SZ     = 14;
static constexpr uint32_t DNP3_UNSOL_THRESH   = 5;
static constexpr double   DNP3_POLL_INT       = 0.5;
static constexpr double   DNP3_EVENT_RATE_NRM = 0.1;   // baseline default (overridden per device)
static constexpr double   DNP3_TIMEOUT        = 2.0;  // s, poll-response timeout
// Kept for reference only: with length-prefixed framing the master accepts any
// unsolicited size, and the live event rate is baseRate / scenario-multiplier,
// so these standalone constants are no longer referenced directly in code.
[[maybe_unused]] static constexpr uint32_t DNP3_UNSOL_SZ_EMR   = 600;
[[maybe_unused]] static constexpr double   DNP3_EVENT_RATE_HLD = 0.2;
[[maybe_unused]] static constexpr double   DNP3_EVENT_RATE_EMR = 2.0;

// ---- DNP3 virtual framing header (Type Identifier + Length) ----
// Every DNP3 message is prefixed on the wire with a 5-byte header so the
// receiver frames messages unambiguously even when poll-responses and
// unsolicited responses interleave on the same TCP connection. This mirrors,
// at an abstracted level, the DNP3 data-link header (start + length field).
//   byte 0      : message type (DNP3_T_*)
//   bytes 1..4  : payload length, big-endian uint32
static constexpr uint32_t DNP3_HDR_SZ    = 5;
static constexpr uint8_t  DNP3_T_POLL    = 1;   // master     -> outstation: integrity poll
static constexpr uint8_t  DNP3_T_RESP    = 2;   // outstation -> master    : Class-0 response
static constexpr uint8_t  DNP3_T_UNSOL   = 3;   // outstation -> master    : unsolicited response
static constexpr uint8_t  DNP3_T_CONFIRM = 4;   // master     -> outstation: app-layer confirm

// ---- IEC 60870-5-104 parameters ----
// Frame PAYLOAD sizes (APCI, or APCI+ASDU for I-frames). I/S/U sizes confirmed
// by the CEUR paper / standard: APCI is 6 bytes (S- and U-frames are APCI-only).
static constexpr uint32_t IEC_IFRAME_SZ  = 72;     // APCI(6)+ASDU(66), representative
// Mo hinh kich thuoc ASDU theo so doi tuong thong tin.
static constexpr uint32_t IEC_ASDU_HDR_SZ = 12;   // APCI(6) + ASDU header(6)
static constexpr uint32_t IEC_OBJ_SZ      = 6;    // IOA(3)+value(2)+QDS(1)
static constexpr uint32_t IEC_OBJ_TS_SZ   = 16;   // + CP56Time2a(7), value(5)
static constexpr uint32_t IEC_CYC_OBJ_MIN = 1;    // ASDU do luong chu ky
static constexpr uint32_t IEC_CYC_OBJ_MAX = 10;
static constexpr uint32_t IEC_EVT_OBJ_MIN = 1;    // ASDU spontaneous
static constexpr uint32_t IEC_EVT_OBJ_MAX = 4;

// Kich thuoc mot ASDU do luong chu ky: 18..72 B
static uint32_t IecCyclicSize() {
    return IEC_ASDU_HDR_SZ +
           ObjectCount(IEC_CYC_OBJ_MIN, IEC_CYC_OBJ_MAX) * IEC_OBJ_SZ;
}
// Kich thuoc mot ASDU spontaneous co nhan thoi gian: 28..76 B
static uint32_t IecEventSize() {
    return IEC_ASDU_HDR_SZ +
           ObjectCount(IEC_EVT_OBJ_MIN, IEC_EVT_OBJ_MAX) * IEC_OBJ_TS_SZ;
}
static constexpr uint32_t IEC_SFRAME_SZ  = 6;      // S-frame = APCI only
static constexpr uint32_t IEC_UFRAME_SZ  = 6;      // U-frame = APCI only
static constexpr uint32_t IEC_W          = 8;      // ack after w received I-frames (standard default)
static constexpr uint32_t IEC_K          = 12;     // max unacked I-frames; sender stops at k (standard default)
static constexpr double   IEC_T1         = 15.0;   // s, ack timeout of a sent I-frame -> close (standard default)
static constexpr double   IEC_T2         = 10.0;   // s, send S-frame ack if unacked & idle, t2 < t1 (standard default)
static constexpr double   IEC_T3         = 20.0;   // s, idle -> send TESTFR (standard default)
static constexpr uint32_t IEC_GI_COUNT   = 10;     // I-frames in a General Interrogation response burst
static constexpr double   IEC_GI_INT     = 60.0;   // s, periodic General Interrogation interval
static constexpr double   IEC_INT_NRM    = 1.0;   // controlled baseline default (overridden per device)
[[maybe_unused]] static constexpr double IEC_INT_HLD = 0.5;  // reference; live rate = baseInt * multiplier
[[maybe_unused]] static constexpr double IEC_INT_EMR = 0.1;  // reference; live rate = baseInt * multiplier
static constexpr double   IEC_CMD_INT_NRM = 2.0;
static constexpr double   IEC_CMD_INT_HLD = 1.0;
static constexpr double   IEC_CMD_INT_EMR = 0.2;

// ---- IEC-104 virtual framing header (Type Identifier + Length) ----
// 5-byte prefix [type(1)][length(4) big-endian] so I/S/U frames (and U
// subtypes) are framed unambiguously when they interleave on the TCP stream.
static constexpr uint32_t IEC_HDR_SZ         = 5;
static constexpr uint8_t  IEC_T_I            = 1;  // I-frame (information / ASDU)
static constexpr uint8_t  IEC_T_S            = 2;  // S-frame (supervisory ack)
static constexpr uint8_t  IEC_T_STARTDT_ACT  = 3;  // U: STARTDT act
static constexpr uint8_t  IEC_T_STARTDT_CON  = 4;  // U: STARTDT con
static constexpr uint8_t  IEC_T_TESTFR_ACT   = 5;  // U: TESTFR act
static constexpr uint8_t  IEC_T_TESTFR_CON   = 6;  // U: TESTFR con
static constexpr uint8_t  IEC_T_GI           = 7;  // I-frame carrying C_IC General Interrogation

// ---- OPC-UA binary transport message sizes ----
static constexpr uint32_t OPC_HEL_SZ      = 56;   // Hello: 8 hdr + 20 body + EndpointUrl string
static constexpr uint32_t OPC_ACK_SZ      = 28;   // Acknowledge: 8 hdr + 20 body (exact)
static constexpr uint32_t OPC_OPN_REQ_SZ  = 132;  // OpenSecureChannel request
static constexpr uint32_t OPC_OPN_RSP_SZ  = 140;  // OpenSecureChannel response
static constexpr uint32_t OPC_CSES_REQ_SZ = 200;  // CreateSession request
static constexpr uint32_t OPC_CSES_RSP_SZ = 350;  // CreateSession response (endpoints + cert)
static constexpr uint32_t OPC_ACTI_REQ_SZ = 100;  // ActivateSession request
static constexpr uint32_t OPC_ACTI_RSP_SZ = 80;   // ActivateSession response
static constexpr uint32_t OPC_CSUB_REQ_SZ = 80;   // CreateSubscription request
static constexpr uint32_t OPC_CSUB_RSP_SZ = 60;   // CreateSubscription response
static constexpr uint32_t OPC_CMI_REQ_SZ  = 160;  // CreateMonitoredItems request
static constexpr uint32_t OPC_CMI_RSP_SZ  = 120;  // CreateMonitoredItems response
static constexpr uint32_t OPC_READ_SZ     = 64;   // Read request
static constexpr uint32_t OPC_READ_RSP_SZ = 96;   // Read response (DataValue array)
// So monitored item trong mot NotificationMessage thay doi tung lan publish,
// nen kich thuoc ban tin do luong trai rong va trum len kich thuoc ban tin
// su kien.  EventNotification mang it item hon nhung moi item co them cac
// truong su kien nen "nang" hon.
static constexpr uint32_t OPC_NOTIF_ITEM_MIN = 1;
static constexpr uint32_t OPC_NOTIF_ITEM_MAX = 12;
static constexpr uint32_t OPC_EVENT_ITEM_MIN = 1;
static constexpr uint32_t OPC_EVENT_ITEM_MAX = 4;
static constexpr double   OPC_EVENT_ITEM_MUL = 1.6;
static constexpr uint32_t OPC_PUBREQ_SZ   = 80;   // PublishRequest token (client→server, upstream)
static constexpr uint32_t OPC_PUB_NRM     = 1024; // PublishResponse payload (normal)
static constexpr uint32_t OPC_PUB_HLD     = 4096; // PublishResponse payload (high_load)
static constexpr double   OPC_PUB_INT_NRM = 0.5;  // PublishingInterval default (normal)
static constexpr double   OPC_PUB_INT_HLD = 0.1;  // PublishingInterval ceiling (high_load)
static constexpr uint32_t OPC_PUB_WINDOW  = 2;    // outstanding PublishRequests kept by client
static constexpr double   OPC_READ_INT    = 2.0;  // client periodic Read cadence (s)

// TCP can split or coalesce OPC-UA messages arbitrarily. This compact
// simulator framing mirrors the real OPC-UA message header's type/length
// information and keeps PublishResponse and ReadResponse parsing unambiguous.
static constexpr uint32_t OPC_HDR_SZ = 5;
static constexpr uint8_t OPC_T_HEL       = 1;
static constexpr uint8_t OPC_T_ACK       = 2;
static constexpr uint8_t OPC_T_OPN_REQ   = 3;
static constexpr uint8_t OPC_T_OPN_RSP   = 4;
static constexpr uint8_t OPC_T_CSES_REQ  = 5;
static constexpr uint8_t OPC_T_CSES_RSP  = 6;
static constexpr uint8_t OPC_T_ACTI_REQ  = 7;
static constexpr uint8_t OPC_T_ACTI_RSP  = 8;
static constexpr uint8_t OPC_T_CSUB_REQ  = 9;
static constexpr uint8_t OPC_T_CSUB_RSP  = 10;
static constexpr uint8_t OPC_T_CMI_REQ   = 11;
static constexpr uint8_t OPC_T_CMI_RSP   = 12;
static constexpr uint8_t OPC_T_PUB_REQ   = 13;
static constexpr uint8_t OPC_T_PUB_RSP   = 14;
static constexpr uint8_t OPC_T_READ_REQ  = 15;
static constexpr uint8_t OPC_T_READ_RSP  = 16;

// ---- MQTT message sizes ----
static constexpr uint32_t MQTT_CONNECT_SZ = 42;
static constexpr uint32_t MQTT_CONNACK_SZ = 4;
static constexpr uint32_t MQTT_PINGREQ_SZ = 2;
static constexpr uint32_t MQTT_PINGRSP_SZ = 2;
static constexpr uint32_t MQTT_PUB_NRM    = 50;
static constexpr uint32_t MQTT_PUB_EMR    = 100;
static constexpr uint32_t MQTT_PUBACK_SZ  = 4;
static constexpr double   MQTT_KEEPALIVE  = 60.0;
static constexpr double   MQTT_INT_NRM    = 5.0;
static constexpr double   MQTT_EMR_MAX_INT = 0.1;  // s — hard ceiling so emergency publishes ~instantly
static constexpr double   MQTT_ACK_TIMEOUT = 0.5;  // s, PUBACK wait timeout (QoS 1 emergency)


// =====================================================================
//  ModbusSlaveApp
// =====================================================================
TypeId ModbusSlaveApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::ModbusSlaveApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<ModbusSlaveApp>()
        .AddTraceSource("Tx", "Response sent",
            MakeTraceSourceAccessor(&ModbusSlaveApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
ModbusSlaveApp::ModbusSlaveApp()
    : m_listenSock(nullptr),
      m_baseRespSz(MODBUS_RESP_SZ_NRM),
      m_respSz(MODBUS_RESP_SZ_NRM),
      m_incidentLabel("NORMAL"),
      m_incidentSemanticCategory("ALARM"),
      m_incidentResponsesLeft(0) {}
ModbusSlaveApp::~ModbusSlaveApp() {}
void ModbusSlaveApp::Setup(std::string selfIp) { m_selfIp = selfIp; }
void ModbusSlaveApp::SetBaseline(uint32_t respSz) {
    m_baseRespSz = respSz;
    m_respSz     = respSz;            // initial = baseline
}
void ModbusSlaveApp::SetScenario(const std::string& sc) {
    auto m = GetScenarioMulPair("Modbus", sc);
    m_respSz = (uint32_t)std::max(1.0, m_baseRespSz * m.second);
}
void ModbusSlaveApp::StartApplication() {
    m_listenSock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listenSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), PORT_MODBUS));
    m_listenSock->Listen();
    m_listenSock->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&ModbusSlaveApp::OnAccept, this));
}
void ModbusSlaveApp::StopApplication() {
    Simulator::Cancel(m_incidentEndEv);
    if (m_listenSock) { m_listenSock->Close(); m_listenSock = nullptr; }
    for (auto& [s, b] : m_rxBuf) if (s) s->Close();
    m_rxBuf.clear();
}
void ModbusSlaveApp::TriggerIncident(double duration, const std::string& label,
                                     uint32_t responses,
                                     const std::string& semanticCategory) {
    Simulator::Cancel(m_incidentEndEv);
    if (responses == 0) {
        EndIncident();
        return;
    }
    m_incidentLabel =
        (label == "TIME_CRITICAL" || label == "EMERGENCY")
            ? "TIME_CRITICAL" : "OPERATIONAL";
    m_incidentSemanticCategory = semanticCategory;
    m_incidentResponsesLeft = responses;
    m_incidentEndEv = Simulator::Schedule(
        Seconds(std::max(0.0, duration)), &ModbusSlaveApp::EndIncident, this);
}
void ModbusSlaveApp::EndIncident() {
    m_incidentLabel = "NORMAL";
    m_incidentResponsesLeft = 0;
}
void ModbusSlaveApp::OnAccept(Ptr<Socket> ns, const Address&) {
    ns->SetRecvCallback(MakeCallback(&ModbusSlaveApp::OnRecv, this));
    ns->SetCloseCallbacks(
        MakeCallback(&ModbusSlaveApp::OnClose, this),
        MakeNullCallback<void, Ptr<Socket>>());
    m_rxBuf[ns] = {};
}
void ModbusSlaveApp::OnRecv(Ptr<Socket> sock) {
    auto it = m_rxBuf.find(sock);
    if (it == m_rxBuf.end()) {
        Ptr<Packet> p;
        while ((p = sock->Recv())) { /* discard */ }
        return;
    }
    std::vector<uint8_t>& buf = it->second;
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t n = p->GetSize();
        if (n == 0) continue;
        size_t off = buf.size();
        buf.resize(off + n);
        p->CopyData(buf.data() + off, n);
    }

    while (buf.size() >= MODBUS_HDR_SZ) {
        uint32_t transactionId = ModbusReadU32(buf.data());
        uint32_t frameLen = ModbusReadU32(buf.data() + 4);
        if (frameLen < MODBUS_HDR_SZ || frameLen > 65536) {
            NS_LOG_WARN("Dropping malformed Modbus request frame length=" << frameLen);
            buf.clear();
            break;
        }
        if (buf.size() < frameLen) break;
        buf.erase(buf.begin(), buf.begin() + frameLen);
        Simulator::Schedule(MilliSeconds(1),
            &ModbusSlaveApp::SendResp, this, sock, transactionId);
    }
}
void ModbusSlaveApp::SendResp(Ptr<Socket> sock, uint32_t transactionId) {
    uint32_t frameLen = std::max(m_respSz, MODBUS_HDR_SZ);
    std::vector<uint8_t> bytes(frameLen, 0);
    ModbusWriteU32(bytes.data(), transactionId);
    ModbusWriteU32(bytes.data() + 4, frameLen);
    Ptr<Packet> resp = Create<Packet>(bytes.data(), frameLen);
    const bool incident = m_incidentLabel != "NORMAL"
                       && m_incidentResponsesLeft > 0;
    SetScadaMessageMetadata(resp, incident ? m_incidentLabel : "NORMAL",
                            incident ? "EVENT" : "TELEMETRY",
                            incident ? m_incidentSemanticCategory : "NONE");
    m_tx(resp);
    sock->Send(resp);
    if (incident && --m_incidentResponsesLeft == 0) EndIncident();
}
void ModbusSlaveApp::OnClose(Ptr<Socket> sock) {
    m_rxBuf.erase(sock);
}
NS_OBJECT_ENSURE_REGISTERED(ModbusSlaveApp);

// =====================================================================
//  ModbusMasterApp
// =====================================================================
TypeId ModbusMasterApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::ModbusMasterApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<ModbusMasterApp>()
        .AddTraceSource("Tx", "Request sent",
            MakeTraceSourceAccessor(&ModbusMasterApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
ModbusMasterApp::ModbusMasterApp()
    : m_baseInt(0.5), m_pollInt(0.5),
      m_nextTransactionId(1), m_outstandingTransactionId(0),
      m_retryCount(0), m_waitingResponse(false),
      m_conn(false), m_run(false) {}
ModbusMasterApp::~ModbusMasterApp() {}
void ModbusMasterApp::Setup(Address peer, std::string masterIp) {
    m_peer = peer; m_masterIp = masterIp;
}
void ModbusMasterApp::SetBaseline(double pollInt) {
    m_baseInt = pollInt;
    m_pollInt = pollInt;
}
void ModbusMasterApp::SetScenario(const std::string& sc) {
    auto m = GetScenarioMulPair("Modbus", sc);
    m_pollInt = m_baseInt * m.first;
}
void ModbusMasterApp::StartApplication() {
    m_run = true;
    m_sock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_sock->SetIpTos(LabelToTos("Modbus", "normal"));
    m_sock->Bind();
    m_sock->Connect(m_peer);
    m_sock->SetConnectCallback(
        MakeCallback(&ModbusMasterApp::OnConn, this),
        MakeCallback(&ModbusMasterApp::OnFail, this));
    m_sock->SetRecvCallback(MakeCallback(&ModbusMasterApp::OnRecv, this));
}
void ModbusMasterApp::StopApplication() {
    m_run = false;
    Simulator::Cancel(m_pollEv);
    Simulator::Cancel(m_timeoutEv);
    if (m_sock) m_sock->Close();
}
void ModbusMasterApp::OnConn(Ptr<Socket>) { m_conn = true; Poll(); }
void ModbusMasterApp::OnFail(Ptr<Socket>) { m_conn = false; }
void ModbusMasterApp::Poll() {
    if (!m_run || !m_conn || m_waitingResponse) return;
    m_outstandingTransactionId = m_nextTransactionId++;
    std::vector<uint8_t> bytes(MODBUS_REQ_SZ, 0);
    ModbusWriteU32(bytes.data(), m_outstandingTransactionId);
    ModbusWriteU32(bytes.data() + 4, MODBUS_REQ_SZ);
    Ptr<Packet> req = Create<Packet>(bytes.data(), MODBUS_REQ_SZ);
    SetScadaMessageMetadata(req, "NORMAL", "PROTOCOL");
    m_tx(req);
    m_sock->Send(req);
    m_waitingResponse = true;
    Simulator::Cancel(m_timeoutEv);
    m_timeoutEv = Simulator::Schedule(Seconds(MODBUS_TIMEOUT),
        &ModbusMasterApp::OnTimeout, this);
}
void ModbusMasterApp::OnRecv(Ptr<Socket> sock) {
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t n = p->GetSize();
        if (n == 0) continue;
        size_t off = m_rxBytes.size();
        m_rxBytes.resize(off + n);
        p->CopyData(m_rxBytes.data() + off, n);
    }
    while (m_rxBytes.size() >= MODBUS_HDR_SZ) {
        uint32_t transactionId = ModbusReadU32(m_rxBytes.data());
        uint32_t frameLen = ModbusReadU32(m_rxBytes.data() + 4);
        if (frameLen < MODBUS_HDR_SZ || frameLen > 65536) {
            NS_LOG_WARN("Dropping malformed Modbus response frame length=" << frameLen);
            m_rxBytes.clear();
            break;
        }
        if (m_rxBytes.size() < frameLen) break;
        m_rxBytes.erase(m_rxBytes.begin(), m_rxBytes.begin() + frameLen);
        if (!m_waitingResponse || transactionId != m_outstandingTransactionId) {
            continue;
        }
        m_waitingResponse = false;
        m_retryCount = 0;
        Simulator::Cancel(m_timeoutEv);
        Simulator::Cancel(m_pollEv);
        if (m_run && m_conn) {
            m_pollEv = Simulator::Schedule(Seconds(JitteredInterval(m_pollInt)),
                &ModbusMasterApp::Poll, this);
        }
    }
}
void ModbusMasterApp::OnTimeout() {
    // Response presumed lost — re-poll immediately.
    if (m_waitingResponse && m_run && m_conn) {
        m_waitingResponse = false;
        m_retryCount = std::min(m_retryCount + 1, 4u);
        double backoff = m_pollInt * static_cast<double>(1u << m_retryCount);
        Simulator::Cancel(m_pollEv);
        m_pollEv = Simulator::Schedule(Seconds(JitteredInterval(backoff)),
            &ModbusMasterApp::Poll, this);
    }
}
NS_OBJECT_ENSURE_REGISTERED(ModbusMasterApp);

// Big-endian (de)serialization for the 4-byte length field shared by the
// DNP3 and IEC-104 virtual framing headers.
static inline void BeWriteU32(uint8_t* b, uint32_t v) {
    b[0] = (uint8_t)((v >> 24) & 0xFF);
    b[1] = (uint8_t)((v >> 16) & 0xFF);
    b[2] = (uint8_t)((v >> 8)  & 0xFF);
    b[3] = (uint8_t)( v        & 0xFF);
}
static inline uint32_t BeReadU32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
         | ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
}

// =====================================================================
//  Dnp3OutstationApp
// =====================================================================
TypeId Dnp3OutstationApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::Dnp3OutstationApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<Dnp3OutstationApp>()
        .AddTraceSource("Tx", "Packet sent",
            MakeTraceSourceAccessor(&Dnp3OutstationApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
Dnp3OutstationApp::Dnp3OutstationApp()
    : m_listenSock(nullptr), m_sessSock(nullptr),
      m_evtBuffer(0), m_pendingConfirm(false), m_armed(false),
      m_baseRate(DNP3_EVENT_RATE_NRM), m_basePay(DNP3_UNSOL_SZ),
      m_burstProb(0.03),
      m_evtRate(DNP3_EVENT_RATE_NRM), m_unsolSz(DNP3_UNSOL_SZ),
      m_unsolicitedEnabled(false), m_incidentActive(false),
      m_incidentReportsLeft(0), m_incidentRate(DNP3_EVENT_RATE_NRM),
      m_incidentUrgency("IMPORTANT"),
      m_incidentSemanticCategory("STATUS") {}
Dnp3OutstationApp::~Dnp3OutstationApp() {}
void Dnp3OutstationApp::Setup(std::string selfIp) { m_selfIp = selfIp; }
void Dnp3OutstationApp::SetBaseline(double baseRate, uint32_t basePay,
                                     double burstProb) {
    m_baseRate  = baseRate;
    m_basePay   = basePay;
    m_burstProb = burstProb;
    m_evtRate   = baseRate;
    m_unsolSz   = basePay;
}
void Dnp3OutstationApp::SetScenario(const std::string& sc) {
    auto m = GetScenarioMulPair("DNP3", sc);
    // intMul applies to 1/rate ⇒ rate scales by 1/intMul.
    m_evtRate = m_baseRate / m.first;
    m_unsolSz = (uint32_t)std::max(1.0, m_basePay * m.second);
    Simulator::Cancel(m_evtEv);
    if (m_sessSock && m_armed && m_unsolicitedEnabled && m_incidentActive) {
        ScheduleNextEvent();
    }
}
void Dnp3OutstationApp::Arm() {
    if (m_armed) return;
    m_armed = true;
    if (m_sessSock && m_unsolicitedEnabled && m_incidentActive) {
        ScheduleNextEvent();
    }
}
void Dnp3OutstationApp::SetUnsolicitedEnabled(bool enabled) {
    m_unsolicitedEnabled = enabled;
    if (!enabled) {
        Simulator::Cancel(m_evtEv);
        EndIncident();
    }
}
void Dnp3OutstationApp::TriggerIncident(double duration, double rate,
                                        uint32_t reports, std::string urgency,
                                        std::string semanticCategory) {
    if (!m_unsolicitedEnabled || reports == 0) return;
    m_incidentActive = true;
    m_incidentReportsLeft = reports;
    m_incidentRate = std::max(0.1, rate);
    m_incidentUrgency = urgency;
    m_incidentSemanticCategory = semanticCategory;
    m_evtBuffer = DNP3_UNSOL_THRESH - 1;
    Simulator::Cancel(m_evtEv);
    Simulator::Cancel(m_incidentEndEv);
    if (m_sessSock && m_armed && !m_pendingConfirm) {
        m_evtEv = Simulator::Schedule(MilliSeconds(10),
            &Dnp3OutstationApp::GenerateEvent, this);
    }
    m_incidentEndEv = Simulator::Schedule(Seconds(duration),
        &Dnp3OutstationApp::EndIncident, this);
}
void Dnp3OutstationApp::StartApplication() {
    m_rng  = CreateObject<ExponentialRandomVariable>();
    m_rngU = CreateObject<UniformRandomVariable>();
    m_listenSock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listenSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), PORT_DNP3));
    m_listenSock->Listen();
    m_listenSock->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&Dnp3OutstationApp::OnAccept, this));
}
void Dnp3OutstationApp::StopApplication() {
    if (m_listenSock) { m_listenSock->Close(); m_listenSock = nullptr; }
    if (m_sessSock)   { m_sessSock->Close();   m_sessSock = nullptr; }
    Simulator::Cancel(m_evtEv);
    Simulator::Cancel(m_incidentEndEv);
}
void Dnp3OutstationApp::OnAccept(Ptr<Socket> ns, const Address&) {
    m_sessSock = ns;
    m_sessSock->SetRecvCallback(MakeCallback(&Dnp3OutstationApp::OnRecv, this));
    if (m_armed && m_unsolicitedEnabled && m_incidentActive) {
        ScheduleNextEvent();
    }
}
void Dnp3OutstationApp::OnRecv(Ptr<Socket> sock) {
    if (!m_sessSock) return;
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t n = p->GetSize();
        if (n == 0) continue;
        size_t off = m_rxBytes.size();
        m_rxBytes.resize(off + n);
        p->CopyData(m_rxBytes.data() + off, n);
    }

    // Length-prefixed framing: [type(1)][len(4)][payload(len)].
    // Read the 5-byte header, then consume exactly len payload bytes. This is
    // immune to poll/confirm interleaving regardless of TCP segmentation.
    while (m_rxBytes.size() >= DNP3_HDR_SZ) {
        uint8_t  type = m_rxBytes[0];
        uint32_t len  = BeReadU32(&m_rxBytes[1]);
        if (m_rxBytes.size() < DNP3_HDR_SZ + len) break;        // wait for full frame
        m_rxBytes.erase(m_rxBytes.begin(),
                        m_rxBytes.begin() + DNP3_HDR_SZ + len);

        if (type == DNP3_T_CONFIRM) {
            // Master acknowledged our unsolicited response.
            m_pendingConfirm = false;
            if (m_incidentActive && m_incidentReportsLeft > 0) {
                --m_incidentReportsLeft;
                if (m_incidentReportsLeft == 0) {
                    EndIncident();
                } else {
                    ScheduleNextEvent();
                }
            } else if (m_evtBuffer >= DNP3_UNSOL_THRESH) {
                Simulator::Schedule(MilliSeconds(10),
                    &Dnp3OutstationApp::SendUnsolicited, this);
            }
        } else if (type == DNP3_T_POLL) {
            // Integrity poll -> Class-0 response.  So data point thay doi tung
            // lan tra loi, nen kich thuoc trai rong va trum len kich thuoc cua
            // response su kien.
            double payScale = static_cast<double>(m_basePay) / DNP3_UNSOL_SZ;
            uint32_t sz = static_cast<uint32_t>(std::max(1.0,
                (DNP3_APP_HDR_SZ + ObjectCount(DNP3_C0_POINT_MIN,
                                           DNP3_C0_POINT_MAX) * DNP3_POINT_SZ)
                * payScale));
            SendFrame(DNP3_T_RESP, sz, "NORMAL", "TELEMETRY");
        }
        // any other type is ignored on the outstation
    }
}
void Dnp3OutstationApp::GenerateEvent() {
    if (!m_unsolicitedEnabled || !m_incidentActive ||
        m_incidentReportsLeft == 0) {
        EndIncident();
        return;
    }
    // Phase 2: per-instance burst probability — emit 3-8 events in quick
    // succession to model state-change cascades.
    if (m_burstProb > 0 && m_rngU->GetValue() < m_burstProb) {
        int n = 3 + (int)(m_rngU->GetValue() * 6.0);    // 3..8
        for (int i = 1; i < n; ++i) {
            double gap_ms = 10.0 + m_rngU->GetValue() * 40.0;   // 10-50ms
            Simulator::Schedule(MilliSeconds((uint32_t)(gap_ms * i)),
                &Dnp3OutstationApp::GenerateBurst, this);
        }
    }
    m_evtBuffer++;
    if (!m_pendingConfirm && m_evtBuffer >= DNP3_UNSOL_THRESH) SendUnsolicited();
    if (!m_pendingConfirm && m_incidentActive) ScheduleNextEvent();
}
void Dnp3OutstationApp::GenerateBurst() {
    if (!m_unsolicitedEnabled || !m_incidentActive) return;
    m_evtBuffer++;
    if (!m_pendingConfirm && m_evtBuffer >= DNP3_UNSOL_THRESH) SendUnsolicited();
}
void Dnp3OutstationApp::ScheduleNextEvent() {
    if (!m_sessSock || !m_unsolicitedEnabled || !m_incidentActive ||
        m_incidentReportsLeft == 0 || m_pendingConfirm) return;
    double liveRate = (m_incidentRate > 0) ? m_incidentRate : m_evtRate;
    double mean = (liveRate > 0) ? (1.0 / liveRate) : 10.0;
    m_rng->SetAttribute("Mean", DoubleValue(JitteredInterval(mean)));
    m_evtEv = Simulator::Schedule(Seconds(m_rng->GetValue()),
        &Dnp3OutstationApp::GenerateEvent, this);
}
void Dnp3OutstationApp::SendUnsolicited() {
    if (!m_sessSock || !m_incidentActive || m_incidentReportsLeft == 0) return;
    m_evtBuffer      = 0;
    m_pendingConfirm = true;       // wait for the master's app-layer confirm
    // Cung mo hinh so point nhu Class-0 response, chi khac moi point co them
    // nhan thoi gian va so point it hon.  Khong con he so theo muc khan cap.
    double payScale = static_cast<double>(m_basePay) / DNP3_UNSOL_SZ;
    uint32_t eventSize = static_cast<uint32_t>(std::max(1.0,
        (DNP3_APP_HDR_SZ + ObjectCount(DNP3_EVT_POINT_MIN,
                                   DNP3_EVT_POINT_MAX) * DNP3_EVT_POINT_SZ)
        * payScale * ServicePayloadScale(m_incidentUrgency)));
    SendFrame(DNP3_T_UNSOL, eventSize, m_incidentUrgency, "EVENT",
              m_incidentSemanticCategory);
}
void Dnp3OutstationApp::EndIncident() {
    m_incidentActive = false;
    m_incidentReportsLeft = 0;
    m_evtBuffer = 0;
    m_pendingConfirm = false;
    Simulator::Cancel(m_evtEv);
    Simulator::Cancel(m_incidentEndEv);
}
void Dnp3OutstationApp::SendFrame(uint8_t type, uint32_t payloadLen,
                                  const std::string& urgency,
                                  const std::string& kind,
                                  const std::string& semanticCategory) {
    if (!m_sessSock) return;
    std::vector<uint8_t> buf(DNP3_HDR_SZ + payloadLen, 0);
    buf[0] = type;
    BeWriteU32(&buf[1], payloadLen);
    Ptr<Packet> p = Create<Packet>(buf.data(), (uint32_t)buf.size());
    SetScadaMessageMetadata(p, urgency, kind, semanticCategory);
    m_tx(p);
    m_sessSock->SetIpTos(LabelToTos("DNP3", g_scenario));
    m_sessSock->Send(p);
}
NS_OBJECT_ENSURE_REGISTERED(Dnp3OutstationApp);

// =====================================================================
//  Dnp3MasterApp
// =====================================================================
TypeId Dnp3MasterApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::Dnp3MasterApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<Dnp3MasterApp>()
        .AddTraceSource("Tx", "Request sent",
            MakeTraceSourceAccessor(&Dnp3MasterApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
Dnp3MasterApp::Dnp3MasterApp()
    : m_pollInt(DNP3_POLL_INT), m_pollEnabled(true), m_waitingPollResp(false),
      m_conn(false), m_run(false) {}
Dnp3MasterApp::~Dnp3MasterApp() {}
void Dnp3MasterApp::Setup(Address peer, std::string masterIp) {
    m_peer = peer; m_masterIp = masterIp;
}
void Dnp3MasterApp::SetPollingEnabled(bool enabled) {
    m_pollEnabled = enabled;
    if (!enabled) {
        Simulator::Cancel(m_pollEv);
        Simulator::Cancel(m_timeoutEv);
        m_waitingPollResp = false;
    }
}
void Dnp3MasterApp::SetScenario(const std::string& sc) {
    m_pollInt = (sc == "emergency") ? 0.1 : DNP3_POLL_INT;
    // Unsolicited size is no longer guessed: the length-prefixed header lets
    // the master accept whatever size the outstation sends.
}
void Dnp3MasterApp::StartApplication() {
    m_run = true;
    m_sock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_sock->SetIpTos(LabelToTos("DNP3", "normal"));
    m_sock->Bind();
    m_sock->Connect(m_peer);
    m_sock->SetConnectCallback(
        MakeCallback(&Dnp3MasterApp::OnConn, this),
        MakeCallback(&Dnp3MasterApp::OnFail, this));
    m_sock->SetRecvCallback(MakeCallback(&Dnp3MasterApp::OnRecv, this));
}
void Dnp3MasterApp::StopApplication() {
    m_run = false;
    Simulator::Cancel(m_pollEv);
    Simulator::Cancel(m_timeoutEv);
    if (m_sock) m_sock->Close();
}
void Dnp3MasterApp::OnConn(Ptr<Socket>) {
    m_conn = true;
    if (m_pollEnabled) Poll();
}
void Dnp3MasterApp::OnFail(Ptr<Socket>) { m_conn = false; }
void Dnp3MasterApp::Poll() {
    if (!m_run || !m_conn || !m_pollEnabled) return;
    SendFrame(DNP3_T_POLL, DNP3_POLL_SZ);
    m_waitingPollResp = true;
    Simulator::Cancel(m_timeoutEv);
    m_timeoutEv = Simulator::Schedule(Seconds(DNP3_TIMEOUT),
        &Dnp3MasterApp::OnTimeout, this);
}
void Dnp3MasterApp::OnRecv(Ptr<Socket> sock) {
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t n = p->GetSize();
        if (n == 0) continue;
        size_t off = m_rxBytes.size();
        m_rxBytes.resize(off + n);
        p->CopyData(m_rxBytes.data() + off, n);
    }

    // Length-prefixed framing: the Type field disambiguates a Class-0
    // poll-response from an unsolicited response no matter how they interleave,
    // and the Length field lets the master accept any unsolicited size.
    while (m_rxBytes.size() >= DNP3_HDR_SZ) {
        uint8_t  type = m_rxBytes[0];
        uint32_t len  = BeReadU32(&m_rxBytes[1]);
        if (m_rxBytes.size() < DNP3_HDR_SZ + len) break;        // wait for full frame
        m_rxBytes.erase(m_rxBytes.begin(),
                        m_rxBytes.begin() + DNP3_HDR_SZ + len);

        if (type == DNP3_T_RESP) {
            // Class-0 response to our integrity poll.
            if (m_waitingPollResp) {
                m_waitingPollResp = false;
                Simulator::Cancel(m_timeoutEv);
                if (m_run && m_conn && m_pollEnabled) {
                    m_pollEv = Simulator::Schedule(Seconds(m_pollInt),
                        &Dnp3MasterApp::Poll, this);
                }
            }
        } else if (type == DNP3_T_UNSOL) {
            // Unsolicited response -> application-layer confirm.
            SendFrame(DNP3_T_CONFIRM, DNP3_CONFIRM_SZ);
        }
        // other types ignored on the master
    }
}
void Dnp3MasterApp::SendFrame(uint8_t type, uint32_t payloadLen) {
    if (!m_sock) return;
    std::vector<uint8_t> buf(DNP3_HDR_SZ + payloadLen, 0);
    buf[0] = type;
    BeWriteU32(&buf[1], payloadLen);
    Ptr<Packet> p = Create<Packet>(buf.data(), (uint32_t)buf.size());
    m_tx(p);
    m_sock->Send(p);   // socket TOS set at start / RestampTos handles DiffServ
}
void Dnp3MasterApp::OnTimeout() {
    // A3: Class-0 response presumed lost — re-poll.
    if (m_waitingPollResp && m_run && m_conn && m_pollEnabled) {
        m_waitingPollResp = false;
        m_pollEv = Simulator::Schedule(Seconds(m_pollInt),
            &Dnp3MasterApp::Poll, this);
    }
}
NS_OBJECT_ENSURE_REGISTERED(Dnp3MasterApp);

// =====================================================================
//  Iec104ControlledApp  (controlled station / RTU, server)
//  ---------------------------------------------------------------------
//  Length-prefixed framing ([type][len]) distinguishes I / S / U(STARTDT,
//  TESTFR) frames unambiguously when they interleave on the TCP stream.
//  Standard mechanisms modelled: STARTDT handshake, w (ack after w I-frames)
//  and t2 (ack remainder on timeout), k (stop sending at k unacked I-frames)
//  with t1 (close if a sent I-frame is not acked in time), t3 (idle TESTFR),
//  and General Interrogation response bursts.
// =====================================================================
TypeId Iec104ControlledApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::Iec104ControlledApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<Iec104ControlledApp>()
        .AddTraceSource("Tx", "Frame sent",
            MakeTraceSourceAccessor(&Iec104ControlledApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
Iec104ControlledApp::Iec104ControlledApp()
    : m_listen(nullptr), m_sess(nullptr),
      m_state(STOPPED),
      m_ssn(0), m_rsn(0), m_acked(0), m_rxSinceAck(0), m_armed(false),
      m_periodicEnabled(true), m_eventEnabled(false),
      m_baseInt(IEC_INT_NRM), m_iframeInt(IEC_INT_NRM),
      m_baseEventRate(0.0), m_eventRate(0.0),
      m_incidentActive(false), m_incidentWaitingAck(false),
      m_incidentReportsLeft(0), m_incidentRate(0.0),
      m_incidentUrgency("IMPORTANT"),
      m_incidentSemanticCategory("STATUS") {}
Iec104ControlledApp::~Iec104ControlledApp() {}
void Iec104ControlledApp::Setup(std::string selfIp) { m_selfIp = selfIp; }
void Iec104ControlledApp::SetBaseline(double baseInt) {
    m_baseInt   = baseInt;
    m_iframeInt = baseInt;
}
void Iec104ControlledApp::SetScenario(const std::string& sc) {
    auto m = GetScenarioMulPair("IEC104", sc);
    m_iframeInt = m_baseInt * m.first;
    m_eventRate = (m.first > 0.0) ? m_baseEventRate / m.first : m_baseEventRate;
    if (m_eventEnabled && m_armed && m_state == STARTED && m_incidentActive) {
        Simulator::Cancel(m_eventEv);
        Simulator::Cancel(m_incidentEv);
        ScheduleNextEvent();
    }
}
void Iec104ControlledApp::SetPeriodicEnabled(bool enabled) {
    m_periodicEnabled = enabled;
    if (!enabled) Simulator::Cancel(m_iEv);
}
void Iec104ControlledApp::SetEventModel(bool enabled, double baseRate) {
    m_eventEnabled = enabled;
    m_baseEventRate = baseRate;
    m_eventRate = baseRate;
    if (!enabled) {
        Simulator::Cancel(m_eventEv);
        EndIncident();
    }
}
void Iec104ControlledApp::TriggerIncident(double duration, double rate,
                                           uint32_t reports,
                                           std::string urgency,
                                           std::string semanticCategory) {
    if (!m_eventEnabled || reports == 0) return;
    m_incidentActive = true;
    m_incidentWaitingAck = false;
    m_incidentReportsLeft = reports;
    m_incidentRate = std::max(0.1, rate);
    m_incidentUrgency = urgency;
    m_incidentSemanticCategory = semanticCategory;
    Simulator::Cancel(m_eventEv);
    Simulator::Cancel(m_incidentEv);
    Simulator::Cancel(m_incidentEndEv);
    if (m_armed && m_state == STARTED && m_sess) {
        m_incidentEv = Simulator::Schedule(MilliSeconds(10),
            &Iec104ControlledApp::SendIncidentFrame, this);
    }
    m_incidentEndEv = Simulator::Schedule(Seconds(duration),
        &Iec104ControlledApp::EndIncident, this);
}
void Iec104ControlledApp::Arm() {
    if (m_armed) return;
    m_armed = true;
    if (m_periodicEnabled && m_state == STARTED && !m_iEv.IsPending()) {
        m_iEv = Simulator::Schedule(Seconds(JitteredInterval(m_iframeInt)),
            &Iec104ControlledApp::SendIFrame, this);
    }
    if (m_eventEnabled && m_state == STARTED && m_incidentActive &&
        !m_eventEv.IsPending() && !m_incidentEv.IsPending()) {
        ScheduleIncidentFrame();
    }
}
void Iec104ControlledApp::StartApplication() {
    m_listen = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), PORT_IEC104));
    m_listen->Listen();
    m_listen->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&Iec104ControlledApp::OnAccept, this));
}
void Iec104ControlledApp::StopApplication() {
    Simulator::Cancel(m_iEv);
    Simulator::Cancel(m_eventEv);
    Simulator::Cancel(m_incidentEv);
    Simulator::Cancel(m_incidentEndEv);
    Simulator::Cancel(m_t1Ev);
    Simulator::Cancel(m_t2Ev);
    Simulator::Cancel(m_t3Ev);
    if (m_listen) { m_listen->Close(); m_listen = nullptr; }
    if (m_sess)   { m_sess->Close();   m_sess = nullptr; }
    m_state = STOPPED;
}
void Iec104ControlledApp::OnAccept(Ptr<Socket> ns, const Address&) {
    m_sess = ns;
    m_state = STOPPED;
    m_rxBytes.clear();
    m_ssn = m_rsn = m_acked = m_rxSinceAck = 0;
    m_sess->SetRecvCallback(MakeCallback(&Iec104ControlledApp::OnRecv, this));
}
void Iec104ControlledApp::OnRecv(Ptr<Socket> sock) {
    if (!m_sess) return;
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t n = p->GetSize();
        if (n == 0) continue;
        size_t off = m_rxBytes.size();
        m_rxBytes.resize(off + n);
        p->CopyData(m_rxBytes.data() + off, n);
    }
    while (m_rxBytes.size() >= IEC_HDR_SZ) {
        uint8_t  type = m_rxBytes[0];
        uint32_t len  = BeReadU32(&m_rxBytes[1]);
        if (m_rxBytes.size() < IEC_HDR_SZ + len) break;
        m_rxBytes.erase(m_rxBytes.begin(), m_rxBytes.begin() + IEC_HDR_SZ + len);

        switch (type) {
        case IEC_T_STARTDT_ACT:
            m_state = STARTED;
            SendFrame(IEC_T_STARTDT_CON, IEC_UFRAME_SZ);
            if (m_periodicEnabled && m_armed && !m_iEv.IsPending()) {
                m_iEv = Simulator::Schedule(Seconds(JitteredInterval(m_iframeInt)),
                    &Iec104ControlledApp::SendIFrame, this);
            }
            if (m_eventEnabled && m_armed && m_incidentActive &&
                !m_eventEv.IsPending() && !m_incidentEv.IsPending()) {
                ScheduleIncidentFrame();
            }
            RearmT3();
            break;
        case IEC_T_TESTFR_ACT:
            SendFrame(IEC_T_TESTFR_CON, IEC_UFRAME_SZ);
            RearmT3();
            break;
        case IEC_T_TESTFR_CON:
            RearmT3();
            break;
        case IEC_T_S:
            NoteAck();                 // S-frame acknowledges our sent I-frames
            RearmT3();
            break;
        case IEC_T_I:
            NoteAck();                 // I-frame piggybacks an ack of our I-frames
            NoteIFrameReceived();      // a command in the control direction
            RearmT3();
            break;
        case IEC_T_GI:
            NoteAck();
            NoteIFrameReceived();
            SendGiResponse();          // answer General Interrogation with a burst
            RearmT3();
            break;
        default:
            break;
        }
    }
}
void Iec104ControlledApp::SendIFrame() {
    if (m_state != STARTED || !m_sess) return;
    // k flow control: only transmit while fewer than k I-frames are unacked.
    if ((m_ssn - m_acked) < IEC_K) {
        SendFrame(IEC_T_I, IecCyclicSize(), "NORMAL", "TELEMETRY");
        m_ssn++;
        ArmT1();
    }
    m_iEv = Simulator::Schedule(Seconds(JitteredInterval(m_iframeInt)),
        &Iec104ControlledApp::SendIFrame, this);
}
void Iec104ControlledApp::ScheduleNextEvent() {
    if (!m_eventEnabled || !m_incidentActive ||
        m_state != STARTED || !m_sess) return;
    if (!m_eventRng) m_eventRng = CreateObject<ExponentialRandomVariable>();
    double liveRate = (m_incidentRate > 0.0) ? m_incidentRate : m_eventRate;
    double mean = (liveRate > 0.0) ? (1.0 / liveRate) : 60.0;
    m_eventRng->SetAttribute("Mean", DoubleValue(JitteredInterval(mean)));
        m_incidentEv = Simulator::Schedule(Seconds(m_eventRng->GetValue()),
        &Iec104ControlledApp::SendIncidentFrame, this);
}
void Iec104ControlledApp::SendEventFrame() {
    if (m_state != STARTED || !m_sess) return;
    if ((m_ssn - m_acked) < IEC_K) {
        SendFrame(IEC_T_I, IecCyclicSize(), "NORMAL", "TELEMETRY");
        m_ssn++;
        ArmT1();
    }
    ScheduleNextEvent();
}
void Iec104ControlledApp::ScheduleIncidentFrame() {
    if (!m_eventEnabled || !m_incidentActive ||
        m_incidentReportsLeft == 0 || m_incidentWaitingAck ||
        m_state != STARTED || !m_sess) return;
    ScheduleNextEvent();
}
void Iec104ControlledApp::SendIncidentFrame() {
    if (!m_eventEnabled || !m_incidentActive ||
        m_incidentReportsLeft == 0 || m_state != STARTED || !m_sess) {
        EndIncident();
        return;
    }
    if ((m_ssn - m_acked) < IEC_K) {
        uint32_t serviceSize = static_cast<uint32_t>(std::max(
            1.0, IecEventSize() * ServicePayloadScale(m_incidentUrgency)));
        SendFrame(IEC_T_I, serviceSize, m_incidentUrgency, "EVENT",
                  m_incidentSemanticCategory);
        m_ssn++;
        m_incidentWaitingAck = true;
        ArmT1();
    } else {
        ScheduleIncidentFrame();
    }
}
void Iec104ControlledApp::EndIncident() {
    m_incidentActive = false;
    m_incidentWaitingAck = false;
    m_incidentReportsLeft = 0;
    Simulator::Cancel(m_eventEv);
    Simulator::Cancel(m_incidentEv);
    Simulator::Cancel(m_incidentEndEv);
}
void Iec104ControlledApp::SendGiResponse() {
    // General Interrogation response: a burst of monitor I-frames.
    for (uint32_t i = 0; i < IEC_GI_COUNT; ++i) {
        SendFrame(IEC_T_I, IecCyclicSize(), "NORMAL", "TELEMETRY");
        m_ssn++;
    }
    ArmT1();
}
void Iec104ControlledApp::SendFrame(uint8_t type, uint32_t payloadLen,
                                    const std::string& urgency,
                                    const std::string& kind,
                                    const std::string& semanticCategory) {
    if (!m_sess) return;
    std::vector<uint8_t> buf(IEC_HDR_SZ + payloadLen, 0);
    buf[0] = type;
    BeWriteU32(&buf[1], payloadLen);
    Ptr<Packet> p = Create<Packet>(buf.data(), (uint32_t)buf.size());
    SetScadaMessageMetadata(p, urgency, kind, semanticCategory);
    m_tx(p);
    m_sess->SetIpTos(LabelToTos("IEC104", g_scenario));
    m_sess->Send(p);
}
void Iec104ControlledApp::SendTestfr() {
    if (m_state != STARTED || !m_sess) return;
    SendFrame(IEC_T_TESTFR_ACT, IEC_UFRAME_SZ);
    m_t3Ev = Simulator::Schedule(Seconds(IEC_T3),
        &Iec104ControlledApp::SendTestfr, this);
}
void Iec104ControlledApp::NoteAck() {
    m_acked = m_ssn;                   // abstraction: an ack catches up all outstanding
    Simulator::Cancel(m_t1Ev);
    if (m_incidentActive && m_incidentWaitingAck) {
        m_incidentWaitingAck = false;
        if (m_incidentReportsLeft > 0) --m_incidentReportsLeft;
        if (m_incidentReportsLeft == 0) {
            EndIncident();
        } else {
            ScheduleIncidentFrame();
        }
    }
}
void Iec104ControlledApp::NoteIFrameReceived() {
    m_rsn++;
    m_rxSinceAck++;
    if (m_rxSinceAck >= IEC_W) {
        SendFrame(IEC_T_S, IEC_SFRAME_SZ);   // w reached -> S-frame ack
        m_rxSinceAck = 0;
        Simulator::Cancel(m_t2Ev);
    } else if (!m_t2Ev.IsPending()) {
        m_t2Ev = Simulator::Schedule(Seconds(IEC_T2),
            &Iec104ControlledApp::OnT2Timeout, this);
    }
}
void Iec104ControlledApp::ArmT1() {
    if (!m_t1Ev.IsPending() && (m_ssn - m_acked) > 0) {
        m_t1Ev = Simulator::Schedule(Seconds(IEC_T1),
            &Iec104ControlledApp::OnT1Timeout, this);
    }
}
void Iec104ControlledApp::RearmT3() {
    Simulator::Cancel(m_t3Ev);
    m_t3Ev = Simulator::Schedule(Seconds(IEC_T3),
        &Iec104ControlledApp::SendTestfr, this);
}
void Iec104ControlledApp::OnT1Timeout() {
    if ((m_ssn - m_acked) > 0) {       // unacked I-frame past t1 -> terminate
        Simulator::Cancel(m_iEv);
        Simulator::Cancel(m_eventEv);
        Simulator::Cancel(m_t2Ev);
        Simulator::Cancel(m_t3Ev);
        if (m_sess) { m_sess->Close(); m_sess = nullptr; }
        m_state = STOPPED;
    }
}
void Iec104ControlledApp::OnT2Timeout() {
    if (m_rxSinceAck > 0) {
        SendFrame(IEC_T_S, IEC_SFRAME_SZ);
        m_rxSinceAck = 0;
    }
}
NS_OBJECT_ENSURE_REGISTERED(Iec104ControlledApp);

// =====================================================================
//  Iec104ControllingApp  (controlling station / master, client)
//  ---------------------------------------------------------------------
//  Opens the connection, drives STARTDT, then issues command I-frames
//  (control direction) plus a periodic General Interrogation. Same k/w/
//  t1/t2/t3 mechanisms and length-prefixed framing as the controlled side.
// =====================================================================
TypeId Iec104ControllingApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::Iec104ControllingApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<Iec104ControllingApp>()
        .AddTraceSource("Tx", "Frame sent",
            MakeTraceSourceAccessor(&Iec104ControllingApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
Iec104ControllingApp::Iec104ControllingApp()
    : m_ssn(0), m_rsn(0), m_acked(0), m_rxSinceAck(0),
      m_cmdInt(IEC_CMD_INT_NRM),
      m_conn(false), m_run(false), m_started(false) {}
Iec104ControllingApp::~Iec104ControllingApp() {}
void Iec104ControllingApp::Setup(Address peer, std::string masterIp) {
    m_peer = peer; m_masterIp = masterIp;
}
void Iec104ControllingApp::SetScenario(const std::string& sc) {
    if      (sc == "normal")    m_cmdInt = IEC_CMD_INT_NRM;
    else if (sc == "high_load") m_cmdInt = IEC_CMD_INT_HLD;
    else                        m_cmdInt = IEC_CMD_INT_EMR;
}
void Iec104ControllingApp::StartApplication() {
    m_run = true;
    m_sock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_sock->SetIpTos(LabelToTos("IEC104", "normal"));
    m_sock->Bind();
    m_sock->Connect(m_peer);
    m_sock->SetConnectCallback(
        MakeCallback(&Iec104ControllingApp::OnConn, this),
        MakeCallback(&Iec104ControllingApp::OnFail, this));
    m_sock->SetRecvCallback(MakeCallback(&Iec104ControllingApp::OnRecv, this));
}
void Iec104ControllingApp::StopApplication() {
    m_run = false;
    Simulator::Cancel(m_ev);
    Simulator::Cancel(m_giEv);
    Simulator::Cancel(m_t1Ev);
    Simulator::Cancel(m_t2Ev);
    Simulator::Cancel(m_t3Ev);
    if (m_sock) m_sock->Close();
}
void Iec104ControllingApp::OnConn(Ptr<Socket>) {
    m_conn = true;
    SendFrame(IEC_T_STARTDT_ACT, IEC_UFRAME_SZ);   // begin data transfer
    RearmT3();
}
void Iec104ControllingApp::OnFail(Ptr<Socket>) { m_conn = false; }
void Iec104ControllingApp::OnRecv(Ptr<Socket> sock) {
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t n = p->GetSize();
        if (n == 0) continue;
        size_t off = m_rxBytes.size();
        m_rxBytes.resize(off + n);
        p->CopyData(m_rxBytes.data() + off, n);
    }
    while (m_rxBytes.size() >= IEC_HDR_SZ) {
        uint8_t  type = m_rxBytes[0];
        uint32_t len  = BeReadU32(&m_rxBytes[1]);
        if (m_rxBytes.size() < IEC_HDR_SZ + len) break;
        m_rxBytes.erase(m_rxBytes.begin(), m_rxBytes.begin() + IEC_HDR_SZ + len);

        switch (type) {
        case IEC_T_STARTDT_CON:
            if (!m_started) {
                m_started = true;
                m_ev = Simulator::Schedule(Seconds(m_cmdInt),
                    &Iec104ControllingApp::SendIFrame, this);
                SendGi();              // initial General Interrogation (+ schedules periodic)
            }
            RearmT3();
            break;
        case IEC_T_TESTFR_ACT:
            SendFrame(IEC_T_TESTFR_CON, IEC_UFRAME_SZ);
            RearmT3();
            break;
        case IEC_T_TESTFR_CON:
            RearmT3();
            break;
        case IEC_T_S:
            NoteAck();                 // RTU acknowledged our command I-frames
            RearmT3();
            break;
        case IEC_T_I:
            NoteAck();                 // piggyback ack
            NoteIFrameReceived();      // monitor data from the RTU
            SendFrame(IEC_T_S, IEC_SFRAME_SZ);  // master processed/acknowledged event
            m_rxSinceAck = 0;
            Simulator::Cancel(m_t2Ev);
            RearmT3();
            break;
        default:
            break;
        }
    }
}
void Iec104ControllingApp::SendIFrame() {
    if (!m_conn || !m_run) return;
    if ((m_ssn - m_acked) < IEC_K) {   // k flow control
        SendFrame(IEC_T_I, IEC_IFRAME_SZ);
        m_ssn++;
        ArmT1();
    }
    m_ev = Simulator::Schedule(Seconds(m_cmdInt),
        &Iec104ControllingApp::SendIFrame, this);
}
void Iec104ControllingApp::SendGi() {
    if (!m_conn || !m_run) return;
    SendFrame(IEC_T_GI, IEC_IFRAME_SZ);   // C_IC general interrogation (an I-frame)
    m_ssn++;
    ArmT1();
    m_giEv = Simulator::Schedule(Seconds(IEC_GI_INT),
        &Iec104ControllingApp::SendGi, this);
}
void Iec104ControllingApp::SendFrame(uint8_t type, uint32_t payloadLen) {
    if (!m_sock) return;
    std::vector<uint8_t> buf(IEC_HDR_SZ + payloadLen, 0);
    buf[0] = type;
    BeWriteU32(&buf[1], payloadLen);
    Ptr<Packet> p = Create<Packet>(buf.data(), (uint32_t)buf.size());
    m_tx(p);
    m_sock->Send(p);   // socket TOS set at start / RestampTos handles DiffServ
}
void Iec104ControllingApp::SendTestfr() {
    if (!m_conn || !m_run) return;
    SendFrame(IEC_T_TESTFR_ACT, IEC_UFRAME_SZ);
    m_t3Ev = Simulator::Schedule(Seconds(IEC_T3),
        &Iec104ControllingApp::SendTestfr, this);
}
void Iec104ControllingApp::NoteAck() {
    m_acked = m_ssn;
    Simulator::Cancel(m_t1Ev);
}
void Iec104ControllingApp::NoteIFrameReceived() {
    m_rsn++;
    m_rxSinceAck++;
    if (m_rxSinceAck >= IEC_W) {
        SendFrame(IEC_T_S, IEC_SFRAME_SZ);
        m_rxSinceAck = 0;
        Simulator::Cancel(m_t2Ev);
    } else if (!m_t2Ev.IsPending()) {
        m_t2Ev = Simulator::Schedule(Seconds(IEC_T2),
            &Iec104ControllingApp::OnT2Timeout, this);
    }
}
void Iec104ControllingApp::ArmT1() {
    if (!m_t1Ev.IsPending() && (m_ssn - m_acked) > 0) {
        m_t1Ev = Simulator::Schedule(Seconds(IEC_T1),
            &Iec104ControllingApp::OnT1Timeout, this);
    }
}
void Iec104ControllingApp::RearmT3() {
    Simulator::Cancel(m_t3Ev);
    m_t3Ev = Simulator::Schedule(Seconds(IEC_T3),
        &Iec104ControllingApp::SendTestfr, this);
}
void Iec104ControllingApp::OnT1Timeout() {
    if ((m_ssn - m_acked) > 0) {
        m_conn = false;
        Simulator::Cancel(m_ev);
        Simulator::Cancel(m_giEv);
        Simulator::Cancel(m_t2Ev);
        Simulator::Cancel(m_t3Ev);
        if (m_sock) { m_sock->Close(); }
    }
}
void Iec104ControllingApp::OnT2Timeout() {
    if (m_rxSinceAck > 0) {
        SendFrame(IEC_T_S, IEC_SFRAME_SZ);
        m_rxSinceAck = 0;
    }
}
NS_OBJECT_ENSURE_REGISTERED(Iec104ControllingApp);

// =====================================================================
//  OpcUaServerApp
// =====================================================================
TypeId OpcUaServerApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::OpcUaServerApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<OpcUaServerApp>()
        .AddTraceSource("Tx", "Message sent",
            MakeTraceSourceAccessor(&OpcUaServerApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
OpcUaServerApp::OpcUaServerApp()
    : m_listen(nullptr), m_sess(nullptr),
      m_state(IDLE),
      m_baseInt(OPC_PUB_INT_NRM), m_basePay(OPC_PUB_NRM),
      m_pubSz(OPC_PUB_NRM), m_pubInt(OPC_PUB_INT_NRM), m_pubTokens(0),
      m_alarmActive(false), m_alarmReady(false),
      m_alarmReportsLeft(0), m_alarmRate(0.0),
      m_incidentUrgency("IMPORTANT"),
      m_incidentSemanticCategory("ALARM") {}
OpcUaServerApp::~OpcUaServerApp() {}
void OpcUaServerApp::Setup(std::string selfIp) { m_selfIp = selfIp; }
void OpcUaServerApp::SetBaseline(double baseInt, uint32_t basePay) {
    m_baseInt = baseInt; m_basePay = basePay;
    m_pubInt  = baseInt;                 // per-device PublishingInterval (rate diversity)
    m_pubSz   = std::max(32u, basePay);  // per-device DataChangeNotification payload
}
void OpcUaServerApp::SetScenario(const std::string& sc) {
    auto m = GetScenarioMulPair("OPC-UA", sc);
    m_pubInt = m_baseInt * m.first;                       // per-device rate diversity
    if (sc == "high_load")
        m_pubInt = std::min(m_pubInt, OPC_PUB_INT_HLD);  // documented fast ceiling
    m_pubSz = std::max(32u, static_cast<uint32_t>(
        std::lround(static_cast<double>(m_basePay) * m.second)));
    if (m_state == RUNNING) {
        Simulator::Cancel(m_pubEv);
        m_pubEv = Simulator::Schedule(Seconds(JitteredInterval(m_pubInt)),
            &OpcUaServerApp::SendPublish, this);
    }
}
void OpcUaServerApp::TriggerIncident(double duration, double rate,
                                     uint32_t reports, std::string urgency,
                                     std::string semanticCategory) {
    if (reports == 0) return;
    m_alarmActive = true;
    m_alarmReady = false;
    m_alarmReportsLeft = reports;
    m_alarmRate = std::max(0.1, rate);
    m_incidentUrgency = urgency;
    m_incidentSemanticCategory = semanticCategory;
    Simulator::Cancel(m_alarmEv);
    Simulator::Cancel(m_alarmEndEv);
    if (m_state == RUNNING && m_sess) {
        m_alarmEv = Simulator::Schedule(MilliSeconds(10),
            &OpcUaServerApp::SendAlarmPublish, this);
    }
    m_alarmEndEv = Simulator::Schedule(Seconds(duration),
        &OpcUaServerApp::EndIncident, this);
}
void OpcUaServerApp::StartApplication() {
    m_listen = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), PORT_OPCUA));
    m_listen->Listen();
    m_listen->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&OpcUaServerApp::OnAccept, this));
}
void OpcUaServerApp::StopApplication() {
    Simulator::Cancel(m_pubEv);
    Simulator::Cancel(m_alarmEv);
    Simulator::Cancel(m_alarmEndEv);
    if (m_listen) { m_listen->Close(); m_listen = nullptr; }
    if (m_sess)   { m_sess->Close();   m_sess = nullptr; }
    m_state = IDLE;
    m_pubTokens = 0;
    m_alarmActive = false;
    m_alarmReady = false;
    m_alarmReportsLeft = 0;
}
void OpcUaServerApp::OnAccept(Ptr<Socket> ns, const Address&) {
    m_sess       = ns;
    m_state      = IDLE;
    m_rxBytes.clear();
    m_pubTokens  = 0;
    m_sess->SetRecvCallback(MakeCallback(&OpcUaServerApp::OnRecv, this));
}
void OpcUaServerApp::OnRecv(Ptr<Socket> sock) {
    if (!m_sess) return;
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t size = p->GetSize();
        size_t offset = m_rxBytes.size();
        m_rxBytes.resize(offset + size);
        p->CopyData(m_rxBytes.data() + offset, size);
    }

    while (m_rxBytes.size() >= OPC_HDR_SZ) {
        uint8_t type = m_rxBytes[0];
        uint32_t payloadLen = BeReadU32(&m_rxBytes[1]);
        if (payloadLen > 1024 * 1024) {
            NS_LOG_WARN("Dropping malformed OPC-UA frame length=" << payloadLen);
            m_rxBytes.clear();
            return;
        }
        if (m_rxBytes.size() < OPC_HDR_SZ + payloadLen) break;
        m_rxBytes.erase(m_rxBytes.begin(),
                        m_rxBytes.begin() + OPC_HDR_SZ + payloadLen);

        switch (m_state) {
        case IDLE:
            if (type == OPC_T_HEL) {
                Send(OPC_T_ACK, OPC_ACK_SZ);
                m_state = WAIT_OPN;
            }
            break;
        case WAIT_OPN:
            if (type == OPC_T_OPN_REQ) {
                Send(OPC_T_OPN_RSP, OPC_OPN_RSP_SZ);
                m_state = WAIT_SESSION;
            }
            break;
        case WAIT_SESSION:
            if (type == OPC_T_CSES_REQ) {
                Send(OPC_T_CSES_RSP, OPC_CSES_RSP_SZ);
                m_state = SESSION_CREATED;
            }
            break;
        case SESSION_CREATED:
            if (type == OPC_T_ACTI_REQ) {
                Send(OPC_T_ACTI_RSP, OPC_ACTI_RSP_SZ);
                m_state = ACTIVE;
            }
            break;
        case ACTIVE:
            if (type == OPC_T_CSUB_REQ) {
                Send(OPC_T_CSUB_RSP, OPC_CSUB_RSP_SZ);
                m_state = SUBSCRIBED;
            }
            break;
        case SUBSCRIBED:
            if (type == OPC_T_CMI_REQ) {
                Send(OPC_T_CMI_RSP, OPC_CMI_RSP_SZ);
                m_state = RUNNING;
                m_pubEv = Simulator::Schedule(
                    Seconds(JitteredInterval(m_pubInt)),
                    &OpcUaServerApp::SendPublish, this);
                if (m_alarmActive && !m_alarmEv.IsPending()) {
                    ScheduleAlarmPublish();
                }
            }
            break;
        case RUNNING:
            if (type == OPC_T_PUB_REQ) {
                ++m_pubTokens;
                // A queued EventNotification is returned immediately when a
                // PublishRequest becomes available instead of waiting for the
                // next publishing cycle.
                TrySendAlarmPublish();
            } else if (type == OPC_T_READ_REQ) {
                Send(OPC_T_READ_RSP, OPC_READ_RSP_SZ);
            }
            break;
        }
    }
}
void OpcUaServerApp::SendPublish() {
    if (m_state != RUNNING || !m_sess) return;
    // Only deliver a NotificationMessage if the client has a PublishRequest
    // queued (real OPC UA publish flow control).  Otherwise skip this tick.
    if (m_pubTokens > 0) {
        if (m_alarmReady) {
            TrySendAlarmPublish();
        } else {
            --m_pubTokens;
            uint32_t unit = std::max(8u, m_pubSz / 6u);
            Send(OPC_T_PUB_RSP,
                 unit * ObjectCount(OPC_NOTIF_ITEM_MIN, OPC_NOTIF_ITEM_MAX),
                 "NORMAL", "TELEMETRY");
        }
    }
    m_pubEv = Simulator::Schedule(Seconds(JitteredInterval(m_pubInt)),
        &OpcUaServerApp::SendPublish, this);
}
void OpcUaServerApp::ScheduleAlarmPublish() {
    if (!m_alarmActive || m_alarmReportsLeft == 0 ||
        m_state != RUNNING || !m_sess) return;
    double mean = (m_alarmRate > 0.0) ? (1.0 / m_alarmRate) : 1.0;
    m_alarmEv = Simulator::Schedule(Seconds(JitteredInterval(mean)),
        &OpcUaServerApp::SendAlarmPublish, this);
}
void OpcUaServerApp::SendAlarmPublish() {
    if (!m_alarmActive || m_alarmReportsLeft == 0 ||
        m_state != RUNNING || !m_sess) {
        EndIncident();
        return;
    }
    // The monitored item has generated an EventNotification. Keep it queued
    // until a PublishRequest token is available.
    m_alarmReady = true;
    TrySendAlarmPublish();
}
void OpcUaServerApp::TrySendAlarmPublish() {
    if (!m_alarmActive || !m_alarmReady || m_alarmReportsLeft == 0 ||
        m_state != RUNNING || !m_sess || m_pubTokens == 0) return;

    --m_pubTokens;
    m_alarmReady = false;

    // A PublishResponse may carry either DataChangeNotification or
    // EventNotificationList. Model the latter as the device's normal
    // notification body plus a variable list of selected event fields.
    // Kich thuoc KHONG phu thuoc muc khan cap.
    uint32_t unit = std::max(8u, m_pubSz / 6u);
    const bool timeCritical = m_incidentUrgency == "TIME_CRITICAL"
                           || m_incidentUrgency == "EMERGENCY";
    const uint32_t itemCount = timeCritical
        ? ObjectCount(1, 2)
        : ObjectCount(3, 5);
    uint32_t eventSize = static_cast<uint32_t>(std::max(32.0,
        unit * OPC_EVENT_ITEM_MUL *
        itemCount *
        ServicePayloadScale(m_incidentUrgency)));
    Send(OPC_T_PUB_RSP, eventSize, m_incidentUrgency, "EVENT",
         m_incidentSemanticCategory);
    --m_alarmReportsLeft;

    if (m_alarmReportsLeft == 0) {
        EndIncident();
    } else {
        ScheduleAlarmPublish();
    }
}
void OpcUaServerApp::EndIncident() {
    m_alarmActive = false;
    m_alarmReady = false;
    m_alarmReportsLeft = 0;
    Simulator::Cancel(m_alarmEv);
    Simulator::Cancel(m_alarmEndEv);
}
void OpcUaServerApp::Send(uint8_t type, uint32_t payloadLen,
                          const std::string& urgency,
                          const std::string& kind,
                          const std::string& semanticCategory) {
    if (!m_sess) return;
    std::vector<uint8_t> bytes(OPC_HDR_SZ + payloadLen, 0);
    bytes[0] = type;
    BeWriteU32(&bytes[1], payloadLen);
    Ptr<Packet> p = Create<Packet>(bytes.data(), bytes.size());
    SetScadaMessageMetadata(p, urgency, kind, semanticCategory);
    m_tx(p);
    m_sess->SetIpTos(LabelToTos("OPC-UA", g_scenario));
    m_sess->Send(p);
}
NS_OBJECT_ENSURE_REGISTERED(OpcUaServerApp);

// =====================================================================
//  OpcUaClientApp
// =====================================================================
TypeId OpcUaClientApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::OpcUaClientApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<OpcUaClientApp>()
        .AddTraceSource("Tx", "Message sent",
            MakeTraceSourceAccessor(&OpcUaClientApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
OpcUaClientApp::OpcUaClientApp()
    : m_phase(P_CONNECT), m_conn(false), m_run(false),
      m_readPending(false) {}
OpcUaClientApp::~OpcUaClientApp() {}
void OpcUaClientApp::Setup(Address peer, std::string masterIp) {
    m_peer = peer; m_masterIp = masterIp;
}
void OpcUaClientApp::SetScenario(const std::string& sc) {
    m_scenario = sc;
}
void OpcUaClientApp::StartApplication() {
    m_run   = true;
    m_phase = P_CONNECT;
    m_sock  = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_sock->SetIpTos(LabelToTos("OPC-UA", "normal"));
    m_sock->Bind();
    m_sock->Connect(m_peer);
    m_sock->SetConnectCallback(
        MakeCallback(&OpcUaClientApp::OnConn, this),
        MakeCallback(&OpcUaClientApp::OnFail, this));
    m_sock->SetRecvCallback(MakeCallback(&OpcUaClientApp::OnRecv, this));
}
void OpcUaClientApp::StopApplication() {
    m_run = false;
    Simulator::Cancel(m_ev);
    Simulator::Cancel(m_readEv);
    if (m_sock) m_sock->Close();
}
void OpcUaClientApp::OnConn(Ptr<Socket>) {
    m_conn  = true;
    m_phase = P_HEL;
    m_ev    = Simulator::Schedule(MilliSeconds(100),
        &OpcUaClientApp::SendHello, this);
}
void OpcUaClientApp::OnFail(Ptr<Socket>) { m_conn = false; }
void OpcUaClientApp::SendHello() {
    Send(OPC_T_HEL, OPC_HEL_SZ);
    m_phase = P_WAIT_ACK;
}
void OpcUaClientApp::OnRecv(Ptr<Socket> sock) {
    if (!m_conn) return;
    Ptr<Packet> p;
    while ((p = sock->Recv())) {
        uint32_t size = p->GetSize();
        size_t offset = m_rxBytes.size();
        m_rxBytes.resize(offset + size);
        p->CopyData(m_rxBytes.data() + offset, size);
    }

    while (m_rxBytes.size() >= OPC_HDR_SZ) {
        uint8_t type = m_rxBytes[0];
        uint32_t payloadLen = BeReadU32(&m_rxBytes[1]);
        if (payloadLen > 1024 * 1024) {
            NS_LOG_WARN("Dropping malformed OPC-UA response length=" << payloadLen);
            m_rxBytes.clear();
            return;
        }
        if (m_rxBytes.size() < OPC_HDR_SZ + payloadLen) break;
        m_rxBytes.erase(m_rxBytes.begin(),
                        m_rxBytes.begin() + OPC_HDR_SZ + payloadLen);

        switch (m_phase) {
        case P_WAIT_ACK:
            if (type != OPC_T_ACK) break;
            m_ev = Simulator::Schedule(MilliSeconds(100),
                &OpcUaClientApp::SendOpn, this);
            break;
        case P_WAIT_OPN:
            if (type != OPC_T_OPN_RSP) break;
            m_ev = Simulator::Schedule(MilliSeconds(200),
                &OpcUaClientApp::SendCreateSession, this);
            break;
        case P_WAIT_SESSION:
            if (type != OPC_T_CSES_RSP) break;
            m_ev = Simulator::Schedule(MilliSeconds(200),
                &OpcUaClientApp::SendActivate, this);
            break;
        case P_WAIT_ACTIVATE:
            if (type != OPC_T_ACTI_RSP) break;
            m_ev = Simulator::Schedule(MilliSeconds(200),
                &OpcUaClientApp::SendCreateSub, this);
            break;
        case P_WAIT_SUB:
            if (type != OPC_T_CSUB_RSP) break;
            m_ev = Simulator::Schedule(MilliSeconds(200),
                &OpcUaClientApp::SendCreateMonitored, this);
            break;
        case P_WAIT_MONITOR:
            if (type != OPC_T_CMI_RSP) break;
            // Enter steady state: prime the PublishRequest window and start
            // the periodic Read timer.
            m_phase = P_RUNNING;
            for (uint32_t i = 0; i < OPC_PUB_WINDOW; ++i) SendPublishRequest();
            m_readEv = Simulator::Schedule(Seconds(OPC_READ_INT),
                &OpcUaClientApp::SendRead, this);
            break;
        case P_RUNNING:
            if (type == OPC_T_PUB_RSP) {
                SendPublishRequest();      // 1-in-1-out replenish
            } else if (type == OPC_T_READ_RSP) {
                m_readPending = false;
            }
            break;
        default:
            break;
        }
    }
}
void OpcUaClientApp::SendOpn() {
    Send(OPC_T_OPN_REQ, OPC_OPN_REQ_SZ);
    m_phase = P_WAIT_OPN;
}
void OpcUaClientApp::SendCreateSession() {
    Send(OPC_T_CSES_REQ, OPC_CSES_REQ_SZ);
    m_phase = P_WAIT_SESSION;
}
void OpcUaClientApp::SendActivate() {
    Send(OPC_T_ACTI_REQ, OPC_ACTI_REQ_SZ);
    m_phase = P_WAIT_ACTIVATE;
}
void OpcUaClientApp::SendCreateSub() {
    Send(OPC_T_CSUB_REQ, OPC_CSUB_REQ_SZ);
    m_phase = P_WAIT_SUB;
}
void OpcUaClientApp::SendCreateMonitored() {
    Send(OPC_T_CMI_REQ, OPC_CMI_REQ_SZ);
    m_phase = P_WAIT_MONITOR;
}
void OpcUaClientApp::SendPublishRequest() {
    Send(OPC_T_PUB_REQ, OPC_PUBREQ_SZ);
}
void OpcUaClientApp::SendRead() {
    if (m_phase != P_RUNNING || !m_conn) return;
    m_readPending = true;
    Send(OPC_T_READ_REQ, OPC_READ_SZ);
    m_readEv = Simulator::Schedule(Seconds(OPC_READ_INT),
        &OpcUaClientApp::SendRead, this);
}
void OpcUaClientApp::Send(uint8_t type, uint32_t payloadLen) {
    std::vector<uint8_t> bytes(OPC_HDR_SZ + payloadLen, 0);
    bytes[0] = type;
    BeWriteU32(&bytes[1], payloadLen);
    Ptr<Packet> p = Create<Packet>(bytes.data(), bytes.size());
    m_tx(p);
    m_sock->Send(p);
}
NS_OBJECT_ENSURE_REGISTERED(OpcUaClientApp);

// =====================================================================
//  MqttPublisherApp
// =====================================================================
TypeId MqttPublisherApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::MqttPublisherApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<MqttPublisherApp>()
        .AddTraceSource("Tx", "Packet sent",
            MakeTraceSourceAccessor(&MqttPublisherApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
MqttPublisherApp::MqttPublisherApp()
    : m_baseInt(MQTT_INT_NRM), m_basePay(MQTT_PUB_NRM),
      m_pubInt(MQTT_INT_NRM), m_pubSz(MQTT_PUB_NRM),
      m_rxBuf(0), m_pubState(WAIT_CONNACK),
      m_conn(false), m_run(false), m_armed(false), m_qos1(false),
      m_onDemand(false), m_localPort(0) {}
MqttPublisherApp::~MqttPublisherApp() {}
void MqttPublisherApp::Setup(Address brokerAddr, std::string selfIp) {
    m_peer = brokerAddr; m_selfIp = selfIp;
}
void MqttPublisherApp::SetBaseline(double baseInt, uint32_t basePay) {
    m_baseInt = baseInt; m_basePay = basePay;
    m_pubInt  = baseInt; m_pubSz   = basePay;
}
void MqttPublisherApp::Arm() {
    if (m_armed) return;
    m_armed = true;
    // On-demand gateway publishers connect only after RL selects this path
    // for a real OT message. This avoids opening every mesh path at startup.
    if (!m_run || m_onDemand) return;
    EnsureConnected();
}
void MqttPublisherApp::EnsureConnected() {
    if (!m_run || !m_armed || m_sock) return;
    if (!m_sock) {
        m_sock = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        Ipv4Address localIp = m_selfIp.empty()
                              ? Ipv4Address::GetAny()
                              : Ipv4Address(m_selfIp.c_str());
        if (m_localPort != 0)
            m_sock->Bind(InetSocketAddress(localIp, m_localPort));
        else
            m_sock->Bind(InetSocketAddress(localIp, 0));
        m_sock->SetConnectCallback(
            MakeCallback(&MqttPublisherApp::OnConn, this),
            MakeCallback(&MqttPublisherApp::OnFail, this));
        m_sock->SetRecvCallback(MakeCallback(&MqttPublisherApp::OnRecv, this));
        m_sock->Connect(m_peer);
    }
}
void MqttPublisherApp::SetScenario(const std::string& sc) {
    auto m = GetScenarioMulPair("MQTT", sc);
    m_pubInt = m_baseInt * m.first;
    m_pubSz  = (uint32_t)std::max(1.0, m_basePay * m.second);
    m_qos1   = (sc == "emergency");
    if (m_qos1) {
        // Emergency: enforce a hard ceiling so alarms are published
        // near-instantly regardless of the device's (possibly slow)
        // per-instance baseline interval.
        m_pubInt = std::min(m_pubInt, MQTT_EMR_MAX_INT);
    }
}
void MqttPublisherApp::StartApplication() {
    // Bootstrap-gated: do not connect to broker until Arm() is called.
    m_run = true;
}
void MqttPublisherApp::StopApplication() {
    m_run = false;
    Simulator::Cancel(m_pubEv);
    Simulator::Cancel(m_pingEv);
    Simulator::Cancel(m_ackTimeoutEv);
    Simulator::Cancel(m_reconnectEv);
    if (m_sock) m_sock->Close();
    m_sock = nullptr;
    m_conn = false;
    m_pendingPublishes.clear();
}
void MqttPublisherApp::OnConn(Ptr<Socket>) {
    m_conn = true;
    Send(MQTT_CONNECT_SZ);
    m_pubState = WAIT_CONNACK;
}
void MqttPublisherApp::OnFail(Ptr<Socket>) {
    m_conn = false;
    if (m_sock) m_sock->Close();
    m_sock = nullptr;
    if (m_run && m_armed && !m_pendingPublishes.empty()) {
        m_reconnectEv = Simulator::Schedule(MilliSeconds(100),
            &MqttPublisherApp::EnsureConnected, this);
    }
}
void MqttPublisherApp::OnRecv(Ptr<Socket> sock) {
    if (!m_conn) return;
    Ptr<Packet> p;
    while ((p = sock->Recv())) m_rxBuf += p->GetSize();

    // A4: drain by current publisher state
    while (true) {
        if (m_pubState == WAIT_CONNACK && m_rxBuf >= MQTT_CONNACK_SZ) {
            m_rxBuf  -= MQTT_CONNACK_SZ;
            m_pubState = IDLE;
            if (!m_onDemand) {
                m_pubEv  = Simulator::Schedule(Seconds(JitteredInterval(m_pubInt)),
                    &MqttPublisherApp::Publish, this);
            } else {
                FlushPending();
            }
            // On-demand (gateway aggregator): stay IDLE, publish only when the
            // OT slave's Tx fires PublishOnce(). Keep-alive handled by Send().
        } else if (m_pubState == WAIT_PUBACK && m_rxBuf >= MQTT_PUBACK_SZ) {
            m_rxBuf -= MQTT_PUBACK_SZ;
            Simulator::Cancel(m_ackTimeoutEv);
            m_pubState = IDLE;
            m_pubEv = Simulator::Schedule(Seconds(JitteredInterval(m_pubInt)),
                &MqttPublisherApp::Publish, this);
        } else if (m_pubState == IDLE && m_rxBuf >= MQTT_PINGRSP_SZ) {
            // Drain a stray PINGRSP if any
            m_rxBuf -= MQTT_PINGRSP_SZ;
        } else {
            break;
        }
    }
}
void MqttPublisherApp::Publish() {
    if (!m_run || !m_conn) return;
    Send(m_pubSz);
    if (m_qos1) {
        m_pubState = WAIT_PUBACK;
        m_ackTimeoutEv = Simulator::Schedule(Seconds(MQTT_ACK_TIMEOUT),
            &MqttPublisherApp::OnPubAckTimeout, this);
    } else {
        m_pubEv = Simulator::Schedule(Seconds(JitteredInterval(m_pubInt)),
            &MqttPublisherApp::Publish, this);
    }
}
void MqttPublisherApp::Ping() {
    if (!m_run || !m_conn) return;
    Send(MQTT_PINGREQ_SZ);   // Send() re-arms the next keep-alive timer
}
void MqttPublisherApp::OnPubAckTimeout() {
    if (m_pubState == WAIT_PUBACK) {
        m_pubState = IDLE;
        m_pubEv = Simulator::Schedule(Seconds(JitteredInterval(m_pubInt)),
            &MqttPublisherApp::Publish, this);
    }
}
void MqttPublisherApp::SetOnDemand(bool b)      { m_onDemand = b; }
void MqttPublisherApp::SetLocalPort(uint16_t p) { m_localPort = p; }
void MqttPublisherApp::PublishOnce(uint8_t tos, uint32_t sz,
                                   uint64_t messageId, uint32_t deviceId,
                                   uint8_t protocolId, uint8_t sourceGateway,
                                   uint8_t chosenPath, uint8_t trafficClass,
                                   uint64_t originTimeNs) {
    if (!m_run || !m_armed) return;
    m_pendingPublishes.push_back({tos, sz, messageId, deviceId, protocolId,
                                  sourceGateway, chosenPath, trafficClass,
                                  originTimeNs});
    EnsureConnected();
    FlushPending();
}
void MqttPublisherApp::FlushPending() {
    if (!m_run || !m_conn || m_pubState != IDLE) return;
    while (!m_pendingPublishes.empty()) {
        PendingPublish pending = m_pendingPublishes.front();
        m_pendingPublishes.pop_front();
        SendFramed(pending.tos, pending.size, pending.messageId,
                   pending.deviceId, pending.protocolId,
                   pending.sourceGateway, pending.chosenPath,
                   pending.trafficClass, pending.originTimeNs);
    }
}
void MqttPublisherApp::SendFramed(uint8_t tos, uint32_t sz,
                                  uint64_t messageId, uint32_t deviceId,
                                  uint8_t protocolId, uint8_t sourceGateway,
                                  uint8_t chosenPath, uint8_t trafficClass,
                                  uint64_t originTimeNs) {
    if (m_sock) m_sock->SetIpTos(tos);
    Ptr<Packet> p = Create<Packet>(sz);
    ScadaMqttHeader header;
    header.SetPayloadLength(sz);
    header.SetMessageId(messageId);
    // Keep the RL timeout and measured delivery delay on the same clock:
    // originTimeNs is captured at the source OT response before any lazy TCP
    // connection or pending MQTT queue wait.
    header.SetSendTimeNs(originTimeNs);
    header.SetDeviceId(deviceId);
    header.SetProtocolId(protocolId);
    header.SetSourceGateway(sourceGateway);
    header.SetChosenPath(chosenPath);
    header.SetTrafficClass(trafficClass);
    p->AddHeader(header);

    std::string urgency = trafficClass >= 2 ? "EMERGENCY" :
                          trafficClass == 1 ? "IMPORTANT" : "NORMAL";
    SetScadaMessageMetadata(p, urgency,
                            urgency == "NORMAL" ? "TELEMETRY" : "EVENT");
    m_tx(p);
    m_sock->Send(p);
}
void MqttPublisherApp::Send(uint32_t sz, const std::string& urgency,
                            const std::string& kind) {
    Ptr<Packet> p = Create<Packet>(sz);
    SetScadaMessageMetadata(p, urgency, kind);
    m_tx(p);
    m_sock->Send(p);
    // any outbound control packet resets
    // the PINGREQ timer, so a PINGREQ is only ever sent when the connection
    // has been genuinely idle for MQTT_KEEPALIVE seconds.
    if (m_conn && !m_onDemand) {
        Simulator::Cancel(m_pingEv);
        m_pingEv = Simulator::Schedule(Seconds(MQTT_KEEPALIVE),
            &MqttPublisherApp::Ping, this);
    }
}
NS_OBJECT_ENSURE_REGISTERED(MqttPublisherApp);

// =====================================================================
//  MqttBrokerApp
// =====================================================================
TypeId MqttBrokerApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::MqttBrokerApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<MqttBrokerApp>()
        .AddTraceSource("Tx", "Packet forwarded",
            MakeTraceSourceAccessor(&MqttBrokerApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
MqttBrokerApp::MqttBrokerApp()
    : m_listen(nullptr), m_brokerIp("") {
    m_toMaster.fill(nullptr);
    m_masterConn.fill(false);
}
MqttBrokerApp::~MqttBrokerApp() {}
void MqttBrokerApp::Setup(Address masterAddr, std::string brokerIp) {
    m_masterAddr = masterAddr;
    m_brokerIp   = brokerIp;
}
void MqttBrokerApp::StartApplication() {
    m_listen = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), PORT_MQTT));
    m_listen->Listen();
    m_listen->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&MqttBrokerApp::OnAccept, this));

    const uint8_t tos[3] = {0, 104, 184};
    for (uint32_t c = 0; c < m_toMaster.size(); ++c) {
        m_toMaster[c] = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
        m_toMaster[c]->Bind();
        m_toMaster[c]->SetIpTos(tos[c]);
        m_toMaster[c]->Connect(m_masterAddr);
        m_toMaster[c]->SetConnectCallback(
            MakeCallback(&MqttBrokerApp::OnMasterConn, this),
            MakeCallback(&MqttBrokerApp::OnMasterFail, this));
    }
}
void MqttBrokerApp::StopApplication() {
    if (m_listen) { m_listen->Close(); m_listen = nullptr; }
    for (auto& [s, d] : m_sessions) if (s) s->Close();
    m_sessions.clear();
    for (auto& socket : m_toMaster) {
        if (socket) socket->Close();
        socket = nullptr;
    }
}
void MqttBrokerApp::OnAccept(Ptr<Socket> ns, const Address&) {
    ns->SetRecvCallback(MakeCallback(&MqttBrokerApp::OnPubData, this));
    m_sessions[ns] = {Create<Packet>(), false};
}
void MqttBrokerApp::OnPubData(Ptr<Socket> sock) {
    auto it = m_sessions.find(sock);
    if (it == m_sessions.end()) {
        // Late callback after StopApplication or unknown socket.  Drain
        // and drop to avoid leaking received bytes inside ns-3 buffers.
        Ptr<Packet> p;
        while ((p = sock->Recv())) { /* discard */ }
        return;
    }
    PubData& sess = it->second;
    Ptr<Packet> p;
    while ((p = sock->Recv())) sess.rxPacket->AddAtEnd(p);

    // A4: parse messages by state and size.
    while (true) {
        if (!sess.connected) {
            if (sess.rxPacket->GetSize() >= MQTT_CONNECT_SZ) {
                sess.rxPacket->RemoveAtStart(MQTT_CONNECT_SZ);
                sess.connected = true;
                Ptr<Packet> ack = Create<Packet>(MQTT_CONNACK_SZ);
                sock->Send(ack);
            } else break;
        } else {
            if (sess.rxPacket->GetSize() < 32) break;
            ScadaMqttHeader header;
            sess.rxPacket->PeekHeader(header);
            if (!header.IsValid()) {
                NS_LOG_WARN("Dropping unframed MQTT byte stream after CONNECT");
                sess.rxPacket->RemoveAtStart(1);
                continue;
            }
            uint32_t frameSize = header.GetSerializedSize()
                               + header.GetPayloadLength();
            if (sess.rxPacket->GetSize() < frameSize) break;
            Ptr<Packet> frame = sess.rxPacket->CreateFragment(0, frameSize);
            sess.rxPacket->RemoveAtStart(frameSize);
            frame->RemoveHeader(header);
            Forward(header, frame);
        }
    }
}
void MqttBrokerApp::OnMasterConn(Ptr<Socket> socket) {
    for (uint32_t i = 0; i < m_toMaster.size(); ++i) {
        if (m_toMaster[i] == socket) m_masterConn[i] = true;
    }
}
void MqttBrokerApp::OnMasterFail(Ptr<Socket> socket) {
    for (uint32_t i = 0; i < m_toMaster.size(); ++i) {
        if (m_toMaster[i] == socket) m_masterConn[i] = false;
    }
}
void MqttBrokerApp::SetClassProfile(uint32_t trafficClass,
                                   double rateBitsPerSec, double burstBytes) {
    if (trafficClass >= m_meter.size()) return;
    ClassMeter& m = m_meter[trafficClass];
    m.enabled = rateBitsPerSec > 0.0;
    m.rateBytesPerSec = rateBitsPerSec / 8.0;
    m.burstBytes = burstBytes;
    m.tokens = burstBytes;                 // start with a full bucket
    m.lastUpdate = Simulator::Now();
}

void MqttBrokerApp::SetClassRate(uint32_t trafficClass,
                                double rateBitsPerSec) {
    if (trafficClass >= m_meter.size()) return;
    ClassMeter& m = m_meter[trafficClass];
    if (!m.enabled) return;                  // never turn a meter on this way
    // Accrue tokens at the old rate up to now, then switch rates, so the
    // change takes effect from this instant and no tokens are created or
    // destroyed by the update itself.
    Time now = Simulator::Now();
    m.tokens = std::min(m.burstBytes,
                        m.tokens + (now - m.lastUpdate).GetSeconds()
                                   * m.rateBytesPerSec);
    m.lastUpdate = now;
    m.rateBytesPerSec = rateBitsPerSec / 8.0;
}

double MqttBrokerApp::GetClassRate(uint32_t trafficClass) const {
    if (trafficClass >= m_meter.size()) return 0.0;
    return m_meter[trafficClass].rateBytesPerSec * 8.0;
}

void MqttBrokerApp::SetEmergencyBorrow(bool enabled) {
    m_emergencyBorrow = enabled;
}

void MqttBrokerApp::SetMeterCallback(
    std::function<void(uint64_t, uint8_t, uint8_t, bool, bool, uint32_t,
                       uint64_t)> callback) {
    m_meterCb = std::move(callback);
}

// Single-rate token bucket: the bucket refills at the declared rate and is
// capped by the burst size, so a class may exceed its rate briefly but not on
// average - the two parameters of the token-bucket model carry the two
// separate meanings of average rate and burst size.
bool MqttBrokerApp::ConsumeTokens(uint32_t trafficClass, uint32_t bytes) {
    ClassMeter& m = m_meter[trafficClass];
    Time now = Simulator::Now();
    double elapsed = (now - m.lastUpdate).GetSeconds();
    m.tokens = std::min(m.burstBytes,
                        m.tokens + elapsed * m.rateBytesPerSec);
    m.lastUpdate = now;
    if (m.tokens >= static_cast<double>(bytes)) {
        m.tokens -= static_cast<double>(bytes);
        ++m.inProfile;
        return true;
    }
    ++m.outOfProfile;
    return false;
}

void MqttBrokerApp::Forward(const ScadaMqttHeader& header, Ptr<Packet> payload) {
    uint32_t cls = std::min<uint32_t>(header.GetTrafficClass(), 2);

    // Meter and re-marking marker.  The message is offered to its own class
    // first; if that profile is exhausted it cascades down one class at a
    // time.  Class 0 is never metered, so a message is never dropped here -
    // an over-classified message costs the priority band's budget, and the
    // class that pays is whichever genuinely urgent message arrives next.
    uint32_t served = cls;
    bool demoted = false;
    bool borrowed = false;
    uint32_t bytes = (payload ? payload->GetSize() : 0)
                   + header.GetSerializedSize();
    if (cls == 2 && m_emergencyBorrow && m_meter[2].enabled
        && m_meter[1].enabled) {
        if (!ConsumeTokens(2, bytes)) {
            // One-way borrowing protects EMERGENCY without allowing
            // IMPORTANT to consume the reserved EMERGENCY bucket.  The
            // aggregate refill rate remains rE+rI.
            if (ConsumeTokens(1, bytes)) {
                borrowed = true;
            } else {
                served = 0;
                demoted = true;
            }
        }
    } else {
        while (served > 0 && m_meter[served].enabled
               && !ConsumeTokens(served, bytes)) {
            --served;
            demoted = true;
        }
    }

    if (m_meterCb) {
        m_meterCb(header.GetMessageId(), static_cast<uint8_t>(cls),
                  static_cast<uint8_t>(served), demoted, borrowed, bytes,
                  header.GetSendTimeNs());
    }
    if (!m_masterConn[served] || !m_toMaster[served]) return;
    Ptr<Packet> fwd = payload ? payload->Copy() : Create<Packet>();
    fwd->AddHeader(header);
    m_tx(fwd);
    m_toMaster[served]->Send(fwd);
}
NS_OBJECT_ENSURE_REGISTERED(MqttBrokerApp);

// =====================================================================
//  ScadaMasterSubscriberApp
// =====================================================================
TypeId ScadaMasterSubscriberApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::ScadaMasterSubscriberApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<ScadaMasterSubscriberApp>()
        .AddTraceSource("Rx", "Framed MQTT message received",
            MakeTraceSourceAccessor(&ScadaMasterSubscriberApp::m_rx),
            "ns3::Packet::TracedCallback");
    return tid;
}
ScadaMasterSubscriberApp::ScadaMasterSubscriberApp()
    : m_port(PORT_MQTT_FWD), m_listen(nullptr) {}
ScadaMasterSubscriberApp::~ScadaMasterSubscriberApp() {}
void ScadaMasterSubscriberApp::Setup(
    uint16_t port,
    std::function<void(const ScadaDeliveryInfo&)> deliveryCallback) {
    m_port = port;
    m_deliveryCallback = std::move(deliveryCallback);
}
void ScadaMasterSubscriberApp::StartApplication() {
    m_listen = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId());
    m_listen->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
    m_listen->Listen();
    m_listen->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address&>(),
        MakeCallback(&ScadaMasterSubscriberApp::OnAccept, this));
}
void ScadaMasterSubscriberApp::StopApplication() {
    if (m_listen) m_listen->Close();
    m_listen = nullptr;
    for (auto& entry : m_sessions) {
        if (entry.first) entry.first->Close();
    }
    m_sessions.clear();
}
void ScadaMasterSubscriberApp::OnAccept(Ptr<Socket> socket, const Address&) {
    m_sessions[socket] = {Create<Packet>()};
    socket->SetRecvCallback(MakeCallback(&ScadaMasterSubscriberApp::OnData, this));
}
void ScadaMasterSubscriberApp::OnData(Ptr<Socket> socket) {
    auto it = m_sessions.find(socket);
    if (it == m_sessions.end()) return;
    Ptr<Packet> packet;
    while ((packet = socket->Recv())) it->second.rxPacket->AddAtEnd(packet);

    Ptr<Packet> buffer = it->second.rxPacket;
    while (buffer->GetSize() >= 32) {
        ScadaMqttHeader header;
        buffer->PeekHeader(header);
        if (!header.IsValid()) {
            buffer->RemoveAtStart(1);
            continue;
        }
        uint32_t frameSize = header.GetSerializedSize()
                           + header.GetPayloadLength();
        if (buffer->GetSize() < frameSize) break;
        Ptr<Packet> frame = buffer->CreateFragment(0, frameSize);
        buffer->RemoveAtStart(frameSize);
        frame->RemoveHeader(header);
        m_rx(frame);

        ScadaDeliveryInfo info;
        info.messageId = header.GetMessageId();
        info.sendTimeNs = header.GetSendTimeNs();
        info.deviceId = header.GetDeviceId();
        info.payloadLength = header.GetPayloadLength();
        info.sourceGateway = header.GetSourceGateway();
        info.chosenPath = header.GetChosenPath();
        info.trafficClass = header.GetTrafficClass();
        info.protocolId = header.GetProtocolId();
        uint64_t nowNs = Simulator::Now().GetNanoSeconds();
        info.delayMs = nowNs >= info.sendTimeNs
                     ? static_cast<double>(nowNs - info.sendTimeNs) / 1e6
                     : 0.0;
        if (m_deliveryCallback) m_deliveryCallback(info);
    }
}
NS_OBJECT_ENSURE_REGISTERED(ScadaMasterSubscriberApp);

// =====================================================================
//  BootstrapAnnounceApp  —  master-side UDP announcer
// =====================================================================
TypeId BootstrapAnnounceApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::BootstrapAnnounceApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<BootstrapAnnounceApp>()
        .AddTraceSource("Tx", "Bootstrap packet sent",
            MakeTraceSourceAccessor(&BootstrapAnnounceApp::m_tx),
            "ns3::Packet::TracedCallback");
    return tid;
}
BootstrapAnnounceApp::BootstrapAnnounceApp() : m_sock(nullptr), m_fireAt(Seconds(1.0)) {}
BootstrapAnnounceApp::~BootstrapAnnounceApp() { m_sock = nullptr; }

void BootstrapAnnounceApp::Setup(Time fireAt) { m_fireAt = fireAt; }
void BootstrapAnnounceApp::AddTarget(Ipv4Address addr, uint16_t port) {
    m_targets.emplace_back(addr, port);
}
void BootstrapAnnounceApp::StartApplication() {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind();
    // Highest priority TOS so the announce reaches before any normal traffic
    m_sock->SetIpTos(184);   // EF
    m_ev = Simulator::Schedule(m_fireAt - Simulator::Now(),
        &BootstrapAnnounceApp::Fire, this);
}
void BootstrapAnnounceApp::StopApplication() {
    Simulator::Cancel(m_ev);
    if (m_sock) { m_sock->Close(); m_sock = nullptr; }
}
void BootstrapAnnounceApp::Fire() {
    if (!m_sock) return;
    // Small payload ("HELLO" + master timestamp), 16 bytes is plenty.
    for (const auto& dst : m_targets) {
        Ptr<Packet> p = Create<Packet>(16);
        m_tx(p);
        m_sock->SendTo(p, 0, dst);
    }
    NS_LOG_UNCOND("[Bootstrap] master announced to "
                  << m_targets.size() << " targets at t="
                  << Simulator::Now().GetSeconds() << "s");
}
NS_OBJECT_ENSURE_REGISTERED(BootstrapAnnounceApp);

// =====================================================================
//  BootstrapListenerApp  —  field/GW-side UDP listener
// =====================================================================
TypeId BootstrapListenerApp::GetTypeId() {
    static TypeId tid = TypeId("ns3::BootstrapListenerApp")
        .SetParent<Application>().SetGroupName("Applications")
        .AddConstructor<BootstrapListenerApp>();
    return tid;
}
BootstrapListenerApp::BootstrapListenerApp()
    : m_sock(nullptr), m_port(9100), m_received(false) {}
BootstrapListenerApp::~BootstrapListenerApp() { m_sock = nullptr; }

void BootstrapListenerApp::Setup(uint16_t port) { m_port = port; }
void BootstrapListenerApp::RegisterArm(std::function<void()> cb) {
    m_callbacks.push_back(std::move(cb));
}
void BootstrapListenerApp::StartApplication() {
    m_sock = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
    m_sock->SetRecvCallback(MakeCallback(&BootstrapListenerApp::OnRecv, this));
}
void BootstrapListenerApp::StopApplication() {
    if (m_sock) { m_sock->Close(); m_sock = nullptr; }
}
void BootstrapListenerApp::OnRecv(Ptr<Socket> sock) {
    Ptr<Packet> p;
    while ((p = sock->Recv())) { /* drain */ }
    if (m_received) return;             // idempotent: arm only once
    m_received = true;
    for (auto& cb : m_callbacks) cb();
}
NS_OBJECT_ENSURE_REGISTERED(BootstrapListenerApp);

// =====================================================================
//  RestampTos implementations
//  Kept for explicit policy experiments.  The DT/RF classifier path does not
//  call these methods because it predicts traffic_class at the master only.
// =====================================================================
void ModbusMasterApp::RestampTos(uint8_t tos)      { if (m_sock) m_sock->SetIpTos(tos); }
void ModbusSlaveApp::RestampTos(uint8_t tos)       {
    // ModbusSlaveApp stamps via per-session sock in OnAccept; we cannot
    // easily reach all sessions.  No-op here — slave responses use TOS
    // stamped at session start; new sessions will pick up the new override.
    (void)tos;
}
void Dnp3OutstationApp::RestampTos(uint8_t tos)    { if (m_sessSock) m_sessSock->SetIpTos(tos); }
void Dnp3MasterApp::RestampTos(uint8_t tos)        { if (m_sock) m_sock->SetIpTos(tos); }
void Iec104ControlledApp::RestampTos(uint8_t tos)  { if (m_sess) m_sess->SetIpTos(tos); }
void Iec104ControllingApp::RestampTos(uint8_t tos) { if (m_sock) m_sock->SetIpTos(tos); }
void OpcUaServerApp::RestampTos(uint8_t tos)       { if (m_sess) m_sess->SetIpTos(tos); }
void OpcUaClientApp::RestampTos(uint8_t tos)       { if (m_sock) m_sock->SetIpTos(tos); }
void MqttPublisherApp::RestampTos(uint8_t tos)     { if (m_sock) m_sock->SetIpTos(tos); }

} // namespace ns3
