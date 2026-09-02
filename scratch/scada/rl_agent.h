// =====================================================================
//  rl_agent.h - tabular Q-learning gateway path selector
// =====================================================================
#pragma once

#include "ns3/core-module.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <ostream>
#include <sstream>
#include <string>
#include <unordered_map>

namespace ns3 {

enum class RlTrafficClass : uint8_t {
    NORMAL = 0,
    IMPORTANT = 1,
    EMERGENCY = 2
};

enum class RlMode : uint8_t {
    OFF = 0,
    HEURISTIC = 1,
    TRAIN = 2,
    QTABLE = 3
};

struct RlPathState {
    double queueRatio = 0.0;
    double delayMs = 15.0;
    double loss = 0.0;
    double assignedLoad = 0.0;
};

struct RlDecision {
    uint32_t path = 0;
    uint64_t messageId = 0;
};

class GatewayRlAgent {
public:
    static constexpr uint32_t N_PATHS = 3;
    static constexpr uint32_t N_CLASSES = 3;
    static constexpr uint32_t N_HEALTH_COMBINATIONS = 27;
    // State = (class, health of all 3 paths, best current path).  previous_path
    // used to be a fourth dimension, which tripled the table to 729 states for
    // little signal: the hysteresis margin already supplies path stickiness,
    // and PathCost still folds `previous` into best_current_path. Dropping it
    // concentrates the same traffic into a third as many rows, which is what
    // EMERGENCY needed - at 729 states only 33% of its rows ever reached 20
    // visits even after 200 episodes.
    static constexpr uint32_t CLASS_STRIDE = N_HEALTH_COMBINATIONS * N_PATHS;
    static constexpr uint32_t N_STATES = N_CLASSES * CLASS_STRIDE;

    // Normalized delay charged to a message that never reported back within
    // FeedbackTimeoutMs.  Delivered messages are bounded below this by
    // construction (the timeout fires at deadline + 50ms), so this is the
    // worst per-message delay the reward can observe.
    static constexpr double TIMEOUT_NORM_PENALTY = 2.0;
    // v3_sev rescaled the reward by class severity; v4 additionally dropped the
    // previous_path state dimension (729 -> 243 states).  Both changes make
    // older tables unusable, so they are rejected at load instead of being
    // reinterpreted under the new encoding.
    static constexpr const char* STATE_SCHEMA = "health_best_v4_sev";

    void Setup(uint32_t gatewayId, RlMode mode, double alpha = 0.10,
               double gamma = 0.90, double epsilon = 0.20,
               double decisionMs = 100.0, double timeoutMs = 1500.0,
               bool safeMask = true,
               std::ostream* transitionCsv = nullptr) {
        m_gatewayId = std::min(gatewayId, 2u);
        m_mode = mode;
        m_alpha = std::clamp(alpha, 0.0, 1.0);
        m_gamma = std::clamp(gamma, 0.0, 0.999);
        m_epsilon = std::clamp(epsilon, 0.0, 1.0);
        m_decisionMs = std::max(1.0, decisionMs);
        m_timeoutMs = std::max(10.0, timeoutMs);
        m_safeMask = safeMask;
        m_transitionCsv = transitionCsv;
        m_rng = CreateObject<UniformRandomVariable>();
        m_rng->SetStream(7000 + static_cast<int64_t>(m_gatewayId));
        m_prevPath.fill(m_gatewayId);
        m_activeWindow.fill(0);
        for (uint32_t p = 0; p < N_PATHS; ++p) {
            m_paths[p] = RlPathState{};
            m_paths[p].delayMs = (p == m_gatewayId) ? 15.0 : 22.0;
        }
    }

    void SetPathQueue(uint32_t path, double ratio) {
        if (path >= N_PATHS) return;
        m_paths[path].queueRatio = std::clamp(ratio, 0.0, 1.0);
    }

    void SetPathLoss(uint32_t path, double ratio) {
        if (path >= N_PATHS) return;
        m_paths[path].loss = std::clamp(ratio, 0.0, 1.0);
    }

    RlDecision SelectPath(RlTrafficClass cls, uint32_t bytes) {
        const uint32_t c = ClassIndex(cls);
        uint64_t windowId = m_activeWindow[c];
        auto existing = m_windows.find(windowId);
        if (windowId == 0 || existing == m_windows.end()
            || existing->second.closed) {
            windowId = OpenWindow(cls);
        }

        Window& window = m_windows.at(windowId);
        ++window.total;
        ++window.pending;

        uint64_t local = ++m_messageCounter;
        uint64_t messageId = (static_cast<uint64_t>(m_gatewayId + 1) << 60)
                           | local;
        Pending pending;
        pending.windowId = windowId;
        pending.path = window.action;
        pending.timeout = Simulator::Schedule(
            MilliSeconds(FeedbackTimeoutMs(cls)), &GatewayRlAgent::OnTimeout,
            this, messageId);
        m_pending.emplace(messageId, pending);

        double weightedBytes = static_cast<double>(bytes)
                             * (c == 2 ? 4.0 : c == 1 ? 2.0 : 1.0);
        RlPathState& path = m_paths[window.action];
        path.assignedLoad = 0.90 * path.assignedLoad
                          + 0.10 * weightedBytes;
        return {window.action, messageId};
    }

    void OnDelivery(uint64_t messageId, uint32_t path, double delayMs) {
        auto pendingIt = m_pending.find(messageId);
        if (pendingIt == m_pending.end()) return;
        Pending pending = pendingIt->second;
        Simulator::Cancel(pending.timeout);
        m_pending.erase(pendingIt);

        auto windowIt = m_windows.find(pending.windowId);
        if (windowIt == m_windows.end()) return;
        Window& window = windowIt->second;
        if (window.pending > 0) --window.pending;
        ++window.delivered;
        double deadline = DeadlineMs(window.cls);
        double normalizedDelay =
            std::min(delayMs / deadline, TIMEOUT_NORM_PENALTY);
        window.normalizedDelaySum += normalizedDelay;
        window.maxNormalizedDelay = std::max(window.maxNormalizedDelay,
                                             normalizedDelay);
        if (delayMs > deadline) ++window.deadlineMisses;

        uint32_t actualPath = std::min(path, 2u);
        RlPathState& state = m_paths[actualPath];
        state.delayMs = 0.85 * state.delayMs + 0.15 * delayMs;
        state.loss *= 0.90;
        TryFinalize(window.id);
    }

    void Finish() {
        std::vector<uint64_t> pendingIds;
        pendingIds.reserve(m_pending.size());
        for (const auto& entry : m_pending) pendingIds.push_back(entry.first);
        for (uint64_t id : pendingIds) OnTimeout(id);

        std::vector<uint64_t> windowIds;
        windowIds.reserve(m_windows.size());
        for (const auto& entry : m_windows) windowIds.push_back(entry.first);
        for (uint64_t id : windowIds) {
            auto it = m_windows.find(id);
            if (it == m_windows.end()) continue;
            it->second.closed = true;
            it->second.nextState = EncodeState(it->second.cls,
                                               it->second.action);
            TryFinalize(id);
        }
    }

    bool LoadQTable(const std::string& path) {
        std::ifstream input(path);
        if (!input.is_open()) return false;
        std::string line;
        std::getline(input, line);
        if (line.find("state_schema") == std::string::npos) return false;
        uint32_t loaded = 0;
        while (std::getline(input, line)) {
            if (line.empty()) continue;
            std::stringstream ss(line);
            std::array<std::string, 6> col;
            for (uint32_t i = 0; i < col.size(); ++i) {
                if (!std::getline(ss, col[i], ',')) break;
            }
            try {
                uint32_t gw = static_cast<uint32_t>(std::stoul(col[0]));
                uint32_t state = static_cast<uint32_t>(std::stoul(col[1]));
                uint32_t action = static_cast<uint32_t>(std::stoul(col[2]));
                if (col[5] != STATE_SCHEMA) continue;
                if (gw != m_gatewayId || state >= N_STATES || action >= N_PATHS)
                    continue;
                m_q[state][action] = std::stod(col[3]);
                m_visits[state][action] = static_cast<uint64_t>(std::stoull(col[4]));
                ++loaded;
            } catch (...) {
                continue;
            }
        }
        m_loadedAny = loaded > 0;
        return m_loadedAny;
    }

    void WriteQTable(std::ostream& output) const {
        for (uint32_t state = 0; state < N_STATES; ++state) {
            for (uint32_t action = 0; action < N_PATHS; ++action) {
                if (m_visits[state][action] == 0
                    && std::abs(m_q[state][action]) < 1e-15) continue;
                output << m_gatewayId << ',' << state << ',' << action << ','
                       << std::setprecision(12) << m_q[state][action] << ','
                       << m_visits[state][action] << ',' << STATE_SCHEMA << '\n';
            }
        }
    }

    const std::array<RlPathState, N_PATHS>& PathStates() const {
        return m_paths;
    }

private:
    struct Pending {
        uint64_t windowId = 0;
        uint32_t path = 0;
        EventId timeout;
    };

    struct Window {
        uint64_t id = 0;
        RlTrafficClass cls = RlTrafficClass::NORMAL;
        uint32_t state = 0;
        uint32_t nextState = 0;
        uint32_t action = 0;
        uint32_t total = 0;
        uint32_t pending = 0;
        uint32_t delivered = 0;
        uint32_t lost = 0;
        uint32_t deadlineMisses = 0;
        double normalizedDelaySum = 0.0;
        double maxNormalizedDelay = 0.0;
        double queueAtStart = 0.0;
        uint32_t actionHealth = 0;
        uint32_t minHealth = 0;
        bool degradedFallback = false;
        bool switched = false;
        bool closed = false;
    };

    uint64_t OpenWindow(RlTrafficClass cls) {
        uint32_t c = ClassIndex(cls);
        uint32_t previous = m_prevPath[c];
        uint32_t state = EncodeState(cls, previous);
        uint32_t action = ChooseAction(state, cls, previous);

        Window window;
        window.id = ++m_windowCounter;
        window.cls = cls;
        window.state = state;
        window.action = action;
        window.queueAtStart = m_paths[action].queueRatio;
        window.actionHealth = HealthBin(m_paths[action]);
        window.minHealth = MinHealth();
        window.degradedFallback = m_lastSafetyFallback[c];
        window.switched = action != previous;
        m_windows.emplace(window.id, window);
        m_activeWindow[c] = window.id;
        m_prevPath[c] = action;
        Simulator::Schedule(MilliSeconds(m_decisionMs),
                            &GatewayRlAgent::CloseWindow, this, window.id);
        return window.id;
    }

    void CloseWindow(uint64_t windowId) {
        auto it = m_windows.find(windowId);
        if (it == m_windows.end() || it->second.closed) return;
        Window& window = it->second;
        window.closed = true;
        window.nextState = EncodeState(window.cls, window.action);
        uint32_t c = ClassIndex(window.cls);
        if (m_activeWindow[c] == windowId) m_activeWindow[c] = 0;
        TryFinalize(windowId);
    }

    void OnTimeout(uint64_t messageId) {
        auto pendingIt = m_pending.find(messageId);
        if (pendingIt == m_pending.end()) return;
        Pending pending = pendingIt->second;
        m_pending.erase(pendingIt);
        auto windowIt = m_windows.find(pending.windowId);
        if (windowIt == m_windows.end()) return;
        Window& window = windowIt->second;
        if (window.pending > 0) --window.pending;
        ++window.lost;
        ++window.deadlineMisses;
        window.normalizedDelaySum += TIMEOUT_NORM_PENALTY;
        window.maxNormalizedDelay = TIMEOUT_NORM_PENALTY;
        RlPathState& state = m_paths[std::min(pending.path, 2u)];
        state.loss = 0.90 * state.loss + 0.10;
        TryFinalize(window.id);
    }

    void TryFinalize(uint64_t windowId) {
        auto it = m_windows.find(windowId);
        if (it == m_windows.end()) return;
        Window& w = it->second;
        if (!w.closed || w.pending != 0 || w.total == 0) return;

        double total = static_cast<double>(w.total);
        double avgNormDelay = w.normalizedDelaySum / total;
        double lossRate = static_cast<double>(w.lost) / total;
        double missRate = static_cast<double>(w.deadlineMisses) / total;
        double tailExcess = std::max(0.0, w.maxNormalizedDelay - 0.50);

        // Loss and deadline misses are scaled by class severity.  Everything
        // slower than FeedbackTimeoutMs collapses into the same "lost" bucket
        // regardless of how late it eventually arrives, so the only lever that
        // separates a safety-critical failure from a routine one is how much a
        // drop costs per class.  Weighting it flat let the agent trade an
        // EMERGENCY timeout for a marginal average-delay gain on telemetry.
        double severity = ClassSeverity(w.cls);
        double reward = 1.0
                      - 0.75 * avgNormDelay
                      - 3.00 * severity * lossRate
                      - 2.00 * severity * missRate
                      - 0.75 * tailExcess
                      - 0.25 * w.queueAtStart
                      - 0.15 * (w.switched ? 1.0 : 0.0);
        // Floor scales with severity too: a fixed -2.0 saturated so early for
        // EMERGENCY that a window losing one message scored the same as one
        // losing half of them, erasing the gradient the agent needs.
        reward = std::clamp(reward, -2.0 * severity, 1.0);

        double oldQ = m_q[w.state][w.action];
        double newQ = oldQ;
        if (m_mode == RlMode::TRAIN && !w.degradedFallback) {
            auto nextAllowed = AllowedActions(w.nextState);
            uint32_t nextAction = AllPathsDegraded(w.nextState)
                ? ChooseSafeHeuristic(w.cls, w.action, nextAllowed)
                : ArgMaxAllowed(w.nextState, nextAllowed);
            double bestNext = m_q[w.nextState][nextAction];
            newQ = oldQ + m_alpha * (reward + m_gamma * bestNext - oldQ);
            m_q[w.state][w.action] = newQ;
        }

        if (m_transitionCsv) {
            *m_transitionCsv << std::fixed << std::setprecision(6)
                << Simulator::Now().GetSeconds() << ',' << m_gatewayId << ','
                << w.id << ',' << ClassIndex(w.cls) << ',' << w.state << ','
                << w.action << ',' << w.nextState << ',' << reward << ','
                << w.total << ',' << w.delivered << ',' << w.lost << ','
                << w.deadlineMisses << ',' << avgNormDelay << ','
                << w.maxNormalizedDelay << ',' << w.queueAtStart << ','
                << w.actionHealth << ',' << w.minHealth << ','
                << (w.degradedFallback ? 1 : 0) << ','
                << (w.switched ? 1 : 0) << ','
                << oldQ << ',' << newQ << ','
                << m_visits[w.state][w.action] << '\n';
        }
        m_windows.erase(it);
    }

    uint32_t ChooseAction(uint32_t state, RlTrafficClass cls,
                          uint32_t previous) {
        uint32_t c = ClassIndex(cls);
        m_lastSafetyFallback[c] = false;
        if (m_mode == RlMode::OFF) return m_gatewayId;
        if (m_mode == RlMode::HEURISTIC) return ChooseHeuristic(cls, previous);
        auto allowed = AllowedActions(state);
        if (m_safeMask && AllPathsDegraded(state)) {
            m_lastSafetyFallback[c] = true;
            return ChooseSafeHeuristic(cls, previous, allowed);
        }
        if (m_mode == RlMode::QTABLE) {
            uint64_t rowVisits = 0;
            for (uint32_t p = 0; p < N_PATHS; ++p) {
                if (allowed[p]) rowVisits += m_visits[state][p];
            }
            if (!m_loadedAny || rowVisits == 0) {
                m_lastSafetyFallback[c] = true;
                return ChooseSafeHeuristic(cls, previous, allowed);
            }
            uint32_t learned = StableArgMax(state, previous, allowed);
            uint32_t safest = ChooseSafeHeuristic(cls, previous, allowed);
            if (PathCost(cls, learned, previous)
                > PathCost(cls, safest, previous) + GuardMargin(cls)) {
                m_lastSafetyFallback[c] = true;
                return safest;
            }
            return learned;
        }

        // Force a small amount of coverage before ordinary epsilon-greedy.
        uint64_t minVisits = std::numeric_limits<uint64_t>::max();
        for (uint32_t p = 0; p < N_PATHS; ++p) {
            if (allowed[p]) minVisits = std::min(minVisits,
                                                 m_visits[state][p]);
        }
        uint32_t action = 0;
        if (minVisits < 3) {
            std::array<uint32_t, N_PATHS> candidates{};
            uint32_t count = 0;
            for (uint32_t p = 0; p < N_PATHS; ++p) {
                if (allowed[p] && m_visits[state][p] == minVisits)
                    candidates[count++] = p;
            }
            action = candidates[m_rng->GetInteger(0, count - 1)];
        } else if (m_rng->GetValue() < m_epsilon) {
            std::array<uint32_t, N_PATHS> candidates{};
            uint32_t count = 0;
            for (uint32_t p = 0; p < N_PATHS; ++p) {
                if (allowed[p]) candidates[count++] = p;
            }
            action = candidates[m_rng->GetInteger(0, count - 1)];
        } else {
            action = StableArgMax(state, previous, allowed);
        }
        uint32_t safest = ChooseSafeHeuristic(cls, previous, allowed);
        if (PathCost(cls, action, previous)
            > PathCost(cls, safest, previous) + GuardMargin(cls)) {
            m_lastSafetyFallback[c] = true;
            action = safest;
        }
        ++m_visits[state][action];
        return action;
    }

    uint32_t ChooseHeuristic(RlTrafficClass cls, uint32_t previous) const {
        std::array<bool, N_PATHS> all{true, true, true};
        return ChooseSafeHeuristic(cls, previous, all);
    }

    uint32_t ChooseSafeHeuristic(
        RlTrafficClass cls, uint32_t previous,
        const std::array<bool, N_PATHS>& allowed) const {
        uint32_t best = m_gatewayId;
        double bestCost = std::numeric_limits<double>::max();
        for (uint32_t p = 0; p < N_PATHS; ++p) {
            if (!allowed[p]) continue;
            double cost = PathCost(cls, p, previous);
            if (cost < bestCost) {
                bestCost = cost;
                best = p;
            }
        }
        return best;
    }

    double PathCost(RlTrafficClass cls, uint32_t path,
                    uint32_t previous) const {
        const RlPathState& s = m_paths[path];
        double delayWeight = cls == RlTrafficClass::NORMAL ? 0.5 : 1.0;
        return delayWeight * s.delayMs
             + 60.0 * s.queueRatio
             + 200.0 * s.loss
             + (path == previous ? 0.0 : 1.0);
    }

    static double GuardMargin(RlTrafficClass cls) {
        if (cls == RlTrafficClass::EMERGENCY) return 1.5;
        if (cls == RlTrafficClass::IMPORTANT) return 2.0;
        return 3.0;
    }

    uint32_t ArgMaxAllowed(
        uint32_t state, const std::array<bool, N_PATHS>& allowed) const {
        uint32_t best = 0;
        while (best + 1 < N_PATHS && !allowed[best]) ++best;
        for (uint32_t p = best + 1; p < N_PATHS; ++p) {
            if (allowed[p] && m_q[state][p] > m_q[state][best]) best = p;
        }
        return best;
    }

    uint32_t StableArgMax(
        uint32_t state, uint32_t previous,
        const std::array<bool, N_PATHS>& allowed) const {
        previous = std::min(previous, N_PATHS - 1);
        uint32_t best = ArgMaxAllowed(state, allowed);
        // Scale the dead band with class severity: severity also scales the
        // reward, hence the Q magnitudes, so a fixed margin would act as a
        // proportionally weaker brake on exactly the class where path churn is
        // most expensive.
        double margin = Q_SWITCH_MARGIN * ClassSeverity(ClassOfState(state));
        if (best != previous && allowed[previous]
            && m_q[state][best] < m_q[state][previous] + margin) {
            return previous;
        }
        return best;
    }

    std::array<bool, N_PATHS> AllowedActions(uint32_t state) const {
        std::array<bool, N_PATHS> allowed{true, true, true};
        if (!m_safeMask) return allowed;

        uint32_t health = HealthOfState(state);
        std::array<uint32_t, N_PATHS> bins{
            health / 9, (health / 3) % 3, health % 3};
        uint32_t minimum = *std::min_element(bins.begin(), bins.end());
        for (uint32_t p = 0; p < N_PATHS; ++p)
            allowed[p] = bins[p] == minimum;
        return allowed;
    }

    static bool AllPathsDegraded(uint32_t state) {
        return HealthOfState(state) == N_HEALTH_COMBINATIONS - 1;
    }

    uint32_t MinHealth() const {
        uint32_t minimum = 2;
        for (const auto& path : m_paths)
            minimum = std::min(minimum, HealthBin(path));
        return minimum;
    }

    uint32_t EncodeState(RlTrafficClass cls, uint32_t previous) const {
        uint32_t health = HealthBin(m_paths[0]) * 9
                        + HealthBin(m_paths[1]) * 3
                        + HealthBin(m_paths[2]);
        std::array<bool, N_PATHS> all{true, true, true};
        // `previous` still reaches the state indirectly: PathCost charges a
        // switch penalty, so it can tip which path counts as best.
        uint32_t bestPath = ChooseSafeHeuristic(cls, previous, all);
        return (ClassIndex(cls) * N_HEALTH_COMBINATIONS + health) * N_PATHS
             + bestPath;
    }

    // Health combination packed into a state, as three per-path bins.
    static uint32_t HealthOfState(uint32_t state) {
        return (state % CLASS_STRIDE) / N_PATHS;
    }

    static uint32_t HealthBin(const RlPathState& state) {
        if (state.queueRatio >= 0.70 || state.loss >= 0.05
            || state.delayMs >= 80.0) return 2;
        if (state.queueRatio >= 0.30 || state.loss >= 0.01
            || state.delayMs >= 30.0) return 1;
        return 0;
    }

    static uint32_t ClassIndex(RlTrafficClass cls) {
        return std::min(static_cast<uint32_t>(cls), 2u);
    }

    static double DeadlineMs(RlTrafficClass cls) {
        if (cls == RlTrafficClass::EMERGENCY) return 100.0;
        if (cls == RlTrafficClass::IMPORTANT) return 300.0;
        return 1000.0;
    }

    // How much worse it is to drop or time out a message of this class.  A
    // missed EMERGENCY alarm is a plant-safety event; a late NORMAL telemetry
    // sample is routine, so the two must not share one penalty weight.
    // States are class-strided (class index = state / CLASS_STRIDE) and argmax
    // never compares across classes, so scaling rewards per class does not
    // distort action selection.
    static double ClassSeverity(RlTrafficClass cls) {
        if (cls == RlTrafficClass::EMERGENCY) return 3.0;
        if (cls == RlTrafficClass::IMPORTANT) return 1.5;
        return 1.0;
    }

    static RlTrafficClass ClassOfState(uint32_t state) {
        uint32_t index = std::min(state / CLASS_STRIDE, N_CLASSES - 1);
        return static_cast<RlTrafficClass>(index);
    }

    double FeedbackTimeoutMs(RlTrafficClass cls) const {
        // A route that already missed its QoS deadline must affect path health
        // promptly; the configured timeout remains a global upper bound.
        return std::min(m_timeoutMs, DeadlineMs(cls) + 50.0);
    }

    uint32_t m_gatewayId = 0;
    RlMode m_mode = RlMode::OFF;
    double m_alpha = 0.10;
    static constexpr double Q_SWITCH_MARGIN = 0.20;

    double m_gamma = 0.90;
    double m_epsilon = 0.20;
    double m_decisionMs = 100.0;
    double m_timeoutMs = 1500.0;
    bool m_safeMask = true;
    Ptr<UniformRandomVariable> m_rng;
    std::ostream* m_transitionCsv = nullptr;
    bool m_loadedAny = false;
    uint64_t m_messageCounter = 0;
    uint64_t m_windowCounter = 0;
    std::array<uint32_t, N_CLASSES> m_prevPath{};
    std::array<uint64_t, N_CLASSES> m_activeWindow{};
    std::array<bool, N_CLASSES> m_lastSafetyFallback{};
    std::array<RlPathState, N_PATHS> m_paths{};
    std::array<std::array<double, N_PATHS>, N_STATES> m_q{};
    std::array<std::array<uint64_t, N_PATHS>, N_STATES> m_visits{};
    std::map<uint64_t, Window> m_windows;
    std::unordered_map<uint64_t, Pending> m_pending;
};

inline RlMode ParseRlMode(const std::string& mode) {
    if (mode == "heuristic") return RlMode::HEURISTIC;
    if (mode == "train") return RlMode::TRAIN;
    if (mode == "qtable") return RlMode::QTABLE;
    return RlMode::OFF;
}

inline RlTrafficClass ParseRlTrafficClass(const std::string& cls) {
    if (cls == "EMERGENCY") return RlTrafficClass::EMERGENCY;
    if (cls == "IMPORTANT") return RlTrafficClass::IMPORTANT;
    return RlTrafficClass::NORMAL;
}

inline uint8_t RlTrafficClassId(RlTrafficClass cls) {
    return static_cast<uint8_t>(cls);
}

} // namespace ns3
