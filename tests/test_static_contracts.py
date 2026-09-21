#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def python_features() -> list[str]:
    tree = ast.parse((ROOT / "ml/train_service_classifier.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "FEATURES":
                    return ast.literal_eval(node.value)
    raise AssertionError("service FEATURES not found")


def header_features() -> list[str]:
    text = (ROOT / "scratch/scada/scada_service_features.h").read_text()
    block = re.search(r"TRAINED_FEATURE_NAMES.*?\{(.*?)\};", text, re.S)
    if not block:
        raise AssertionError("TRAINED_FEATURE_NAMES not found")
    return re.findall(r'"([^"]+)"', block.group(1))


def header_thresholds() -> dict[tuple[str, str, str], float]:
    text = (ROOT / "scratch/scada/scada_service_config.h").read_text()
    result: dict[tuple[str, str, str], float] = {}
    protocols = ["unused", "Modbus", "DNP3", "IEC104", "OPC-UA"]
    pattern = re.compile(
        r"(DT|RF)_(TIME_CRITICAL|OPERATIONAL)_THRESHOLD"
        r"\[N_PROTOCOL_IDS\]\s*=\s*\{([^}]+)\}"
    )
    for family, service, values in pattern.findall(text):
        for protocol, value in zip(protocols, values.split(",")):
            if protocol != "unused":
                result[(family.lower(), protocol, service.lower())] = float(value)
    return result


class StaticContracts(unittest.TestCase):
    def test_feature_order_is_identical(self) -> None:
        manifest = json.loads(
            (ROOT / "scratch/scada/scada_service_manifest.json").read_text()
        )
        self.assertEqual(21, len(manifest["features"]))
        self.assertEqual(manifest["features"], python_features())
        self.assertEqual(manifest["features"], header_features())

    def test_rl_schema_and_size(self) -> None:
        source = (ROOT / "scratch/scada/rl_agent.h").read_text()
        self.assertIn('STATE_SCHEMA = "health_best_v4_sev"', source)
        self.assertIn("N_STATES = N_CLASSES * CLASS_STRIDE", source)
        self.assertIn("N_HEALTH_COMBINATIONS = 27", source)
        self.assertIn("lossRecoveryMs", source)

    def test_docs_do_not_advertise_stale_rl_schema(self) -> None:
        docs = "\n".join(
            (ROOT / name).read_text(encoding="utf-8")
            for name in ("README.md", "rl/README.md")
        )
        self.assertNotIn("health_best_prev_v3_sev", docs)
        self.assertNotIn("729 states", docs)
        self.assertIn("health_best_v4_sev", docs)

    def test_generated_models_cover_declared_ml_protocols(self) -> None:
        manifest = json.loads(
            (ROOT / "scratch/scada/scada_service_manifest.json").read_text()
        )
        expected = {"DNP3", "IEC104", "Modbus", "OPC-UA"}
        self.assertEqual(expected, set(manifest["models"]["dt"]["thresholds"]))
        self.assertEqual(expected, set(manifest["models"]["rf"]["thresholds"]))

    def test_generated_threshold_header_matches_manifest(self) -> None:
        manifest = json.loads(
            (ROOT / "scratch/scada/scada_service_manifest.json").read_text()
        )
        actual = header_thresholds()
        expected = {
            (family, protocol, service): float(value)
            for family, config in manifest["models"].items()
            for protocol, values in config["thresholds"].items()
            for service, value in values.items()
        }
        self.assertEqual(expected, actual)

    def test_canonical_qos_runs_use_locked_model_thresholds(self) -> None:
        for name in ("run_qos_audit.sh", "run_qos_dynamic_demo.sh"):
            script = (ROOT / "scripts" / name).read_text()
            self.assertNotIn("--mlTauDnp3", script)
            self.assertNotIn("--mlTauIec104", script)
            self.assertNotIn("--mlTauOpcua", script)

    def test_qos_controller_conserves_budget_by_construction(self) -> None:
        source = (ROOT / "scratch/scada/scada.cc").read_text()
        self.assertIn("violationNum", source)
        self.assertIn("violationDen", source)
        self.assertIn(
            "const double nextImportant = g_qosCtrlBudget - nextEmergency",
            source,
        )
        self.assertIn(
            "stationRate = kv.second * 1000.0 / stationCount", source
        )
        self.assertIn(
            "classRate - reserve * stationCount", source
        )
        self.assertIn("g_qosCtrl[2].rateBps = nextEmergency", source)
        self.assertIn("prediction.priorityEvidence >= g_qosSafetyRatio", source)
        self.assertIn('cmd.AddValue("qosSafetyPromote"', source)
        self.assertIn('cmd.AddValue("qosSafetyRatio"', source)
        self.assertIn("budget_error_kbps", source)
        self.assertIn("targetIncidentReports", source)

    def test_modbus_incidents_are_report_bounded(self) -> None:
        header = (ROOT / "scratch/scada/protocols.h").read_text()
        source = (ROOT / "scratch/scada/protocols.cc").read_text()
        self.assertIn("uint32_t responses", header)
        self.assertIn("m_incidentResponsesLeft", header)
        self.assertIn("--m_incidentResponsesLeft == 0", source)

    def test_ddos_generator_does_not_set_detector_state(self) -> None:
        source = (ROOT / "scratch/scada/scada.cc").read_text()
        truth_fn = re.search(
            r"static void SetDdosTruth\(bool active\) \{(.*?)\n\}",
            source,
            re.S,
        )
        self.assertIsNotNone(truth_fn)
        self.assertIn("g_ddosTruthActive = active", truth_fn.group(1))
        self.assertNotIn("SetSecurityState", truth_fn.group(1))
        self.assertIn(
            "g_ddosProtectUrgent && g_securityState != SecurityState::CLEAN",
            source,
        )

    def test_ddos_rf_runtime_feature_contract(self) -> None:
        source = (ROOT / "scratch/scada/scada.cc").read_text()
        header = (ROOT / "scratch/scada/scada_ddos_rf.h").read_text()
        expected = (
            "ingress_mbps, ingress_packets, mean_packet_bytes, "
            "unique_sources, source_entropy, dominant_source_frac, "
            "udp_frac, rate_delta_mbps"
        )
        self.assertIn('#include "scada_ddos_rf.h"', source)
        self.assertIn("double detectorFeatures[8]", source)
        self.assertIn("score_ddos_rf(detectorFeatures, detectorOutput)", source)
        self.assertIn("Feature order: " + expected, header)

    def test_ddos_observation_label_is_audit_only(self) -> None:
        source = (ROOT / "scratch/scada/scada.cc").read_text()
        sampler = re.search(
            r"static void SampleDdosDetector\(\) \{(.*?)\n\}",
            source,
            re.S,
        )
        self.assertIsNotNone(sampler)
        body = sampler.group(1)
        feature_vector = re.search(
            r"double detectorFeatures\[8\] = \{(.*?)\};", body, re.S
        )
        self.assertIsNotNone(feature_vector)
        self.assertNotIn("attackObserved", feature_vector.group(1))
        self.assertNotIn("g_ddosTruthActive", feature_vector.group(1))
        self.assertIn("udp.GetDestinationPort() == 9400", source)
        self.assertIn("attack_truth,attack_observed,transition", source)

    def test_ddos_burst_evidence_is_reset_between_fsm_stages(self) -> None:
        source = (ROOT / "scratch/scada/scada.cc").read_text()
        transition = re.search(
            r"static void SetSecurityState\(.*?\) \{(.*?)\n\}",
            source,
            re.S,
        )
        self.assertIsNotNone(transition)
        self.assertIn("g_ddosHighCount = 0", transition.group(1))
        self.assertIn("g_ddosLowCount = 0", transition.group(1))
        self.assertIn("g_ddosHighCount >= g_ddosAttackWindows", source)

    def test_runtime_and_delivery_logs_share_message_identity(self) -> None:
        source = (ROOT / "scratch/scada/scada.cc").read_text()
        self.assertIn(
            '"t,message_id,device_id,protocol_id,protocol,message_kind,baseline_ready,"',
            source,
        )
        self.assertIn("<< now << ',' << decision.messageId << ','", source)
        self.assertIn(
            '"t,message_id,source_gateway,path,traffic_class,device_id,"',
            source,
        )
        self.assertIn(
            '"message_true_class,message_deadline_ms,message_deadline_met,"',
            source,
        )
        self.assertIn(
            "ParseRlTrafficClass(windowTruthClass)",
            source,
        )
        self.assertIn(
            "g_msgMessageTrueClass[decision.messageId]",
            source,
        )
        self.assertIn(
            '"pred_service_class,priority_evidence,qos_safety_promoted,"',
            source,
        )
        inference = (ROOT / "scratch/scada/ml_inference.cc").read_text()
        self.assertIn("result.priorityEvidence = std::max", inference)


if __name__ == "__main__":
    unittest.main()
