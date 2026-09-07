#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def python_features() -> list[str]:
    tree = ast.parse((ROOT / "ml/build_behavior_features.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "FEATURES_BEHAVIOR20":
                    return ast.literal_eval(node.value)
    raise AssertionError("FEATURES_BEHAVIOR20 not found")


def header_features() -> list[str]:
    text = (ROOT / "scratch/scada/scada_binary_features.h").read_text()
    block = re.search(r"TRAINED_FEATURE_NAMES.*?\{(.*?)\};", text, re.S)
    if not block:
        raise AssertionError("TRAINED_FEATURE_NAMES not found")
    return re.findall(r'"([^"]+)"', block.group(1))


def header_thresholds() -> dict[tuple[str, str], float]:
    text = (ROOT / "scratch/scada/scada_binary_config.h").read_text()
    result: dict[tuple[str, str], float] = {}
    pattern = re.compile(
        r"(?:inline\s+constexpr\s+double\s+)?"
        r"(DT|RF)_(DNP3|IEC104|OPCUA)_THRESHOLD\s*=\s*"
        r"([0-9]+(?:\.[0-9]+)?)"
    )
    protocol = {"DNP3": "DNP3", "IEC104": "IEC104", "OPCUA": "OPC-UA"}
    for family, stem, value in pattern.findall(text):
        result[(family.lower(), protocol[stem])] = float(value)
    return result


class StaticContracts(unittest.TestCase):
    def test_feature_order_is_identical(self) -> None:
        manifest = json.loads(
            (ROOT / "scratch/scada/scada_binary_manifest.json").read_text()
        )
        self.assertEqual(20, len(manifest["feature_names"]))
        self.assertEqual(manifest["feature_names"], python_features())
        self.assertEqual(manifest["feature_names"], header_features())

    def test_rl_schema_and_size(self) -> None:
        source = (ROOT / "scratch/scada/rl_agent.h").read_text()
        self.assertIn('STATE_SCHEMA = "health_best_v4_sev"', source)
        self.assertIn("N_STATES = N_CLASSES * CLASS_STRIDE", source)
        self.assertIn("N_HEALTH_COMBINATIONS = 27", source)
        self.assertIn("lossRecoveryMs", source)

    def test_docs_do_not_advertise_stale_rl_schema(self) -> None:
        docs = "\n".join(
            (ROOT / name).read_text(encoding="utf-8")
            for name in ("README.md", "HANDOFF.md", "rl/README.md")
        )
        self.assertNotIn("health_best_prev_v3_sev", docs)
        self.assertNotIn("729 states", docs)
        self.assertIn("health_best_v4_sev", docs)

    def test_generated_models_cover_declared_ml_protocols(self) -> None:
        manifest = json.loads(
            (ROOT / "scratch/scada/scada_binary_manifest.json").read_text()
        )
        expected = {"DNP3", "IEC104", "OPC-UA"}
        self.assertEqual(expected, set(manifest["models"]["dt"]))
        self.assertEqual(expected, set(manifest["models"]["rf"]))

    def test_generated_threshold_header_matches_manifest(self) -> None:
        manifest = json.loads(
            (ROOT / "scratch/scada/scada_binary_manifest.json").read_text()
        )
        actual = header_thresholds()
        expected = {
            (family, protocol): float(values["threshold"])
            for family, models in manifest["models"].items()
            for protocol, values in models.items()
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
        self.assertIn("budget_error_kbps", source)
        self.assertIn("targetIncidentReports", source)

    def test_modbus_incidents_are_report_bounded(self) -> None:
        header = (ROOT / "scratch/scada/protocols.h").read_text()
        source = (ROOT / "scratch/scada/protocols.cc").read_text()
        self.assertIn("uint32_t responses", header)
        self.assertIn("m_incidentResponsesLeft", header)
        self.assertIn("--m_incidentResponsesLeft == 0", source)


if __name__ == "__main__":
    unittest.main()
