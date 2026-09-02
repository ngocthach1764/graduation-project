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


if __name__ == "__main__":
    unittest.main()
