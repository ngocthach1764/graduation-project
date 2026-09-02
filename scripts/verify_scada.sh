#!/usr/bin/env bash
set -euo pipefail

PY="${PY:-../../.venv/bin/python}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_DIR:-output/verification_${STAMP}}"
SCENE="${SCENE:-12}"

test ! -e "$OUT_DIR" || {
  echo "Refusing to overwrite existing directory: $OUT_DIR" >&2
  exit 2
}
[ -x "$PY" ] || {
  echo "Python environment not found: $PY (set PY=/path/to/python)" >&2
  exit 2
}

./ns3 build scada
"$PY" -m unittest tests/test_static_contracts.py
./ns3 run "scada --mode=rf --run=99001 --sceneDur=$SCENE --rlMode=heuristic --rlLossRecoveryMs=2000 --modbusSemanticAlarms=1 --qosShiftWorkload=1 --packetCsv=1 --featureCsv=0 --flowXml=0 --runtimeMlCsv=1 --outDir=$OUT_DIR/"
"$PY" ml/build_behavior_features.py \
  --packets "$OUT_DIR/scada_packets.csv" \
  --out "$OUT_DIR/scada_features_offline.csv"
"$PY" tests/compare_feature_parity.py \
  --offline "$OUT_DIR/scada_features_offline.csv" \
  --runtime "$OUT_DIR/scada_runtime_ml.csv"
"$PY" scripts/write_experiment_manifest.py \
  --out "$OUT_DIR/manifest.json" --suite verification \
  --parameter "sceneDur=$SCENE" --parameter run=99001 \
  --artifact build/scratch/scada/ns3.47-scada-optimized \
  --artifact scratch/scada/scada_binary_manifest.json \
  --artifact "$OUT_DIR/scada_packets.csv" \
  --artifact "$OUT_DIR/scada_runtime_ml.csv"

echo "Verification passed: $OUT_DIR"
