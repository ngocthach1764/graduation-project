#!/usr/bin/env bash
# Reproduce the P12 DT/RF split without deleting or overwriting old output.
set -euo pipefail

PY="${PY:-../../.venv/bin/python}"
SCENE="${SCENE:-100}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT="${OUT_ROOT:-output/repro_p12_${STAMP}}"
SKIP_DATA="${SKIP_DATA:-0}"
SKIP_TUNE="${SKIP_TUNE:-0}"
INSTALL_MODELS="${INSTALL_MODELS:-0}"

TRAIN_RUNS="1 2 3 4 5 9 10 11"
VALID_RUNS="6 12 13 14"
TEST_RUNS="7 8"
DATA="$OUT_ROOT/data"
TUNE="$OUT_ROOT/tune"
MODEL_OUT="$OUT_ROOT/exported_models"
REPORT_OUT="$OUT_ROOT/report"

if [ -e "$OUT_ROOT" ]; then
  [ "$SKIP_DATA" = "1" ] || {
    echo "Refusing to overwrite existing directory: $OUT_ROOT" >&2
    exit 2
  }
else
  [ "$SKIP_DATA" = "0" ] || {
    echo "SKIP_DATA=1 requires an existing OUT_ROOT" >&2
    exit 2
  }
  mkdir -p "$OUT_ROOT"
fi

train_csv() { for r in $TRAIN_RUNS; do printf '%s/train/run%s/scada_features.csv ' "$DATA" "$r"; done; }
valid_csv() { for r in $VALID_RUNS; do printf '%s/validation/run%s/scada_features.csv ' "$DATA" "$r"; done; }
test_csv()  { for r in $TEST_RUNS; do printf '%s/test/run%s/scada_features.csv ' "$DATA" "$r"; done; }
step() { printf '\n=============== %s ===============\n' "$*"; }

[ -x "$PY" ] || { echo "Python is not executable: $PY" >&2; exit 1; }
"$PY" -c 'import numpy,pandas,sklearn,matplotlib,m2cgen'

step "Build simulator"
./ns3 build scada

if [ "$SKIP_DATA" = "0" ]; then
  step "Generate independent train/validation/test runs"
  gen() {
    local split="$1" run="$2" dir="$DATA/$split/run$2"
    ./ns3 run "scada --run=$run --sceneDur=$SCENE --rlMode=off --rlLossRecoveryMs=0 --modbusSemanticAlarms=0 --qosShiftWorkload=0 --packetCsv=1 --featureCsv=0 --flowXml=0 --runtimeMlCsv=0 --outDir=$dir/"
    "$PY" ml/build_behavior_features.py \
      --packets "$dir/scada_packets.csv" --out "$dir/scada_features.csv"
  }
  for run in $TRAIN_RUNS; do gen train "$run"; done
  for run in $VALID_RUNS; do gen validation "$run"; done
  for run in $TEST_RUNS; do gen test "$run"; done
fi

if [ "$SKIP_TUNE" = "0" ]; then
  step "Tune with the recorded 12-fold run-level CV"
  "$PY" ml/tune_binary_semantic.py \
    --csv-train $(train_csv) \
    --csv-validation $(valid_csv) \
    --csv-test $(test_csv) \
    --scope both --families dt rf --cv-folds 12 \
    --min-urgent-recall 0.95 --out "$TUNE"

  step "Export models into this experiment directory"
  "$PY" ml/export_binary_models.py \
    --csv-train $(train_csv) $(valid_csv) \
    --config-dir "$TUNE" --families dt rf --out "$MODEL_OUT"
fi

RUNTIME_ARGS=()
if [ "$INSTALL_MODELS" = "1" ]; then
  step "Install the freshly exported headers and run embedded inference"
  cp "$MODEL_OUT"/scada_binary_* scratch/scada/
  ./ns3 build scada
  for mode in dt rf; do
    dir="$OUT_ROOT/runtime_$mode"
    ./ns3 run "scada --mode=$mode --run=7 --sceneDur=$SCENE --rlMode=off --rlLossRecoveryMs=0 --modbusSemanticAlarms=0 --runtimeMlCsv=1 --packetCsv=0 --featureCsv=0 --flowXml=0 --outDir=$dir/"
  done
  RUNTIME_ARGS=(--runtime-dt "$OUT_ROOT/runtime_dt/scada_runtime_ml.csv"
                --runtime-rf "$OUT_ROOT/runtime_rf/scada_runtime_ml.csv")
fi

step "Generate report figures and tables"
"$PY" ml/plot_binary_results.py \
  --features-train $(train_csv) \
  --features-validation $(valid_csv) \
  --features-test $(test_csv) \
  --tune-dir "$TUNE" --model-dir "$MODEL_OUT" \
  "${RUNTIME_ARGS[@]}" --out "$REPORT_OUT"

"$PY" scripts/write_experiment_manifest.py \
  --out "$OUT_ROOT/manifest.json" --suite p12_binary_ml \
  --parameter "sceneDur=$SCENE" \
  --parameter "trainRuns=$TRAIN_RUNS" \
  --parameter "validationRuns=$VALID_RUNS" \
  --parameter "testRuns=$TEST_RUNS" \
  --parameter cvFolds=12 \
  --artifact build/scratch/scada/ns3.47-scada-optimized \
  --artifact "$MODEL_OUT/scada_binary_manifest.json"

if [ -n "${REPORT:-}" ] && [ -d "$REPORT" ]; then
  cp "$REPORT_OUT"/figs/*.png "$REPORT"/
fi
echo "Reproduction complete: $OUT_ROOT"
