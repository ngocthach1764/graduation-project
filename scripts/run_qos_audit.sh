#!/usr/bin/env bash
set -euo pipefail

PY="${PY:-../../.venv/bin/python}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_DIR:-output/qos_audit_${STAMP}}"
RUN_START="${RUN_START:-40}"
RUN_COUNT="${RUN_COUNT:-15}"
SCENE="${SCENE:-40}"
BUDGET="${BUDGET:-6}"
METER_BURST_BYTES="${METER_BURST_BYTES:-8000}"
INCLUDE_ORACLE="${INCLUDE_ORACLE:-1}"

test ! -e "$OUT_DIR" || {
  echo "Refusing to overwrite existing directory: $OUT_DIR" >&2
  exit 2
}
[ -x "$PY" ] || {
  echo "Python environment not found: $PY" >&2
  exit 2
}

./ns3 build scada
mkdir -p "$OUT_DIR"
analysis_args=()
artifacts=()

run_arm() {
  local classifier="$1" arm="$2" run="$3" ef="$4" af="$5" ctrl="$6"
  local out="$OUT_DIR/${classifier}_${arm}_run${run}"
  local mode_args=()
  local policy_args=(
    --qosEmergencyBorrow=0 --qosLossFeedback=0
    --qosCtrlDemoteSignal=0 --qosCtrlPressureOnly=0
  )
  if [ "$classifier" = rf ]; then
    # Thresholds are part of the locked RF artifact and are checked against
    # scada_binary_manifest.json by tests/test_static_contracts.py.
    mode_args=(--mode=rf)
  fi
  if [ "$ctrl" = 1 ]; then
    policy_args=(
      --qosEmergencyBorrow=1 --qosLossFeedback=0
      --qosCtrlDemoteSignal=1 --qosCtrlPressureOnly=1
      --qosCtrlPressurePower=2 --qosCtrlPressureHold=1
      --qosCtrlInitialEfFrac=0.25
    )
  fi

  build/scratch/scada/ns3.47-scada-optimized \
    "${mode_args[@]}" \
    --run="$run" --sceneDur="$SCENE" --rlMode=heuristic \
    --qosShiftWorkload=1 --qosShiftFactor=3 \
    --qosShiftReportsNormal=160 --qosShiftReportsHigh=105 \
    --qosShiftReportsEmergency=60 --qosMode=private \
    --meterEfKbps="$ef" --meterAf31Kbps="$af" \
    --meterBurstBytes="$METER_BURST_BYTES" \
    --qosCtrl="$ctrl" --qosCtrlBudget="$BUDGET" --qosCtrlMs=100 \
    --qosCtrlMemMs=5000 --qosCtrlBeta=2 --qosCtrlMinFrac=0.5 \
    --qosCtrlMaxStep=0.05 "${policy_args[@]}" \
    --brokerBw=5Mbps --rlCongestion=1 --rlBgLoad=0.85 \
    --rlBgTos=0 --rlBgBurst=8 --bgWhere=master --bgFull=1 \
    --queueLen=1000 --devQueue=10 --qosQueueCsv=100 \
    --packetCsv=0 --featureCsv=0 --flowXml=0 --runtimeMlCsv=0 \
    --outDir="$out/"

  analysis_args+=(--input "${classifier}_${arm}=$out")
  artifacts+=(--artifact "$out/rl_deliveries.csv")
  if [ "$ctrl" = 1 ]; then
    "$PY" tests/check_qos_run.py "$out" --budget-kbps "$BUDGET"
    artifacts+=(--artifact "$out/qos_control.csv")
  fi
}

for ((offset=0; offset<RUN_COUNT; ++offset)); do
  run=$((RUN_START + offset))
  run_arm rf static15_45 "$run" 1.5 4.5 0
  run_arm rf static30_30 "$run" 3.0 3.0 0
  run_arm rf static45_15 "$run" 4.5 1.5 0
  run_arm rf dynamic "$run" 3.0 3.0 1
  if [ "$INCLUDE_ORACLE" = 1 ]; then
    run_arm oracle static15_45 "$run" 1.5 4.5 0
    run_arm oracle static30_30 "$run" 3.0 3.0 0
    run_arm oracle static45_15 "$run" 4.5 1.5 0
    run_arm oracle dynamic "$run" 3.0 3.0 1
  fi
done

"$PY" scripts/analyze_qos_runs.py --scene-dur "$SCENE" --per-run \
  "${analysis_args[@]}" > "$OUT_DIR/qos_metrics.csv"
"$PY" scripts/plot_qos_results.py "$OUT_DIR" --scene-dur "$SCENE"
"$PY" scripts/print_qos_summary.py audit "$OUT_DIR"

"$PY" scripts/write_experiment_manifest.py \
  --out "$OUT_DIR/manifest.json" --suite qos_dynamic_audit \
  --command "bash scripts/run_qos_audit.sh" \
  --parameter "runStart=$RUN_START" --parameter "runCount=$RUN_COUNT" \
  --parameter "sceneDur=$SCENE" --parameter "budgetKbps=$BUDGET" \
  --parameter "meterBurstBytes=$METER_BURST_BYTES" \
  --parameter "feedback=meter_pressure_with_borrow" \
  --parameter "pressurePower=2" --parameter "pressureHold=1" \
  --parameter "initialEfFraction=0.25" --parameter "maxStep=0.05" \
  --parameter "backgroundTos=0(BE)" \
  --parameter "shiftReports=160,105,60" \
  --parameter "includeOracle=$INCLUDE_ORACLE" \
  --artifact build/scratch/scada/ns3.47-scada-optimized \
  --artifact "$OUT_DIR/qos_metrics.csv" \
  --artifact "$OUT_DIR/figures/qos-cost-comparison.pdf" \
  --artifact "$OUT_DIR/figures/qos-rate-trajectory.pdf" \
  --artifact "$OUT_DIR/figures/qos-rf-class-mix.pdf" \
  "${artifacts[@]}"

echo "QoS audit completed without overwriting old output: $OUT_DIR"
