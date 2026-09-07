#!/usr/bin/env bash
# Generate behavior-only runtime features for QoS-aware ML training.  The
# classifier decision cannot affect these features: they are captured on the
# OT uplink before DSCP marking, queueing, and the Master bottleneck.
set -euo pipefail

OUT_DIR="${OUT_DIR:-output/ml_training_dataset}"
RUN_START="${RUN_START:-60}"
RUN_COUNT="${RUN_COUNT:-45}"
SCENE="${SCENE:-40}"

test ! -e "$OUT_DIR" || {
  echo "Refusing to overwrite existing directory: $OUT_DIR" >&2
  exit 2
}

./ns3 build scada
mkdir -p "$OUT_DIR"

for ((offset=0; offset<RUN_COUNT; ++offset)); do
  run=$((RUN_START + offset))
  out="$OUT_DIR/run${run}"
  build/scratch/scada/ns3.47-scada-optimized \
    --mode=rf --run="$run" --sceneDur="$SCENE" --rlMode=off \
    --qosShiftWorkload=1 --qosShiftFactor=3 \
    --qosShiftReportsNormal=160 --qosShiftReportsHigh=105 \
    --qosShiftReportsEmergency=60 \
    --packetCsv=0 --featureCsv=0 --flowXml=0 --runtimeMlCsv=1 \
    --qosQueueCsv=0 --outDir="$out/"
  test -s "$out/scada_runtime_ml.csv"
  rm -f -- "$out/qos_control.csv" "$out/qos_queues.csv" \
    "$out/rl_deliveries.csv" "$out/rl_transitions.csv"
  echo "dataset run=$run rows=$(( $(wc -l < "$out/scada_runtime_ml.csv") - 1 ))"
done

echo "ML training dataset complete: $OUT_DIR"
