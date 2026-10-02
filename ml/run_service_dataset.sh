#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${SCADA_PYTHON:-/home/ngthach1706/ns3-major-project/.venv/bin/python}"
START_RUN="${1:-201}"
END_RUN="${2:-215}"
SCENE_DUR="${SCENE_DUR:-20}"
PARALLEL="${PARALLEL:-4}"
DATASET="${DATASET:-$ROOT/output/service_flow_v1/data}"

generate_run() {
    set -euo pipefail
    local run="$1"
    local directory="$DATASET/run$run"
    mkdir -p "$directory"
    # Generate labels and observable flow windows under the same workload
    # profile used at deployment.  QoS and routing are disabled because they
    # act after the Station classification point, while qosShiftWorkload must
    # remain enabled to preserve the deployed service-class distribution.
    if [[ "${REBUILD_ONLY:-0}" != "1" ]]; then
        "$ROOT/build/scratch/scada/ns3.47-scada-optimized" \
            --run="$run" --sceneDur="$SCENE_DUR" --profile=qos \
            --mode=rf --rlMode=off --modbusServiceEvents=1 \
            --qosCtrl=0 --anim=0 --packetCsv=1 --featureCsv=0 \
            --runtimeMlCsv=0 --flowXml=0 --pcap=0 --outDir="$directory/" \
            >"$directory/simulation.log" 2>&1
    fi
    "$PYTHON" "$ROOT/ml/build_behavior_features.py" \
        --packets "$directory/scada_packets.csv" \
        --out "$directory/scada_features.csv" \
        >"$directory/features.log" 2>&1
    echo "run$run ready"
}

export ROOT PYTHON SCENE_DUR DATASET REBUILD_ONLY
export -f generate_run
seq "$START_RUN" "$END_RUN" | xargs -P "$PARALLEL" -I{} \
    bash -c 'generate_run "$1"' _ {}

echo "Dataset ready: $DATASET"
