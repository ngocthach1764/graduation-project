#!/usr/bin/env bash
set -euo pipefail

PY="${PY:-../../.venv/bin/python}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_DIR:-output/qos_dynamic_demo_${STAMP}}"
RUN="${RUN:-300}"

test ! -e "$OUT_DIR" || {
  echo "Refusing to overwrite existing directory: $OUT_DIR" >&2
  exit 2
}
[ -x "$PY" ] || {
  echo "Python environment not found: $PY (set PY=/path/to/python)" >&2
  exit 2
}

./ns3 build scada
build/scratch/scada/ns3.47-scada-optimized \
  --profile=qos --run="$RUN" --sceneDur=40 --rlMode=heuristic \
  --qosQueueCsv=100 \
  --packetCsv=0 --featureCsv=0 --flowXml=0 --runtimeMlCsv=0 \
  --outDir="$OUT_DIR/"

"$PY" tests/check_qos_run.py "$OUT_DIR" --budget-kbps 100
"$PY" scripts/print_qos_summary.py run "$OUT_DIR" \
  --scene-dur 40 --budget-kbps 100
echo "OUTPUT_DIR=$OUT_DIR"
