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
  --mode=rf --mlTauDnp3=0.01 --mlTauIec104=0.01 --mlTauOpcua=0.21 \
  --run="$RUN" --sceneDur=40 --rlMode=heuristic \
  --qosShiftWorkload=1 --qosShiftFactor=3 \
  --qosShiftReportsNormal=160 --qosShiftReportsHigh=105 \
  --qosShiftReportsEmergency=60 --qosMode=private \
  --meterEfKbps=3 --meterAf31Kbps=3 --meterBurstBytes=2000 \
  --qosCtrl=1 --qosCtrlBudget=6 --qosCtrlMs=100 \
  --qosCtrlMemMs=5000 --qosCtrlBeta=2 --qosCtrlMinFrac=0.5 \
  --qosCtrlMaxStep=0.1 --qosCtrlDemoteSignal=0 \
  --brokerBw=5Mbps --rlCongestion=1 --rlBgLoad=0.85 \
  --rlBgTos=0 --rlBgBurst=8 --bgWhere=master --bgFull=1 \
  --queueLen=1000 --devQueue=10 --qosQueueCsv=100 \
  --packetCsv=0 --featureCsv=0 --flowXml=0 --runtimeMlCsv=0 \
  --outDir="$OUT_DIR/"

"$PY" tests/check_qos_run.py "$OUT_DIR" --budget-kbps 6
"$PY" scripts/print_qos_summary.py run "$OUT_DIR" \
  --scene-dur 40 --budget-kbps 6
echo "OUTPUT_DIR=$OUT_DIR"
