#!/usr/bin/env bash
# =====================================================================
#  Sinh toan bo 11 hinh + 17 bang so lieu cho phan danh gia DT/RF.
#
#  Chay tu thu muc goc ns-3:   bash ml/make_report_figs.sh
#
#  Bien moi truong tuy chon:
#    PY        duong dan python co numpy/pandas/sklearn/matplotlib/m2cgen
#    SCENE     thoi luong moi kich ban, giay (mac dinh 100)
#    REPORT    thu muc Images/ cua bao cao, de tu dong chep hinh sang
#    SKIP_DATA =1 de bo qua Buoc 1-2 (dung lai du lieu da co)
#    SKIP_TUNE =1 de bo qua Buoc 3-5 (dung lai mo hinh da xuat)
# =====================================================================
set -euo pipefail

PY="${PY:-$HOME/ns3-major-project/.venv/bin/python}"
SCENE="${SCENE:-100}"
OUT=output/report_figs
SKIP_DATA="${SKIP_DATA:-0}"
SKIP_TUNE="${SKIP_TUNE:-0}"

TRAIN_RUNS="1 2 3 4 5"
VALID_RUN=6
TEST_RUNS="7 8"

train_csv() { for r in $TRAIN_RUNS; do printf 'output/ml_train/run%s/scada_features.csv ' "$r"; done; }
valid_csv() { printf 'output/ml_test/run%s/scada_features.csv ' "$VALID_RUN"; }
test_csv()  { for r in $TEST_RUNS;  do printf 'output/ml_final/run%s/scada_features.csv ' "$r"; done; }

step() { echo; echo "=============== $* ==============="; }

[ -x "$PY" ] || { echo "Khong tim thay python: $PY"; exit 1; }
"$PY" -c 'import numpy,pandas,sklearn,matplotlib,m2cgen' \
  || { echo "Python $PY thieu thu vien"; exit 1; }

# ---------------------------------------------------------------- Buoc 0
step "Buoc 0/6  Bien dich bo mo phong"
./ns3 build scada

# ---------------------------------------------------------------- Buoc 1+2
if [ "$SKIP_DATA" = "1" ]; then
  step "Buoc 1-2  BO QUA (SKIP_DATA=1), dung du lieu dac trung da co"
else
  step "Buoc 1/6  Sinh du lieu goi tho cho 8 lan chay doc lap"
  gen() {   # $1 = so hieu run, $2 = thu muc dich
    echo "  -> run $1 ($2)"
    ./ns3 run "scada --run=$1 --sceneDur=$SCENE --rlMode=off \
        --packetCsv=1 --featureCsv=0 --flowXml=0 --runtimeMlCsv=0 \
        --outDir=$2/" > /dev/null
  }
  for r in $TRAIN_RUNS; do gen "$r" "output/ml_train/run$r"; done
  gen "$VALID_RUN" "output/ml_test/run$VALID_RUN"
  for r in $TEST_RUNS;  do gen "$r" "output/ml_final/run$r"; done

  step "Buoc 2/6  Dung vector dac trung theo ban tin"
  for d in $(for r in $TRAIN_RUNS; do echo output/ml_train/run$r; done) \
           output/ml_test/run$VALID_RUN \
           $(for r in $TEST_RUNS; do echo output/ml_final/run$r; done); do
    echo "  -> $d"
    "$PY" ml/build_behavior_features.py \
        --packets "$d/scada_packets.csv" --out "$d/scada_features.csv" \
        | tail -1
  done
fi

# ---------------------------------------------------------------- Buoc 3-5
if [ "$SKIP_TUNE" = "1" ]; then
  step "Buoc 3-5  BO QUA (SKIP_TUNE=1), dung mo hinh da xuat"
else
  step "Buoc 3/6  Tinh chinh sieu tham so va nguong (pooled + per-protocol)"
  "$PY" ml/tune_binary_semantic.py \
      --csv-train      $(train_csv) \
      --csv-validation $(valid_csv) \
      --csv-test       $(test_csv) \
      --scope both --families dt rf \
      --min-urgent-recall 0.95 \
      --out output/ml_final_verification

  step "Buoc 4/6  Xuat 6 mo hinh sang ma C"
  "$PY" ml/export_binary_models.py \
      --csv-train  $(train_csv) $(valid_csv) \
      --config-dir output/ml_final_verification \
      --families dt rf \
      --out scratch/scada

  step "Buoc 5/6  Bien dich lai + chay mo phong voi bo phan loai bat"
  ./ns3 build scada
fi

for m in dt rf; do
  echo "  -> runtime $m"
  ./ns3 run "scada --mode=$m --run=${TEST_RUNS%% *} --sceneDur=$SCENE \
      --rlMode=off --runtimeMlCsv=1 --packetCsv=0 --featureCsv=0 \
      --flowXml=0 --outDir=output/report_runtime_$m/" | tail -2
done

# ---------------------------------------------------------------- Buoc 6
step "Buoc 6/6  Sinh 11 hinh + 17 bang so lieu"
rm -rf "$OUT/figs" "$OUT/tables"   # xoa hinh/bang cu de khong lan lon
"$PY" ml/plot_binary_results.py \
    --features-train      $(train_csv) \
    --features-validation $(valid_csv) \
    --features-test       $(test_csv) \
    --tune-dir   output/ml_final_verification \
    --model-dir  scratch/scada \
    --runtime-dt output/report_runtime_dt/scada_runtime_ml.csv \
    --runtime-rf output/report_runtime_rf/scada_runtime_ml.csv \
    --out "$OUT"

step "Ket qua"
echo "Hinh:  $(ls "$OUT"/figs/*.png | wc -l) tep trong $OUT/figs/"
ls -1 "$OUT"/figs/
echo
echo "Bang:  $(ls "$OUT"/tables/*.csv | wc -l) tep trong $OUT/tables/"

if [ -n "${REPORT:-}" ] && [ -d "$REPORT" ]; then
  cp "$OUT"/figs/*.png "$REPORT"/
  echo
  echo "Da chep hinh sang: $REPORT"
fi
