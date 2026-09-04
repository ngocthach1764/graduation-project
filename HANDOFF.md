# Handoff — SCADA ns-3 project

Cập nhật: 2026-09-03. Repo WSL:
`/home/ngthach1706/ns3-major-project/ns-allinone-3.47/ns-3.47`.

## Trạng thái hiện tại

- Git đã được khởi tạo trên branch `main`; baseline overlay là `e240352`.
- `output/` và `rl/outputs/` được giữ nguyên trên đĩa, không track bởi Git và
  không bị xóa trong đợt hoàn thiện này.
- Phần mã dự án được giới hạn ở `scratch/scada`, `ml`, `rl`, `scripts`, `tests`
  cùng ba file tài liệu; source ns-3 bundled không được đưa vào commit.
- Build C++ đã thành công. Smoke run `99001`, `sceneDur=12` đã xuất 17.371 packet
  row; parity đạt 4.376 message x 20 feature giữa Python và C++. Artifact kiểm
  tra nằm ở `output/verification_codex_20260902/` và có manifest SHA-256.

## Những thay đổi đã hoàn thiện

1. Đồng bộ clock end-to-end: `originTimeNs` được chụp tại OT Tx event, đi qua
   `PendingPublish` và vào `ScadaMqttHeader`. Delivery delay nay bao gồm thời
   gian lazy connect/pending queue và cùng mốc với RL timeout.
2. RL path recovery: timeout-derived loss suy giảm theo hàm mũ bằng
   `--rlLossRecoveryMs` (mặc định 2000 ms), tránh safe mask khóa path mãi mãi.
3. Modbus semantic alarms: slave có incident window, response mang EVENT và
   IMPORTANT/EMERGENCY; mỗi incident nay bị chặn bởi số response đã lập lịch
   (hoặc duration), không biến mọi poll trong cửa sổ thành alarm.
4. Packet error model được mô hình hai chiều, độc lập theo receiver; CLI đã ghi
   đúng là packet error rate thay vì BER.
5. QoS workload dịch chuyển: `--qosShiftWorkload=1` giữ một report budget theo
   pha và đổi mix IMPORTANT:EMERGENCY `3:1 -> 1:1 -> 1:3`. Mặc định
   `qosShiftReportsNormal/High/Emergency=160/105/60` được hiệu chỉnh cho RF,
   `sceneDur=40`, để assigned urgent load không tăng theo pha chỉ vì workload.
6. QoS controller: đây là policer/marker, không phải shaper. EWMA làm mượt tử
   số/mẫu số riêng nên cửa sổ rỗng không giả thành `mu=0`; feedback mặc định là
   deadline miss. Controller điều khiển `r_E`, suy ra `r_I=C-r_E`, vì vậy tổng
   budget chính xác ở mọi tick. CSV có `feedback_mass`, `total_rate_kbps` và
   `budget_error_kbps`.
7. Reproducibility: P12 sửa thành train `1 2 3 4 5 9 10 11`, validation
   `6 12 13 14`, test `7 8`, `--cv-folds 12`; output mới có timestamp/manifest
   và script không còn `rm -rf` kết quả cũ.
8. Tests: contract feature/model/RL/QoS, kiểm tra budget trên CSV và đối chiếu
   đủ 20 feature giữa Python offline với C++ runtime.

## Compatibility với kết quả cũ

Artifact cũ được sinh trước Modbus event, RL recovery và workload shift. Khi cần
tái tạo đúng môi trường legacy, dùng:

```text
--rlLossRecoveryMs=0 --modbusSemanticAlarms=0 --qosShiftWorkload=0
```

Error model hai chiều/độc lập thay đổi RNG consumption so với binary cũ. Vì vậy
so sánh trước/sau phải chạy lại tất cả arm trên cùng commit mới, cùng run ID;
không ghép CSV cũ và mới thành một bảng thống kê.

Q-table schema hiện tại là `health_best_v4_sev`, 243 state/gateway. Table cùng
schema vẫn load được, nhưng table train khi recovery bằng 0 cần đánh giá lại nếu
deployment dùng recovery 2000 ms.

## Kết quả sanity QoS (chưa phải claim thống kê)

Lượt 3 seed `40..42`, budget 6 kbps, workload shift đã hiệu chỉnh nằm ở
`output/qos_dynamic_calibrated_20260902/`. Deadline feedback tốt hơn nhẹ so với
demotion feedback (`weighted_cost` 42.422 so với 43.474), nhưng RF dynamic vẫn
thua static `1.5/4.5` (38.310). Nguyên nhân quan sát được là RF false-positive
đẩy nhiều traffic sang IMPORTANT, nên mix mà controller thấy vẫn I-heavy dù mix
true class đã đổi. Không được dùng ba seed này để tuyên bố ưu thế.

Oracle check cùng ba seed nằm ở `output/qos_dynamic_oracle_20260902/`. Dynamic
di chuyển rate Emergency trung bình khoảng `2.61 -> 3.58 -> 3.96` kbps qua ba
pha, giữ tổng đúng 6 kbps, và có mean cost 252.082 so với static tốt nhất theo
mean 255.035. Đây chỉ là kiểm tra cơ chế: miss tuyệt đối cao do stress background
và mẫu quá nhỏ; cần suite canonical 15 seed cùng confidence interval.

Tương tự, kết quả RL lịch sử chỉ dùng để tham khảo. Sau khi sửa timestamp và
recovery cần retrain/evaluate đủ `off`, `heuristic`, `qtable` trên seed chưa thấy.

## Lệnh bàn giao

Kiểm tra nhanh, tạo thư mục output mới và manifest:

```bash
bash scripts/verify_scada.sh
```

Audit QoS paired-seed canonical (mặc định 15 seed, RF + oracle):

```bash
bash scripts/run_qos_audit.sh
```

`RUN_COUNT=3` dùng cho smoke; `INCLUDE_ORACLE=0` chỉ chạy RF. Audit gồm
`priority_only`, ba static split và dynamic. `priority_only` giữ nguyên
DSCP/PrioQueueDisc nhưng tắt meter và controller, nên là đối chứng matched để
tách ảnh hưởng của policing. Script không ghi đè output, kiểm tra budget từng
dynamic run, tạo `qos_metrics.csv` và manifest.
Canonical QoS audit đặt tường minh `rlBgTos=0` (BE). Không bỏ cờ này: mặc định
`rlBgTos=184` được dùng cho stress test RL và sẽ đưa background vào cùng băng
EF với Emergency, làm sai mục tiêu của phép ablation QoS.

Tái lập P12 từ dữ liệu thô mới:

```bash
bash ml/make_report_figs.sh
```

Script P12 mặc định export model vào chính thư mục thí nghiệm. Chỉ đặt
`INSTALL_MODELS=1` khi chủ động muốn cài các header vừa train vào
`scratch/scada/` và build runtime inference.

## Việc nghiên cứu tiếp theo

1. Chạy `scripts/run_qos_audit.sh` đủ tối thiểu 15 seed; thêm bootstrap CI cho
   paired difference dynamic-vs-best-static trước khi viết claim. Nếu RF vẫn
   thua nhưng oracle thắng, hiệu chỉnh/retrain classifier bằng objective của
   closed loop thay vì chỉnh controller theo ba seed sanity.
2. Retrain Q-table với recovery 2000 ms, đánh giá trên run ID mới và kiểm tra
   path có trở lại sau giai đoạn lỗi hay không.
3. Nếu cần tuyên bố “ML đa giao thức gồm Modbus”, phải thu thập/tạo feature
   Modbus và train model thật; hiện Modbus là semantic rule.
4. Nếu cần latency gateway vật lý, thay zero-delay Tx trace proxy bằng application
   nhận OT frame thực trên gateway rồi mới publish MQTT.

## File nên đọc trước

- `README.md`: kiến trúc, phạm vi và cách chạy canonical.
- `scratch/scada/scada.cc`: topology, classification, routing, QoS, workload.
- `scratch/scada/protocols.{h,cc}`: ứng dụng giao thức và MQTT framing.
- `scratch/scada/rl_agent.h`: state/reward/mask/recovery.
- `ml/make_report_figs.sh`: split P12 và quy trình tái lập.
- `tests/`: contract và feature parity.
