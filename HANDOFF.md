# Handoff — SCADA ns-3 project

Cập nhật: 2026-09-02. Repo WSL:
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
   IMPORTANT/EMERGENCY; gateway dùng semantic rule vì chưa có model Modbus.
4. Packet error model được mô hình hai chiều, độc lập theo receiver; CLI đã ghi
   đúng là packet error rate thay vì BER.
5. QoS workload dịch chuyển: `--qosShiftWorkload=1` làm class trội thay đổi qua
   normal/high-load/emergency để đánh giá controller trong môi trường phi dừng.
6. Reproducibility: P12 sửa thành train `1 2 3 4 5 9 10 11`, validation
   `6 12 13 14`, test `7 8`, `--cv-folds 12`; output mới có timestamp/manifest
   và script không còn `rm -rf` kết quả cũ.
7. Tests: contract feature/model/RL schema và đối chiếu đủ 20 feature giữa
   Python offline với C++ runtime.

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

## Kết quả đã có nhưng không phải claim mới

Các artifact lịch sử trong `output/` từng cho thấy RF/DT phân loại urgency tốt
và calibrated RF giảm deadline miss rõ so với default threshold. QoS controller
cũ chưa thắng static split tốt nhất trên workload cũ. Vì thế workload shift mới
được thêm như testbed; chưa được ghi là kết luận cho đến khi chạy multi-seed và
confidence interval.

Tương tự, kết quả RL lịch sử chỉ dùng để tham khảo. Sau khi sửa timestamp và
recovery cần retrain/evaluate đủ `off`, `heuristic`, `qtable` trên seed chưa thấy.

## Lệnh bàn giao

Kiểm tra nhanh, tạo thư mục output mới và manifest:

```bash
bash scripts/verify_scada.sh
```

Tái lập P12 từ dữ liệu thô mới:

```bash
bash ml/make_report_figs.sh
```

Script P12 mặc định export model vào chính thư mục thí nghiệm. Chỉ đặt
`INSTALL_MODELS=1` khi chủ động muốn cài các header vừa train vào
`scratch/scada/` và build runtime inference.

## Việc nghiên cứu tiếp theo

1. Chạy QoS `static 1:3`, `static 3:1`, `dynamic` trên workload shift, tối thiểu
   15 seed; báo cáo miss theo class và weighted cost với CI.
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
