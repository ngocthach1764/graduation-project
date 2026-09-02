# SCADA multi-protocol routing, ML classification and QoS

Dự án mô phỏng một hệ SCADA đa giao thức trên ns-3.47: Modbus TCP, DNP3,
IEC 60870-5-104 và OPC UA ở miền OT; MQTT ở miền northbound; phân loại mức
khẩn cấp bằng DT/RF; định tuyến ba đường bằng heuristic hoặc Q-learning; và
QoS bằng DSCP, hàng đợi ưu tiên, token-bucket cùng bộ điều khiển động.

## Cấu trúc dự án

| Thư mục | Vai trò |
|---|---|
| `scratch/scada/` | Mô hình mạng, ứng dụng giao thức, feature runtime, ML nhúng và RL |
| `ml/` | Dựng 20 feature nhân quả, tune/evaluate DT-RF, xuất model C/C++ |
| `rl/` | Train và đánh giá Q-table theo gateway |
| `scripts/` | Manifest thí nghiệm và kiểm tra end-to-end |
| `tests/` | Contract tĩnh và đối chiếu feature Python/C++ |
| `output/` | Kết quả mô phỏng; được giữ trên đĩa nhưng không theo dõi bởi Git |

Git chỉ quản lý phần overlay của đồ án, không quản lý toàn bộ source ns-3 được
bundled trong thư mục này. Commit baseline ban đầu là `e240352`.

## Luồng dữ liệu

```text
OT device response
  -> translation proxy tại Station
  -> 20 behavior features
  -> DT/RF NORMAL hoặc URGENT
  -> semantic parser IMPORTANT hoặc EMERGENCY
  -> DSCP / shaper
  -> heuristic hoặc Q-learning chọn một trong ba path
  -> MQTT Broker
  -> SCADA Master và delivery feedback
```

`OnOtUplink` hiện được nối với trace Tx của thiết bị và đóng vai trò translation
proxy không trễ. Timestamp gốc được chụp tại trace này rồi mang xuyên suốt hàng
đợi kết nối MQTT. Vì vậy delivery delay và RL timeout dùng cùng một mốc, bao gồm
cả thời gian lazy TCP connect/pending queue. Đây chưa phải mô hình gateway nhận
OT frame qua một application/socket riêng; không nên diễn giải kết quả như độ
trễ xử lý gateway vật lý hoàn chỉnh.

## Chạy nhanh

Từ thư mục gốc ns-3 trong WSL:

```bash
./ns3 build scada
./ns3 run "scada --run=1 --sceneDur=30 --mode=rf \
  --rlMode=heuristic --outDir=output/demo_run1/"
```

Các chế độ chính:

- `--mode=`: expert/oracle reference; `dt` hoặc `rf`: phân loại ML nhúng.
- `--rlMode=off|heuristic|train|qtable`: chính sách chọn đường tại ba Station.
- `--qosMode=private|neutral|fifo`: mức hỗ trợ DSCP của miền vận chuyển.
- `--qosCtrl=1`: điều khiển động ngân sách IMPORTANT/EMERGENCY.
- `--qosShiftWorkload=1 --qosShiftFactor=3`: workload phi dừng, IMPORTANT trội
  ở normal và EMERGENCY trội ở emergency để đánh giá khả năng thích nghi.
- `--modbusSemanticAlarms=1`: ánh xạ alarm-register Modbus thành event khẩn cấp.
- `--rlLossRecoveryMs=2000`: loss ước lượng do timeout tự phục hồi theo hàm mũ;
  đặt `0` để tái tạo hành vi legacy.

`errAccess`, `errCore` và `errMesh` là packet error rate, không phải BER. Mỗi
hướng nhận có một `RateErrorModel` độc lập và access link được mô hình hai chiều.

## Phạm vi ML và Modbus

Model nhúng hiện có cho DNP3, IEC104 và OPC-UA. `scada_binary_manifest.json`
định nghĩa đúng 20 feature và ngưỡng của sáu model DT/RF. Modbus chưa có model
học máy; event Modbus được phân lớp bằng semantic alarm-register tại translation
proxy. Khi báo cáo kết quả phải tách rõ “ML urgency detection” của ba giao thức
và “semantic rule” của Modbus.

Kiểm tra contract model/feature:

```bash
python3 -m unittest tests/test_static_contracts.py
```

## RL

Mỗi gateway có Q-table riêng. State schema đang dùng là
`health_best_v4_sev`, gồm 243 state:

```text
(traffic_class, health_path0, health_path1, health_path2, best_current_path)
```

Safe action mask chỉ cho chọn path trong health bin tốt nhất. Loss do timeout
không còn khóa path vĩnh viễn: `rlLossRecoveryMs` điều khiển hằng số thời gian
phục hồi. Các Q-table cũ khác schema bị từ chối; Q-table v4 cũ vẫn đọc được
nhưng nên đánh giá lại vì dynamics mặc định nay có recovery. Chi tiết ở
[`rl/README.md`](rl/README.md).

## Tái lập và kiểm thử

Bộ P12 chuẩn dùng train `1 2 3 4 5 9 10 11`, validation `6 12 13 14`, test
`7 8` và 12-fold run-level CV:

```bash
bash ml/make_report_figs.sh
```

Script tạo thư mục `output/repro_p12_<UTC>/` mới, ghi manifest Git/hash và từ
chối ghi đè. Nó không xóa output cũ. Đặt `INSTALL_MODELS=1` chỉ khi muốn copy
model vừa train vào `scratch/scada/` và chạy kiểm chứng inference nhúng.

Kiểm tra build + smoke + parity Python/C++:

```bash
bash scripts/verify_scada.sh
```

Mỗi lần chạy tạo `output/verification_<UTC>/` mới. Có thể đặt `OUT_DIR` và
`SCENE`; script cũng từ chối ghi đè thư mục đã tồn tại.

Để tái tạo đúng các artifact legacy trước thay đổi này, thêm:

```text
--rlLossRecoveryMs=0 --modbusSemanticAlarms=0 --qosShiftWorkload=0
```

## Nguyên tắc kết quả

- Không gộp run train, validation và test.
- Không dùng dữ liệu transition/warm-up để train.
- Chỉ công bố ưu thế QoS controller sau khi chạy cùng seed, cùng tổng budget và
  báo cáo confidence interval; workload dịch chuyển mới là testbed, chưa tự nó
  chứng minh controller tốt hơn static.
- Không xóa hay ghi đè `output/`; mỗi suite dùng thư mục mới kèm manifest.
