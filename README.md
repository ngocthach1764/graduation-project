# SCADA multi-protocol routing, ML classification and QoS

Dự án mô phỏng một hệ SCADA đa giao thức trên ns-3.47: Modbus TCP, DNP3,
IEC 60870-5-104 và OPC UA ở miền OT; MQTT ở miền northbound; phân loại mức
khẩn cấp bằng DT/RF; định tuyến ba đường bằng heuristic hoặc Q-learning; và
QoS bằng DSCP, hàng đợi ưu tiên, token-bucket policer/marker cùng bộ điều
khiển động.

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
  -> DSCP / token-bucket policer-marker
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
- `--qosCtrl=1`: điều khiển động ngân sách profile IMPORTANT/EMERGENCY;
  feedback mặc định là deadline miss, dùng `--qosCtrlDemoteSignal=1` để thử
  tín hiệu demotion cục bộ.
- `--qosShiftWorkload=1 --qosShiftFactor=3`: workload phi dừng, IMPORTANT trội
  ở normal và EMERGENCY trội ở emergency để đánh giá khả năng thích nghi.
- `--qosShiftReportsNormal|High|Emergency`: tổng report khẩn cấp mục tiêu từng
  pha; mặc định `160/105/60` được hiệu chỉnh cho `sceneDur=40` và RF canonical.
- `--modbusSemanticAlarms=1`: ánh xạ alarm-register Modbus thành event khẩn cấp.
- `--rlLossRecoveryMs=2000`: loss ước lượng do timeout tự phục hồi theo hàm mũ;
  đặt `0` để tái tạo hành vi legacy.

`errAccess`, `errCore` và `errMesh` là packet error rate, không phải BER. Mỗi
hướng nhận có một `RateErrorModel` độc lập và access link được mô hình hai chiều.

## QoS động

Controller đo offered load và tỷ lệ vi phạm của hai lớp được meter, làm mượt
tử số/mẫu số EWMA riêng rồi phân bổ một tổng budget cố định. Nó chỉ điều khiển
một bậc tự do: `r_IMPORTANT = C - r_EMERGENCY`, nên tổng profile đúng bằng `C`
ở mọi chu kỳ kể cả khi có dead-band/slew limit. `qos_control.csv` ghi cả
`total_rate_kbps` và `budget_error_kbps`; đây là profile của policer/marker,
không phải bảo đảm tốc độ đầu ra như một traffic shaper có hàng đợi.

Workload shift giữ tổng report khẩn cấp theo từng pha và đảo tỷ lệ class
`3:1 -> 1:1 -> 1:3`. Alarm Modbus kết thúc sau đúng số response đã lập lịch
hoặc khi hết cửa sổ, tránh biến một incident thành alarm ở mọi poll.

Chạy một dynamic run và in bảng terminal gọn để kiểm tra/chụp minh họa:

```bash
bash scripts/run_qos_dynamic_demo.sh
```

Chạy audit canonical (15 seed, priority-only, ba static split, dynamic, RF và
oracle):

```bash
bash scripts/run_qos_audit.sh
```

Script tạo `output/qos_audit_<UTC>/`, kiểm tra conservation cho từng dynamic
run, pool kết quả vào `qos_metrics.csv`, in bảng terminal, tạo ba hình PDF/PNG,
ghi manifest/hash và từ chối ghi đè.
Cánh tay `priority_only` vẫn giữ DSCP và `PrioQueueDisc` của private mode nhưng
tắt cả hai meter (`meterEfKbps=-1`, `meterAf31Kbps=-1`) và controller. Vì mọi
tham số còn lại giống các cánh tay khác, đây là ablation dùng để đo riêng tác
động của token-bucket policing.
Audit QoS truyền tường minh `rlBgTos=0`, nên nguồn nền 0,85 tải liên kết là BE
và không cạnh tranh trong băng EF của Emergency. Giá trị mặc định của chương
trình vẫn phục vụ các thí nghiệm gây nghẽn RL khác và không được dùng ngầm cho
audit QoS.
Có thể smoke nhanh bằng `RUN_COUNT=3`; đặt `INCLUDE_ORACLE=0` nếu chỉ cần RF.
Các target report mặc định được hiệu chỉnh tại `sceneDur=40`, vì vậy đổi
`SCENE` thì phải kiểm tra lại assigned urgent load trước khi so sánh.

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

Kiểm tra riêng một dynamic run:

```bash
python3 tests/check_qos_run.py output/<run>/ --budget-kbps 6
```

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
- Báo cáo riêng oracle và RF. Nếu oracle thích nghi nhưng RF không thắng static,
  đó là giới hạn của classifier/threshold trong closed loop, không được gộp
  thành kết luận rằng controller đã thắng end-to-end.
- Không xóa hay ghi đè `output/`; mỗi suite dùng thư mục mới kèm manifest.
