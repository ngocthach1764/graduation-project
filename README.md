# SCADA đa giao thức: ML, QoS động và Q-learning

Dự án mô phỏng hệ thống SCADA trên ns-3.47 với Modbus TCP, DNP3,
IEC 60870-5-104 và OPC UA ở miền OT, MQTT ở miền northbound, phân loại lưu
lượng bằng DT/RF, QoS động tại biên Station và định tuyến Q-learning trên nền
RIP. Một lớp phủ an ninh độc lập tạo UDP flood hoặc routing-table poisoning để
đánh giá từng cơ chế và trường hợp phối hợp.

## Kiến trúc hiện tại

```text
Thiết bị hiện trường
  -> giao thức OT tới Station
  -> translation proxy và 20 behavior features
  -> RF xác định NORMAL/URGENT, semantic parser tách IMPORTANT/EMERGENCY
  -> Q-learning chọn egress sau khi có bằng chứng bất thường tuyến
  -> token-bucket marker và hàng đợi DSCP tại egress Station
  -> một trong ba tuyến northbound
  -> MQTT Broker
  -> Master SCADA, detector DDoS và feedback
```

`OnOtUplink` hiện đóng vai trò translation proxy không trễ. Timestamp gốc được
chụp tại sự kiện OT Tx và giữ đến Master, nên deadline gồm cả thời gian kết nối
MQTT, pending queue, truyền và xếp hàng. Đây chưa phải độ trễ xử lý của một
gateway vật lý hoàn chỉnh.

| Thành phần | Vị trí/ý nghĩa |
|---|---|
| RF | Phân loại tại Station; model nhúng cho DNP3, IEC104 và OPC-UA |
| Modbus | Phân lớp bằng semantic alarm-register, chưa có model ML riêng |
| QoS | Marker/policer và hàng đợi DSCP tại egress Station |
| Q-learning | Chọn một trong ba đường khi giám sát FIB phát hiện bất thường |
| RIP | Cơ chế định tuyến nền; route poisoning tác động lên bảng FIB thật |
| Detector DDoS | Quan sát lưu lượng đến Master, không đọc cờ ground truth |

## Cấu trúc thư mục

| Thư mục | Vai trò |
|---|---|
| `scratch/scada/` | Topology, ứng dụng giao thức, RF nhúng, QoS, DDoS và RL |
| `ml/` | Tạo feature, huấn luyện/đánh giá DT-RF và xuất model C/C++ |
| `rl/` | Huấn luyện, đánh giá và Q-table triển khai |
| `scripts/` | Chạy thí nghiệm, audit và in bảng kết quả |
| `tests/` | Contract tĩnh và đối chiếu feature Python/C++ |
| `output/` | Artifact mô phỏng cục bộ, không được Git theo dõi |

## Profile chính

`--profile=qos` nạp cấu hình đã kiểm chứng:

- RF classification;
- Q-learning với `rl/outputs/qtable_rf_qos.csv`;
- RIP nền và FIB-integrity monitor chu kỳ 100 ms;
- QoS private tại Station, tổng urgent budget 6 kbps trên mỗi egress;
- split E/I bị giới hạn gần cân bằng bởi `qosCtrlMinFrac=0.9`;
- bucket 4000 B, controller 100 ms, EWMA memory 5 s;
- tải BE tại Broker--Master: normal 0%, high-load 70% burst x2,
  emergency 50% burst x4;
- UDP flood 2.4 Mbps từ 18 nguồn phân tán khi `--ddos=1`;
- cơ chế bảo vệ urgent được kích hoạt theo trạng thái detector;
- không có packet loss 5% nhân tạo và không poisoning nếu chưa bật cờ.

CLI luôn có thể ghi đè từng mặc định sau khi chọn profile.

## Build và chạy nhanh

Từ thư mục `ns-3.47` trong WSL:

```bash
./ns3 build scada

./ns3 run "scada --run=1 --sceneDur=15 --profile=qos \
  --outDir=output/qos_run1/"
```

Ba pha vận hành bắt đầu sau bootstrap 1 s:

```text
normal:     [1, 1 + sceneDur)
high_load:  [1 + sceneDur, 1 + 2*sceneDur)
emergency:  [1 + 2*sceneDur, 1 + 3*sceneDur)
```

## DDoS và NetAnim

DDoS là lớp phủ an ninh, độc lập với ba pha vận hành. Khi không truyền thời
điểm thủ công, code tự đặt:

```text
ddosStart    = 1 + 1.25*sceneDur
ddosDuration = 0.5*sceneDur
```

Với `sceneDur=15`, UDP flood chạy từ 19.75 đến 27.25 s. Demo đầy đủ:

```bash
./ns3 run "scada --run=500 --sceneDur=15 --profile=qos \
  --anim=1 --ddos=1 --outDir=output/netanim_ddos_demo/"
```

Mở `output/netanim_ddos_demo/scada_netanim.xml` bằng NetAnim. Dashboard hiển
thị `CLEAN -> SUSPECTED -> UNDER_ATTACK -> RECOVERY`. Demo rút còn 5 s làm
thay đổi phân bố cửa sổ RF; khi chỉ cần trực quan hóa có thể thêm
`--ddosRfThreshold=0.55`, nhưng phép đánh giá chính vẫn dùng ngưỡng 0.85.

`--ddos=1` tạo UDP flood băng thông. Nó không phải firewall và không tự tuyên
bố trạng thái tấn công; detector phải suy luận từ thống kê ingress. Các gói
tấn công mang DSCP BE.

## Sáu kịch bản đánh giá

Mỗi kịch bản phải chạy paired-seed cho bốn arm:

| Arm | Override sau `--profile=qos` |
|---|---|
| Baseline | `--qosMode=fifo --qosCtrl=0 --rlMode=off --ddosProtectUrgent=0` |
| Chỉ QoS | `--rlMode=off` |
| Chỉ RL | `--qosMode=fifo --qosCtrl=0 --ddosProtectUrgent=0` |
| QoS + RL | Không cần override |

| Kịch bản | Cờ bổ sung |
|---|---|
| Normal/high-load/emergency | `--ddos=0 --ripPoison=0` (ba pha trong một run) |
| UDP flood | `--ddos=1 --ripPoison=0` |
| Routing-table poisoning | `--ddos=0 --ripPoison=1` |
| Mixed | `--ddos=1 --ripPoison=1` |

Trong kịch bản sạch hoặc UDP-only, FIB không có bất thường nên Q-learning giữ
đường home và không switch. Khi poisoning xuất hiện, monitor cần hai mẫu FIB
liên tiếp để xác nhận, mask tuyến bị nghi ngờ và Q-learning mới chọn đường còn
hợp lệ. Ba mẫu sạch liên tiếp đưa hệ thống về trạng thái bình thường.

Kết quả QoS+RL gần nhất trên 15 seed, tải high-load 70% và emergency 50%, không
dùng loss 5% ngẫu nhiên:

| Kịch bản | E miss | I miss | J = 3E + 1.5I |
|---|---:|---:|---:|
| Normal | 0.000% | 0.000% | 0.000 |
| High-load | 1.463% | 3.488% | 9.623 |
| Emergency | 1.179% | 8.000% | 15.536 |
| UDP flood | 0.743% | 2.667% | 6.228 |
| Routing-table poisoning | 1.143% | 5.779% | 12.098 |
| Mixed | 0.852% | 1.721% | 5.139 |

Các số liệu này là kết quả mô phỏng cục bộ; thư mục `output/` không được commit.
Khi công bố phải kèm seed, cấu hình, confidence interval và so sánh paired với
baseline/chỉ-QoS/chỉ-RL trên cùng revision.

## QoS động

Controller chia budget cố định `C` giữa EMERGENCY và IMPORTANT. Nó điều khiển
một bậc tự do và luôn suy ra `r_I=C-r_E`, nên tổng rate bằng đúng `C` tại mọi
chu kỳ. `qos_control.csv` ghi `total_rate_kbps` và `budget_error_kbps`.

Đây là policer/marker: thiếu token làm gói bị đánh dấu xuống lớp dịch vụ thấp
hơn, không phải traffic shaper giữ gói chờ token. Mất gói xảy ra tại error model
hoặc hàng đợi hữu hạn. Bucket 4000 B hấp thụ burst ngắn nhưng không thay đổi
rate dài hạn. Emergency có thể mượn token Important chưa sử dụng; giới hạn
split 0.9 giữ cả hai lớp tối thiểu 45% budget để tránh làm I bị đói.

Kiểm tra contract của một run:

```bash
python3 tests/check_qos_run.py output/<run>/ --budget-kbps 6
```

Audit QoS legacy/canonical vẫn có thể chạy bằng:

```bash
bash scripts/run_qos_dynamic_demo.sh
bash scripts/run_qos_audit.sh
```

Các script audit có manifest riêng; không trộn số liệu cũ với benchmark sáu
kịch bản nếu tham số topology, tải hoặc controller khác nhau.

## Q-learning và route poisoning

Mỗi gateway có Q-table riêng với schema `health_best_v4_sev`, 243 state:

```text
(traffic_class, health_path0, health_path1, health_path2, best_current_path)
```

Safe action mask chỉ cho chọn tuyến trong health bin tốt nhất và loại tuyến có
bằng chứng FIB bất thường. RL data-plane failover mặc định tắt trong benchmark
chính, vì vậy cấu hình loss 5% nhân tạo không được bí mật cấp như oracle cho
agent. Delivery và timeout chỉ cung cấp quan sát sau khi gói thật được xử lý.

Route poisoning dùng một node `RIP-Attacker` và quảng bá route sai vào Station
nạn nhân. Node này xuất hiện trong NetAnim khi `--ripPoison=1`. Sau khi tấn công
kết thúc, metric 16 rút quảng bá và RIP phục hồi FIB. Chi tiết Q-table và công
cụ offline nằm tại [`rl/README.md`](rl/README.md).

## ML và kiểm thử

Manifest nhúng định nghĩa 20 feature nhân quả và ngưỡng của DT/RF. Kiểm tra
model/feature contract:

```bash
python3 -m unittest tests/test_static_contracts.py
```

Kiểm tra build, smoke và parity Python/C++:

```bash
bash scripts/verify_scada.sh
```

Tái lập pipeline P12:

```bash
bash ml/make_report_figs.sh
```

Không gộp train/validation/test, không dùng warm-up để train và không suy luận
hiệu quả từ một seed. `errAccess`, `errCore` và `errMesh` là packet error rate,
không phải BER.

## Quản lý Git và output

Repo chỉ theo dõi overlay của đồ án, không theo dõi toàn bộ source ns-3 bundled.
`output/` và các artifact huấn luyện tạm thời được giữ trên máy nhưng không đưa
vào lịch sử Git. Q-table triển khai ổn định `rl/outputs/qtable_rf_qos.csv` là
ngoại lệ được theo dõi để một clone mới chạy được `--profile=qos` ngay lập tức.
