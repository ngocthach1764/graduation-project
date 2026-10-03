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
  -> translation proxy và cửa sổ luồng với 21 đặc trưng quan sát được
  -> DT/RF phân loại TIME_CRITICAL, OPERATIONAL hoặc MONITORING
  -> uncertainty guard chỉ nâng MONITORING gần ngưỡng lên OPERATIONAL
  -> Q-learning chọn egress theo nghẽn cục bộ kéo dài hoặc bất thường FIB
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
| DT/RF | Model đa giao thức dùng chung, train cùng dữ liệu và 21 đặc trưng; ngưỡng riêng theo giao thức |
| QoS guard | Giữ nhãn ML gốc, chỉ cấp AF31 cho dự đoán MONITORING gần ngưỡng |
| QoS | Marker/policer và hàng đợi DSCP tại egress Station |
| Q-learning | Chọn một trong ba đường khi có nghẽn cục bộ kéo dài hoặc FIB bất thường |
| RIP | Cơ chế định tuyến nền; route poisoning tác động lên bảng FIB thật |
| Detector DDoS | Quan sát lưu lượng đến Master, không đọc cờ ground truth |

## Mô hình nghiệp vụ và bảo vệ biên

Modbus MONITORING và OPERATIONAL dùng chung kết nối TCP/FC03 và bản đồ
thanh ghi. Quét giám sát A-B-C có cả quét chẩn đoán A-C-A; tác vụ vận hành
đọc trạng thái/ngữ cảnh, dừng theo xác nhận, thời lượng hoặc ngân sách đáp ứng.
DT/RF vẫn chỉ dùng 21 đặc trưng hành vi, không dùng mã đọc/ghi hay giá trị
thanh ghi làm đầu vào. Modbus emergency tăng tần suất 1.5 lần; DNP3 giữ 7 lần.

Polling OP Modbus dùng mục tiêu mặc định 100 ms (`--modbusOperationalRefreshMs`),
sàn 20 ms, vẫn chỉ một request outstanding. Khoảng phản hồi thực tế có thể dài
hơn mục tiêu do TCP/mạng. Tác vụ Client khởi tạo kết thúc sau hai xác nhận ổn
định hoặc hết thời lượng/ngân sách; không mô phỏng Slave tự push báo động.

Profile QoS bảo vệ độ tin cậy DSCP tại Station: gói chuyển tiếp trực tiếp từ
giao diện thiết bị không được tự cấp EF/AF31, bị đưa về BE (giữ ECN) và kiểm
tra địa chỉ nguồn theo giao diện. Policer giới hạn 20 kbps/giao diện, tổng
100 kbps/Station, burst tương ứng 4000/8000 byte. Lưu lượng ưu tiên của proxy
có giới hạn riêng 50 kbps/(thiết bị,giao thức), burst 4000 byte; vượt giới hạn
thì hạ BE, không trực tiếp loại bỏ. `station_boundary.csv` ghi audit.

UDP flood phát DSCP EF46/TOS184 ở nguồn, không giả định kẻ tấn công tự dùng
BE. Gói được bộ bảo vệ cho qua vẫn có thể tới Master ở BE; không phải chặn
100% tấn công. Hiệu quả của cấu hình QoS gồm bảo vệ biên, policing, marker,
controller và hàng đợi, không chỉ riêng controller động.

`--normalClean=1` mặc định tắt lỗi đường truyền trong bootstrap/normal,
khôi phục mức `errAccess`, `errCore`, `errMesh` khi sang high-load/emergency.
Loss 5% demo (nếu bật) cũng chỉ bắt đầu sau normal. Đây là điều kiện mô phỏng
tham chiếu sạch, không ép kết quả miss về 0. Có thể dùng `--normalClean=0`
để kiểm tra độ bền trong normal có lỗi. Các cuộc tấn công mặc định phủ trên
high-load; nếu đặt thời gian tấn công vào normal thì normal không còn sạch.

### Mô hình phân loại triển khai

DT và RF dùng cùng 84 phiên train 2000-2083, 18 phiên validation
2200-2217 và 18 phiên test 2400-2417 (70:15:15 theo phiên). Mỗi phiên chứa
cả bốn giao thức; 833372 mẫu fit chung dùng đúng 21 đầu vào. Một nửa phiên
mỗi split có burst MON Modbus đối chứng. Các model đa giao thức được train
lại, không ghép nhánh Modbus riêng. Ngưỡng dưới đây là điểm số quyết định, không
phải xác suất đã hiệu chuẩn hoặc cam kết Precision/Recall.

| Giao thức | DT TC/OP | RF TC/OP |
|---|---|---|
| Modbus | 1.01 / 0.94 | 1.01 / 0.42 |
| DNP3 | 0.34 / 0.02 | 0.22 / 0.26 |
| IEC104 | 0.98 / 0.98 | 0.34 / 0.30 |
| OPC-UA | 0.90 / 0.10 | 0.38 / 0.30 |

TC=1.01 vô hiệu nhánh TC của Modbus trong thiết kế MON/OP hiện tại.

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
- định tuyến theo bằng chứng hàng đợi cục bộ duy trì 300 ms, giữ tuyến 2 s giữa các lần đổi do nghẽn;
- QoS private tại Station, tổng budget ưu tiên 100 kbps dùng chung cho ba egress;
- split khởi tạo TIME_CRITICAL/OPERATIONAL là 20/80 kbps;
- uncertainty guard RF--QoS có tỷ lệ chuẩn hóa 0.45 và chỉ cấp AF31;
- bucket tổng 16000 B, controller 100 ms, EWMA memory 2 s;
- tải BE tại Broker--Master: normal 0%, high-load 70% burst x2,
  emergency 50% burst x4;
- UDP flood 2.4 Mbps từ 18 nguồn phân tán khi `--ddos=1`;
- cơ chế bảo vệ lưu lượng ưu tiên được kích hoạt theo trạng thái detector;
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
tấn công mang DSCP EF46 (TOS184); QoS guard tại Station chỉ cho phần được
chấp nhận đi tiếp ở BE.

## Sáu kịch bản đánh giá

Mỗi kịch bản phải chạy paired-seed cho bốn arm:

| Arm | Override sau `--profile=qos` |
|---|---|
| Baseline | `--qosMode=fifo --qosCtrl=0 --rlMode=off --ddosProtectUrgent=0 --qosIngressGuard=0 --qosSourceLimit=0` |
| Chỉ QoS | `--rlMode=off --qosIngressGuard=1 --qosSourceLimit=1` |
| Chỉ RL | `--qosMode=fifo --qosCtrl=0 --ddosProtectUrgent=0 --qosIngressGuard=0 --qosSourceLimit=0` |
| QoS + RL | Không cần override |

| Kịch bản | Cờ bổ sung |
|---|---|
| Normal/high-load/emergency | `--ddos=0 --ripPoison=0` (ba pha trong một run) |
| UDP flood | `--ddos=1 --ripPoison=0` |
| Routing-table poisoning | `--ddos=0 --ripPoison=1` |
| Mixed | `--ddos=1 --ripPoison=1` |

Q-learning chỉ chuyển tuyến khi có bằng chứng FIB hoặc có tuyến thay thế thỏa
điều kiện nghẽn cục bộ bên dưới. Trong benchmark sạch và UDP-only, không có
bằng chứng đủ điều kiện nên đường home được giữ và số switch bằng 0. Khi
poisoning xuất hiện, monitor cần hai mẫu FIB liên tiếp để xác nhận và mask tuyến
bị nghi ngờ. Ba mẫu sạch liên tiếp xác nhận FIB phục hồi; tác tử trở về home.

Kết quả đánh giá chính thức dùng 15 seed `3100--3114`, mỗi pha 40 giây,
normal không lỗi, tải high-load 70%, emergency 50% và không dùng loss 5%
demo. Bảng dưới là QoS + RL; ba kịch bản tấn công tính trong [51,71) giây:

| Kịch bản | TC miss | OP miss | J = 3TC + 1.5OP |
|---|---:|---:|---:|
| Normal | 0.000% | 0.000% | 0.000 |
| High-load | 1.13% | 2.51% | 7.16 |
| Emergency | 1.70% | 1.46% | 7.29 |
| UDP flood | 1.26% | 5.54% | 12.09 |
| Routing-table poisoning | 0.99% | 2.41% | 6.59 |
| Mixed | 2.96% | 3.33% | 13.88 |

J là điểm deadline có trọng số, không phải tỷ lệ chặn tấn công. FIFO có thể
có OP miss thấp hơn QoS ở một số pha; không khẳng định mọi lớp đều cải thiện.
RF runtime đạt Macro-Precision 95.82%, Macro-Recall 97.13%, Macro-F1 96.44%
và Accuracy 99.62% trên 273868 quan sát clean. Modbus OP có Precision 99.52%,
Recall 92.47%; vẫn có bỏ sót. DT offline trên cùng đặc trưng đạt Macro-F1
93.52%, không phải phép so sánh hai pipeline mạng chạy DT và RF. Test phân loại
2400-2417 là tập riêng: RF Macro-F1 95.57%, DT 92.40%; không trộn với benchmark.

Miss/J lấy từ `rl_deliveries.csv`, tính trên bản tin đã nhận ở Master và
theo cửa sổ thời điểm nhận. Bản tin không bao giờ đến chưa nằm trong mẫu số;
seed/lớp thiếu mẫu hiện được script quy miss=0. Không suy diễn J=0 thành
không mất gói hoặc giảm J thành tỷ lệ chặn DDoS. Cần bổ sung sổ phát-nhận để
đánh giá deadline failure toàn phần. Profile thiết bị ban đầu khớp cả bốn
arm trong 60/60 nhóm seed/kịch bản; tương tác TCP vẫn có thể làm trace khác.

Các số liệu này là kết quả mô phỏng cục bộ; thư mục `output/` không được commit.
Khi công bố phải kèm seed, cấu hình, confidence interval và so sánh paired với
baseline/chỉ-QoS/chỉ-RL trên cùng revision.

## QoS động

Controller chia budget tổng cố định `C=100` kbps giữa TIME_CRITICAL và
OPERATIONAL. Nó điều khiển một bậc tự do và luôn suy ra
`r_OP=C-r_TC`, nên tổng rate bằng đúng `C` tại mọi chu kỳ. Sau đó mỗi rate lớp
được phân phối xuống ba Station theo EWMA nhu cầu và pressure cục bộ; mỗi egress
giữ một phần reserve để luồng mới không bị khóa. `qos_control.csv` ghi
`total_rate_kbps` và `budget_error_kbps`.

Đây là policer/marker: thiếu token làm gói bị đánh dấu xuống lớp dịch vụ thấp
hơn, không phải traffic shaper giữ gói chờ token. Mất gói xảy ra tại error model
hoặc hàng đợi hữu hạn. Bucket tổng 16000 B được chia cho ba Station để hấp thụ
burst ngắn nhưng không thay đổi rate dài hạn. TIME_CRITICAL có thể mượn token
OPERATIONAL chưa sử dụng; `qosCtrlMinFrac=0.4` giữ tối thiểu 20 kbps cho mỗi
lớp. Safety guard tỷ lệ 0.45 chỉ nâng dự đoán MONITORING chưa chắc chắn lên
OPERATIONAL, không cấp EF và không thay đổi nhãn RF được dùng để đánh giá.

Kiểm tra contract của một run:

```bash
python3 tests/check_qos_run.py output/<run>/ --budget-kbps 100
```

Demo và audit QoS hiện tại có thể chạy bằng:

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
bằng chứng FIB bất thường. Profile QoS bật `rlDataPlaneFailover`: hàng đợi
egress được lấy mẫu đồng thời mỗi 100 ms, kể cả trên tuyến chưa được dùng.
Chuyển do nghẽn chỉ được phép khi hàng đợi tuyến hiện tại >=0.35, tuyến ứng
viên <=0.15, chênh lệch >=0.20; hai điều kiện cao/thấp phải duy trì ít nhất
300 ms. Tác tử giữ ít nhất 2 s giữa hai lần chuyển do nghẽn của cùng lớp.
Các ngưỡng là tham số thiết kế, không phải xác suất lỗi mạng.

Không dùng độ trễ khởi tạo của tuyến chưa được đo làm bằng chứng chuyển do
nghẽn. Nếu nghẽn nằm ở Broker--Master chung và không có egress thay thế đủ
thoáng, tác tử giữ tuyến; QoS xử lý áp lực tại hàng đợi. Khi phát hiện FIB
bất thường, việc tránh tuyến và quay về home sau phục hồi không phải chờ
thời gian giữ tuyến do nghẽn. Trong phiên FIB bất thường, cổng bằng chứng
còn xét chênh lệch trễ 20 ms hoặc loss 0.04. Delivery và timeout chỉ cung
cấp quan sát sau khi bản tin thật được xử lý, không đọc cờ tấn công.

Route poisoning dùng một node `RIP-Attacker` và quảng bá route sai vào Station
nạn nhân. Node này xuất hiện trong NetAnim khi `--ripPoison=1`. Sau khi tấn công
kết thúc, metric 16 rút quảng bá và RIP phục hồi FIB. Chi tiết Q-table và công
cụ offline nằm tại [`rl/README.md`](rl/README.md).

## ML và kiểm thử

Manifest nhúng định nghĩa 20 đặc trưng hành vi cộng protocol ID, tổng cộng 21
đầu vào cửa sổ luồng, cùng các ngưỡng của DT/RF. Kiểm tra model/feature contract:

```bash
python3 -m unittest tests/test_static_contracts.py
python3 tests/check_boundary_policy.py
python3 tests/check_modbus_workflow.py
python3 tests/check_station_meter.py
python3 tests/check_normal_clean.py
python3 tests/run_routing_gate_probe.py
```

Kiểm tra build, smoke và parity Python/C++:

```bash
bash scripts/verify_scada.sh
```

Sinh dataset cửa sổ luồng và huấn luyện lại model service-flow:

```bash
bash ml/run_service_dataset.sh 201 215
python3 ml/train_service_classifier.py --help
```

Huấn luyện lại model chung và xuất model đã khóa:

```bash
python3 ml/train_service_split.py --train-start 2000 --validation-start 2200 \
  --test-start 2400 --allow-training-seed-reuse \
  --out-dir output/common_service_2000_20261003 --workers 4
python3 ml/export_common_models.py output/common_service_2000_20261003 \
  --destination scratch/scada
./ns3 build scada
```

Chỉ dùng cờ cho phép dùng lại seed khi chủ động tái tạo dataset trong thư mục
riêng; các seed 2000 từng xuất hiện trong thử nghiệm trước. Không ghi đè CSV cũ.
Exporter tạo header DT/RF chung, ngưỡng và manifest; dispatcher chính không còn
gọi các header Modbus riêng. Các header
được theo dõi trong Git; pickle, CSV thí nghiệm và thư mục output không được
commit. Không chọn lại ngưỡng bằng benchmark 3100-3114. Benchmark đã được dùng
để quan sát nhiều thiết kế, nên cần bộ seed/trace mới để kiểm chứng suy rộng.

Không gộp train/validation/test, không dùng warm-up để train và không suy luận
hiệu quả từ một seed. `errAccess`, `errCore` và `errMesh` là packet error rate,
không phải BER.

## Quản lý Git và output

Repo chỉ theo dõi overlay của đồ án, không theo dõi toàn bộ source ns-3 bundled.
`output/` và các artifact huấn luyện tạm thời được giữ trên máy nhưng không đưa
vào lịch sử Git. Q-table triển khai ổn định `rl/outputs/qtable_rf_qos.csv` là
ngoại lệ được theo dõi để một clone mới chạy được `--profile=qos` ngay lập tức.
