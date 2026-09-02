# Bàn giao trạng thái — cập nhật 2026-08-27

Tài liệu này để một phiên làm việc mới tiếp tục được mà không cần đọc lại
toàn bộ lịch sử hội thoại.

---

## 1. Đang ở đâu

**Khối phân loại DT/RF: đã đóng băng ở cấu hình P12.** Không làm tiếp.

**Khối QoS động: chưa bắt đầu.** Có một vật cản phải giải quyết trước, xem mục 5.

**Báo cáo LaTeX: số liệu đã lạc hậu.** Xem mục 6.

---

## 2. Kết quả P12 đang có hiệu lực

Trực tuyến, run 7, 39.423 bản tin được đánh giá:

| Alg | TP | FN | FP | Precision | Recall | F1 URGENT | F1 macro |
|-----|----|----|----|-----------|--------|-----------|----------|
| DT  | 290 | 20 | 57 | 0,8357 | 0,9355 | 0,8828 | 0,9409 |
| RF  | 279 | 31 | 35 | 0,8885 | 0,9000 | 0,8942 | 0,9467 |

Theo giao thức (trực tuyến, F1 URGENT):

| Giao thức | DT | RF |
|-----------|-----|-----|
| DNP3      | 0,9918 | 0,9918 |
| IEC-104   | 0,7742 | 0,7945 |
| OPC-UA    | 0,8546 | 0,8547 |
| Modbus    | không có mẫu URGENT | |

Ba lớp sau quy tắc ngữ nghĩa: **Precision lớp EMERGENCY = 1,0000 ở cả hai
thuật toán.** Precision lớp IMPORTANT: DT 0,6968 / RF 0,7799.

**Khuyến nghị: chọn RF** — F1 macro cao hơn, precision IMPORTANT khá hơn rõ,
số báo động giả bằng ba phần năm.

Cấu hình đang biên dịch (đọc `scratch/scada/scada_binary_manifest.json`):

```
dt  DNP3   d=5  cay=1  tau=0.98      rf  DNP3   d=30 cay=10 tau=0.70
dt  IEC104 d=25 cay=1  tau=0.95      rf  IEC104 d=30 cay=10 tau=0.70
dt  OPCUA  d=15 cay=1  tau=0.98      rf  OPCUA  d=20 cay=30 tau=0.60
```

Tổng 2,13 MB mã. Chi phí suy luận không đo được: 9,92 s (DT) / 9,98 s (RF)
so với 10,33 s khi tắt ML.

---

## 3. Đã sửa gì trong code, và vì sao

Thứ tự thời gian. Mỗi mục đều có backup tương ứng ở mục 7.

### P1 — đường cơ sở kích thước loại khung PROTOCOL
`scratch/scada/behavior_features.cc/.h`, `ml/build_behavior_features.py`

`AddUplink` được gọi cho mọi gói đi lên, kể cả khung PROTOCOL, nhưng bộ phân
loại chỉ nhìn thấy TELEMETRY/EVENT. Thiết bị chậm có 15 khung PROTOCOL 101 B
lấn 3 khung TELEMETRY 1392 B nên `baseSize` sụp còn 328 B thay vì 1392 B.
Khớp từng byte: warm-up `normal` cho trung bình 327 B, đo được 328 B.

Sửa: `baseSize`/`sizeVar` chỉ cập nhật từ bản tin không phải PROTOCOL. Thêm
tham số `dataMessage`, các bộ đếm `dataBucketCount`/`dataBucketSizeSum`.
`baseRate`, `baseIat` và các đếm cửa sổ giữ nguyên vì đo cường độ thật.

### P2 — đã thử rồi loại bỏ
Thêm đặc trưng `current_size_baseline_delta` (20→21). Ablation cho thấy không
đóng góp gì (DT: mức quan trọng 0,000; RF kém hơn 0,0009). Đã revert hoàn
toàn. `ml_inference.h` trở lại đúng 20 đặc trưng.

### P3 — kiểm định chéo theo lần chạy
`ml/tune_hierarchical.py`, `ml/tune_binary_semantic.py`

Thêm `--cv-folds K`. `run_folds()` chia theo `run_id` chứ không theo mẫu, vì
bản tin cùng lần chạy không độc lập. `candidate_score_cv()` lấy trung bình
qua fold kèm độ lệch chuẩn. `oof_probability()` sinh xác suất out-of-fold để
quét ngưỡng không thiên vị. `--cv-folds 0` giữ nguyên hành vi cũ.

Cũng nâng số lần chạy: 8 train / 4 validation / 2 test (14 lần chạy).

### P6 + P6b — kích thước bản tin theo số đối tượng thông tin
`scratch/scada/protocols.cc`

**Đây là phát hiện quan trọng nhất của cả giai đoạn.** Trước đó telemetry của
IEC-104 và DNP3 là hằng số biên dịch không jitter (đúng 77 B và 125 B, độ
lệch chuẩn 0,0), còn sự kiện luôn lớn hơn. Nên nhãn bị mã hoá thẳng vào kích
thước: một câu `if (pkt_size > K)` đạt F1 macro **1,0000** cho cả hai giao
thức — bằng hoặc hơn mô hình 20 đặc trưng. Toàn bộ kết quả 0,99+ trước đó là
đo tạo tác, không đo bộ phân loại.

Sửa: thêm `ObjectCount(lo, hi)`. Bản tin đo lường chu kỳ mang nhiều đối tượng
không nhãn thời gian, bản tin sự kiện mang ít đối tượng nhưng mỗi cái có thêm
nhãn thời gian — hai phân bố kích thước trùm lên nhau.

- IEC-104: `IecCyclicSize()` = 12 + n×6, n∈[1,10]; `IecEventSize()` = 12 + n×16, n∈[1,4]
- DNP3: Class-0 response = (12 + n×6)×payScale, n∈[1,16]; unsolicited = (12 + n×11)×payScale, n∈[1,8]
- OPC-UA (P6b): telemetry = unit×ObjectCount(1,12); event = unit×1,6×ObjectCount(1,4), với `unit = max(8, m_pubSz/6)`

Bỏ hoàn toàn chênh lệch kích thước theo mức khẩn cấp ở cả ba giao thức — một
ASDU spontaneous EMERGENCY và IMPORTANT không khác nhau về số byte trên mạng
thật, và việc phân biệt hai mức đó là việc của quy tắc ngữ nghĩa.

Kết quả: F1 bằng một ngưỡng kích thước tụt về 0,6949 (IEC-104), 0,5181 (DNP3),
0,4967 (OPC-UA).

### P9 — sự cố phải là đột biến so với nhịp nền
`scratch/scada/scada.cc`

Trước đó tốc độ báo cáo sự cố là hằng số tuyệt đối 2–7 msg/s, còn tốc độ nền
của thiết bị là 10–16 msg/s. Nên **cửa sổ sự cố thưa hơn lúc bình thường** —
đo được `pkt_count_1s` trung vị 12 khi URGENT so với 16 khi NORMAL. Nhóm đặc
trưng cường độ N3 không có tín hiệu nào để mang.

Sửa: thêm `liveBaseRate(idx, proto, t)` tra `deviceCfg[idx].baseInt`, nhân hệ
số kịch bản qua `GetScenarioMulPair`, tính cả trần `min(interval, 0.1)` của
OPC-UA ở `high_load`. Rồi trong `randomizeIncident`:

```cpp
rate = min(INCIDENT_RATE_CAP, max(rate, live * INCIDENT_RATE_FACTOR));
// INCIDENT_RATE_FACTOR = 4.0, INCIDENT_RATE_CAP = 60.0
```

Kết quả: `baseline_pkt_rate_zscore` nhảy từ ~0,4 (NORMAL) lên ~5,2 (URGENT) ở
cả ba giao thức.

### Sửa cách chọn mô hình
`ml/tune_hierarchical.py`, `ml/tune_binary_semantic.py`

1. **`gap` đo bằng F1 macro thay vì accuracy.** Với dữ liệu lệch 100:1,
   accuracy luôn ~0,99 nên bộ dò quá khớp chưa bao giờ kích hoạt được. Thước
   mới cho giá trị tới 0,059 trong khi thước cũ chỉ 0,001 — chênh 54 lần.
   `MAX_GAP = 0.10`. Cột `gap_acc` giữ lại để đối chiếu.

2. **Quy tắc một sai số chuẩn** (Breiman 1984, đã trích trong `refs.bib`).
   Dung sai ε = 0,005 nhỏ hơn sai số chuẩn của trung bình CV tới 5,6 lần với
   DT/DNP3, nên quy tắc cũ đang chọn theo nhiễu. Nay
   `margin = max(tolerance, std/sqrt(n_folds))`.

3. **Lưới độ sâu mở rộng** `[3,5,8,10,12,15]` → `[3,5,8,10,12,15,20,25,30]`.
   Đường cong F1 out-of-fold trước đó vẫn tăng đơn điệu ở biên 15. Sau khi mở
   rộng, DNP3 và OPC-UA chạm cao nguyên ở d20, IEC-104 ở d30.

4. **1-SE áp một lần** trên lưới hợp nhất thay vì hai lần nối tiếp. Độ phức
   tạp lấy bằng `trees × depth` — đúng bằng số phép so sánh khi suy luận, nên
   việc chọn mô hình gắn trực tiếp với chi phí triển khai.

5. **Nhánh dự phòng khi ràng buộc recall bất khả thi** phải cực đại recall
   (hoà thì phân giải bằng F1 macro), có **sàn precision** `--min-urgent-precision`
   mặc định 0,80. Trước đó lùi về "F1 macro cao nhất" nên DT/OPC-UA chọn
   τ = 0,99 cho recall 0,779 trong khi τ = 0,70 cho 0,909.

---

## 4. Ba con số quan trọng nhất để bảo vệ đồ án

**Mô hình thắng mốc tầm thường.** Đặc trưng đơn tốt nhất so với mô hình 20
đặc trưng (CV):

| Giao thức | Đặc trưng đơn tốt nhất | Mô hình | Mức tăng |
|-----------|------------------------|---------|----------|
| DNP3      | 0,8583 `uplink_downlink_ratio` | 0,9807 | +0,122 |
| IEC-104   | 0,7311 `max_pkt_size`          | 0,8737 | +0,143 |
| OPC-UA    | 0,8150 `baseline_pkt_rate_zscore` | 0,9157 | +0,101 |

Trước P6 mức tăng này là **−0,001 và 0,000** — học máy không đóng góp gì.

**Precision lớp EMERGENCY = 1,0000**, sống sót qua mọi thay đổi, vì là tính
chất cấu trúc của quy tắc ngữ nghĩa chứ không phụ thuộc chất lượng mô hình.

**Sai số phân tán trên 11–14 thiết bị / 24**, không còn dồn 98% vào một thiết
bị như trước P1.

---

## 5. Vật cản của khối QoS — PHẢI đọc trước khi bắt đầu

**Hiện không có tắc nghẽn, nên QoS chưa thể đo được.**

Đo trên `rl_deliveries.csv`, không bật tải nền:

| Lớp | Độ trễ trung vị | p99 | Thời hạn | Trễ hạn |
|-----|-----------------|-----|----------|---------|
| EMERGENCY | 10,02 ms | 10,27 ms | 100 ms | **0,0%** |
| IMPORTANT | 10,02 ms | 10,25 ms | 300 ms | **0,0%** |
| NORMAL    | 10,03 ms | 10,50 ms | 1000 ms | **0,0%** |

Ba lớp trễ giống hệt nhau, đúng bằng lan truyền thuần tuý (2 ms access +
5 ms core + 3 ms mesh). Độ trễ hàng đợi bằng 0. Mức sử dụng liên kết
**0,196 Mbps / 100 Mbps = 0,196%**.

`PrioQueueDisc` bốn băng đang chạy nhưng không có gì để ưu tiên. Mọi phương
án QoS đều sẽ cho cùng kết quả. Chuỗi ML → QoS hiện **không thể bác bỏ**.

Đã thử bộ sinh tải nền có sẵn:

| `--rlBgLoad` | E p99 | I p99 | N p99 | Trễ hạn E / I / N |
|--------------|-------|-------|-------|-------------------|
| tắt   | 10,27 ms | 10,25 ms | 10,50 ms | 0% / 0% / 0% |
| 0,8   | 10,40 ms | 10,34 ms | 10,49 ms | 0% / 0% / 0% |
| 1,15  | **48.062 ms** | 35.666 ms | 47.084 ms | 29,2% / 4,7% / 14,6% |

Không có vùng giữa: 0,8 không tắc gì, 1,15 thì p99 = 48 giây (sụp đổ, không
phải tắc nghẽn). **Và thứ tự ưu tiên bị đảo**: EMERGENCY trễ hạn 29,2% còn
IMPORTANT chỉ 4,7%. Nguyên nhân: `rlBgTos = 184` = EF = đúng DSCP của
EMERGENCY, nên tải nền tràn vào chính băng ưu tiên cao nhất.

### Đo lưu lượng 27/08 (output/qos_char) — nguyên nhân thật, thay cho danh sách dưới

Đã đo run 7, sceneDur=100, mode=rf, rlMode=heuristic + quét 12 tổ hợp
`rlBgLoad × rlBgTos`. Bốn nguyên nhân độc lập, không phải một:

1. **Bộ sinh tải nền là CBR.** `scada.cc:1427` `bg.SetConstantRate(...)`: gói
   1200 B ở 90 Mbps = 1 gói mỗi 106,7 µs, phục vụ 96 µs → hàng đợi D/D/1,
   ρ<1 thì độ dài hàng đợi ≤ 1 gói. Đo `rlBgTos=0`: mọi tải 0,90→1,15 đều cho
   trễ hạn 0,00–0,01% và `queue_at_start` = 0 tuyệt đối (8085 mẫu).
   Quét mịn 0,85–1,10 là vô nghĩa — phải làm tải nền bùng nổ (on/off ngẫu nhiên).
2. **Bộ định tuyến hấp thụ hết tắc nghẽn.** `rlCongestion` chỉ làm nghẽn 1 trong
   3 path; heuristic tránh path đó. Trong cửa sổ nghẽn 20 s của kịch bản 0 chỉ
   có **4–38 bản tin / ~2500** đi qua path nghẽn. Muốn đo QoS thì nút cổ chai
   phải **không tránh được**: link broker→master (dùng chung cho cả 3 path,
   `brkMasterDev` cũng đã có prio disc ở chế độ private), hoặc nghẽn cả 3 path
   cùng lúc.
3. **Ngân sách hàng đợi nhỏ hơn thời hạn một bậc.** Payload northbound trung
   bình 145 B → ở 100 Mbps, một băng 1000 gói = **11,6 ms**, cả 4 băng = **46 ms**.
   Thời hạn EMERGENCY là 100 ms. Nên **dù hàng đợi đầy tuyệt đối cũng không thể
   gây trễ hạn** — trễ hạn chỉ có thể đến từ **mất gói → TCP RTO ≥ 1 s**. Chỉ số
   trễ hạn vì thế nhị phân theo cấu trúc: 0% hoặc thảm hoạ. Muốn có vùng chuyển
   tiếp mượt thì core phải ~10 Mbps (116 ms/băng, 464 ms cả 4 băng) hoặc đệm lớn hơn.
4. **p99 = 48 s / 29 s / 20 s: TCP head-of-line blocking, không phải hàng đợi.**
   Northbound là TCP (`MqttPublisherApp`, protocols.cc:1858). Bằng chứng
   `output/rl_train_v5/episode_001_run3000`: 40 bản tin gửi trong 73,48–73,87 s
   **đều được giao trong 103,21–103,23 s**, cùng gateway 1/path 1 — một lần xả
   duy nhất khi tải nền tắt. Có thêm chùm đúng 1010/1013 ms = RTO tối thiểu 1 s
   của ns-3 + lan truyền. Độ dài đuôi = độ dài cửa sổ nghẽn, không phải độ sâu
   hàng đợi.

Thêm hai điều phải biết khi thiết kế thí nghiệm:

- **Mẫu số phải lấy từ `rl_transitions.csv`** (`total/delivered/lost`), không
  phải `rl_deliveries.csv` — file này chỉ chứa bản tin **đã giao**.
- **Cỡ mẫu lớp khẩn cấp rất nhỏ**: 130–160 EMERGENCY mỗi lần chạy 300 s
  (0,05/0,49/1,01 msg/s theo ba kịch bản), tức độ phân giải tỉ lệ trễ hạn chỉ
  ~0,7%. Cần nhiều seed hoặc chạy dài hơn cho đúng lớp quan trọng nhất.
- **`rlBgTos` = 184 đẩy tải nền vào băng 0** nên bỏ đói NORMAL (p99 20 s) chứ
  không phải "đảo thứ tự ưu tiên" như ghi trước đây; EMERGENCY 0% trễ hạn vì
  heuristic đã tránh path nghẽn.
- **Chuỗi ML → QoS đã nối sẵn**: `OnOtUplink` (scada.cc:625–700) chạy
  `MlPredictUrgency` ngay tại gateway rồi `PublishOnce(TrafficClassToTos(...))`.
  Ba trong bốn mốc so sánh đã chạy được hôm nay: FIFO = `--qosMode=neutral`,
  DSCP tĩnh + nhãn ML = `--mode=rf`, oracle = bỏ `--mode`. Chỉ thiếu cơ chế động.

### Ba việc phải làm trước khi viết QoS động *(viết trước khi đo — mục 1 ở trên phủ định bước 1)*

1. **Hiệu chuẩn tải**: quét mịn `rlBgLoad` trong 0,85–1,10, tìm điểm NORMAL
   bắt đầu trễ hạn còn EMERGENCY thì chưa.
2. **Quyết định `rlBgTos`**: đổi sang BE (0) để tải nền cạnh tranh với NORMAL,
   hoặc giữ EF nhưng nói rõ đang nghiên cứu kịch bản lớp cao tự gây tắc.
3. **Giải thích p99 = 48 giây**: hàng đợi 1000 gói × 200 B trên 100 Mbps chỉ
   cho tối đa ~16 ms. Gấp ba nghìn lần thì có thứ khác đang tích luỹ.

### "QoS động" là động cái gì — chưa chốt

Ưu tiên tuyệt đối bốn băng đã cho EMERGENCY quyền đi trước vô điều kiện. Ba
hướng khả dĩ, mỗi cái là bài toán khác:

- Chống bỏ đói lớp thấp (WFQ/DRR với trọng số theo tải quan sát)
- **Lập lịch theo thời hạn (EDF)** — dùng lại thời hạn 100/300/1000 ms đã có
  trong thiết kế, so sánh trực tiếp được với ưu tiên tĩnh. *Hướng được đề
  xuất.*
- Điều khiển nhận / hạn chế tốc độ theo lớp tại Station

### Chế độ tắc nghẽn đã hiệu chuẩn 27/08 — DÙNG CÁI NÀY

Điểm làm việc (link broker→master là nút cổ chai, mọi bản tin phải qua):

```
--rlCongestion=1 --bgWhere=master --bgFull=1 --rlBgLoad=0.85 --rlBgBurst=8 \
--rlBgTos=0 --brokerBw=5Mbps --queueLen=1000 --devQueue=10 --qosQueueCsv=20
```

Chọn từ lưới 32 điểm (`output/qos_char/grid`, quét brokerBw × rlBgLoad ×
rlBgBurst × queueLen cho cả hai nhánh fifo/private). Mọi điểm tải 0,95 đều bị
**RTO chi phối** (mất gói 13–24%, phần trễ ≥900 ms 12–26%) nên bị loại — trông
như tắc nghẽn nhưng thực chất là truyền lại. Điểm đã chọn đạt cả năm tiêu chí:

| Tiêu chí | Đo được |
|---|---|
| FIFO trễ hạn đáng kể, chưa bão hoà | EMERGENCY 66,8% / IMPORTANT 41,2% |
| NORMAL bị ảnh hưởng rõ | p50 134 ms, p90 528 ms (mốc cũ: 10 ms cố định) |
| Đủ mẫu lớp khẩn cấp | 160 EMERGENCY + 136 IMPORTANT mỗi lần chạy 120 s |
| Phân bố liên tục | 357 mức chiếm dụng hàng đợi, 465 bin trễ 1 ms |
| Ổn định qua seed | 5 seed (run 7/8/12/13/14), mọi so sánh chính 5/5 |

Sạch về mặt cơ chế: hàng đợi ở nút cổ chai **không drop gói nào**, mất gói
0,01–0,03%, phần trễ ≥900 ms (tức có RTO) chỉ 0,02%. Băng EF/AF31 đỉnh **3 gói**
— toàn bộ tồn đọng nằm ở băng BE (trung bình 127, đỉnh 881/1000).

### Kết quả ba mốc ở chế độ trên — theo LỚP THẬT, 5 seed

`output/qos_cal2/`. Trễ hạn tính trên bản tin đã giao; cột queue/rto tách
riêng hiệu ứng xếp hàng và hiệu ứng TCP-RTO/HOL (ngưỡng 900 ms vì RTO tối
thiểu của ns-3 là 1 s).

| Nhánh | EME miss | (queue/rto) | IMP miss | (queue/rto) | NOR miss | (queue/rto) |
|---|---|---|---|---|---|---|
| `fifo` (1 băng, cùng tổng đệm) | 66,8 ±14,2 | 65,1 / 1,7 | 41,2 ±17,6 | 36,7 / 4,5 | 2,44 | 0 / 2,44 |
| `--mode=dt` DSCP tĩnh | 7,98 ±3,3 | 7,5 / 0,5 | 5,43 ±0,8 | 4,8 / 0,6 | 2,27 | 0 / 2,27 |
| `--mode=rf` DSCP tĩnh | 9,98 ±4,9 | 9,6 / 0,4 | 6,61 ±1,9 | 6,2 / 0,5 | 2,21 | 0 / 2,21 |
| oracle (bỏ `--mode`) | **0,00 ±0,00** | 0 / 0 | **0,00 ±0,00** | 0 / 0 | 1,89 | 0 / 1,89 |

**Khoảng cách tĩnh→oracle: EMERGENCY 9,98 pp (xấu hơn 5/5 seed), IMPORTANT
6,61 pp (5/5).** Toàn bộ là hiệu ứng xếp hàng (cột queue), không phải RTO.
NORMAL không phân biệt được giữa các nhánh (1–3/5 seed, sai số ±2,6) và trễ
hạn của nó **100% do RTO** — hàng đợi tối đa ~800 ms còn hạn là 1000 ms.

**Nguyên nhân của khoảng cách là nhãn sai, không phải lịch xếp hàng.** Khác
biệt duy nhất giữa `static_rf` và oracle là nhãn. Ví dụ seed 7: 30 bản tin
EMERGENCY thật bị gán NORMAL → đi băng BE → p50 54 ms, p99 382 ms, 26,7% vượt
hạn 100 ms; 25 IMPORTANT thật bị gán NORMAL → 32% vượt hạn 300 ms. Mọi bản tin
**được gán** EMERGENCY đều đúng lớp (precision 1,0), nên bảng theo lớp được
gán báo 0% — xem bẫy 2 dưới đây.

DT tốt hơn RF ở đây (7,98 so với 9,98 pp EMERGENCY, tốt hơn ở 4/5 seed) —
ngược với khuyến nghị chọn RF ở mục 2, vốn dựa trên F1. Chưa đủ mẫu để chốt.

### Hai bẫy của chế độ mới

1. **`--qosMode=neutral` không so được.** Nó xoá hẳn queue disc nên đệm chỉ còn
   `devQueue` gói → mất 48% bản tin và **tải đề nghị cũng tụt** (53 EMERGENCY
   giao được so với 160), tức các nhánh không còn cùng lưu lượng. Mốc "không
   QoS" hợp lệ là **`--qosMode=fifo`** (một băng, cùng tổng đệm `4×queueLen`,
   cùng thiết bị) — khác đúng một biến là kỷ luật xếp hàng.
2. **Phải đọc cột `true_class`, không phải `traffic_class`.** `rl_deliveries.csv`
   giờ có thêm `true_class,true_deadline_ms,true_deadline_met` (map
   messageId→lớp thật trong C++, không thêm field vào header nên kích thước gói
   không đổi). Nhóm theo lớp được gán sẽ ghi một EMERGENCY bị gán sai vào dòng
   NORMAL với hạn 1000 ms và báo "đúng hạn" — chi phí phân loại sai biến mất.

### Knob mới trong scada.cc (backup: `output/code_backup_pre_qos/`)

`--rlBgBurst` (tỉ số đỉnh/trung bình, ON/OFF phân bố mũ; 1 = CBR cũ),
`--rlBgBurstMs`, `--bgWhere` (path|allpaths|master), `--bgFull`, `--coreBw`,
`--brokerBw`, `--queueLen`, `--devQueue`, `--qosQueueCsv=N`,
`--qosMode=fifo`. Cờ mặc định **tái lập bit-by-bit** kết quả trước khi sửa
(md5 rl_deliveries + rl_transitions không đổi) nên artefact RL v5 vẫn đúng.

`--devQueue` là bắt buộc trong chế độ này: TxQueue thiết bị mặc định 100 gói
nằm *dưới* prio disc và là FIFO thuần → ở 5–10 Mbps nó cho 96–190 ms xếp hàng
không ưu tiên được, lớn hơn cả hạn EMERGENCY. Đặt 10.

### Phân tích 27/08 về hướng "promotion động" — chưa đủ điều kiện làm

`output/qos_tau/` (10 lần chạy có `scada_runtime_ml.csv`).

1. **Phía chi phí của bất đối xứng FN/FP bằng 0 ở điểm làm việc này.** Tải nền
   ở BE nên EF/AF31 đỉnh 3 gói; mọi bản tin ra khỏi BE đều p50 29 ms / p99
   35 ms / miss ~0%, kể cả 205 bản tin NORMAL thật bị thăng cấp oan lên AF31.
   Thăng cấp toàn bộ NORMAL cũng chỉ là 0,196 Mbps trên link 5 Mbps. Nên mọi
   chính sách promotion bất đối xứng đều có cực trị là hằng số "thăng cấp tất
   cả", và các đầu vào động (queue state, headroom, slack) đều là hằng số.
2. **Hạ ngưỡng tĩnh thu hồi ~90% khoảng cách.** RF với τ×0,10: recall khẩn cấp
   82,7% → 98,4%, bỏ sót 257 → 24, giá là thăng cấp 2,48% NORMAL (~0,006 Mbps).
   Mọi cơ chế động phải so với **mốc τ mới**, không phải mốc tĩnh hiện tại.
   Sàn `--min-urgent-precision 0.80` trong bộ chọn mô hình là ràng buộc **sai
   dấu** dưới bất đối xứng này (liên quan quyết định treo #2, #3).
3. **DT vs RF đảo chiều khi hiệu chỉnh ngưỡng.** Paired 5 seed: DT − RF ở
   EMERGENCY −2,00 pp, DT tốt hơn 4/5, sign test p = 0,125 (không có ý nghĩa).
   Nguyên nhân: 75,2% false negative của DT có `urgent_probability` **bằng
   đúng 0** (một cây, 80 giá trị xác suất) → recall bão hoà 89,1%; RF có 2802
   giá trị, lên được 98,4%. DT thắng ở ngưỡng tuned theo F1, RF thắng khi ngưỡng
   phục vụ QoS. Phát biểu an toàn: **tiêu chí chọn mô hình phải là recall lớp
   khẩn cấp có trọng số P(miss | BE), không phải F1 với sàn precision.**
4. **Trình tự đề xuất**: (a) hiệu chỉnh lại ngưỡng theo hàm chi phí QoS trên
   dữ liệu CV có sẵn — offline, không cần mô phỏng mới; (b) chạy mốc τ mới;
   (c) chỉ khi dựng được điểm làm việc có **policing theo băng** (EF giới hạn
   vài % dung lượng, như SLA DiffServ thật vẫn làm để chặn mẹo "dán EF cho tất
   cả") hoặc tải nền rải nhiều băng, thì promotion động mới có việc để tối ưu.
   EDF vẫn là nhánh phụ: xếp hàng *trong* băng ưu tiên chưa từng xảy ra.

### Xác nhận đầu-cuối của ngưỡng hiệu chuẩn (27/08) — ĐÃ ĐẠT

`output/qos_ver/` (4 nhánh × 5 seed). Ngưỡng đưa vào bằng ba cờ runtime
`--mlTauIec104=0.01 --mlTauDnp3=0.01 --mlTauOpcua=0.21`; **không** sửa
`scada_binary_config.h`, không train lại, không đổi feature/packet/header.
Override chỉ áp ở bước so sánh `probability >= threshold` trong
`ml_inference.cc`. Không truyền cờ → **trùng md5** `rl_deliveries.csv`,
`rl_transitions.csv`, `qos_queues.csv` với trước khi patch, và đường mặc định
RL cũ cũng trùng md5.

Theo lớp thật, trung bình ± sd qua 5 seed (run 7/8/12/13/14):

| Nhánh | EME miss | (queue/rto) | EME p99 | E→N demote | IMP miss | urgent share |
|---|---|---|---|---|---|---|
| `fifo` | 66,77 ±14,18 | 65,1 / 1,7 | 769,7 ms | 29,0 | 41,20 ±17,58 | 1,22% |
| RF τ mặc định | 9,98 ±4,86 | 9,6 / 0,4 | 473,7 ms | 29,0 | 6,61 ±1,90 | 1,22% |
| **RF τ hiệu chuẩn** | **2,09 ±1,16** | 2,0 / 0,1 | **108,4 ms** | **5,2** | **1,18 ±0,40** | 2,68% |
| oracle | 0,00 ±0,00 | 0 / 0 | 35,3 ms | 0,0 | 0,00 ±0,00 | 1,30% |

Paired theo seed: EMERGENCY **−7,89 pp, tốt hơn 5/5 seed** (−2,5 / −9,7 / −9,1
/ −13,9 / −4,2); IMPORTANT **−5,44 pp, 5/5**. NORMAL không bị ảnh hưởng
(1,14% → 1,09%, vẫn 100% do RTO). Băng EF/AF31 ở nút cổ chai vẫn rỗng (đỉnh 3
và 5 gói, **0 drop**) — thăng cấp không tạo tồn đọng. Oracle vẫn là trần trên.

**Phần dư 2,09 pp là không thể hạ tiếp bằng ngưỡng**: 5,2 bản tin E→N còn lại
mỗi lần chạy chính là các trường hợp RF cho xác suất **bằng đúng 0** (7,4% số
false negative của RF). Muốn đóng nốt phải sửa mô hình/đặc trưng, không phải
ngưỡng.

**Kiểm định giả thiết độc lập của phép offline** (dự báo 1,60%, đo 2,09%):
`P(miss | E→N)` đi từ 0,538 [0,457; 0,618] ở τ mặc định lên 0,654 [0,463;
0,813] ở τ hiệu chuẩn — Fisher exact p = 0,29, tức **không phân biệt được với
nhiễu ở n = 26**. Giả thuyết "sai số phân loại trùng với lúc nghẽn" cũng bị
loại: chiếm dụng băng BE lúc gửi của các bản tin demote còn sót (trung vị 76
gói) không khác các bản tin EMERGENCY được gán đúng (trung vị 119),
Mann-Whitney p = 0,87. Vậy độ lệch +0,49 pp nằm trong khả năng phân giải của
cỡ mẫu, và giả thiết độc lập đứng vững ở điểm làm việc này.

**Bảng không thiên lệch, 15 seed mới 20–34** (`output/qos_ver_fresh/`). Bảng
5 seed ở trên có τ được *chọn* trên chính 3 trong 5 seed đó (12/13/14), nên số
dưới đây mới là số dùng cho báo cáo:

| Nhánh | EME miss | (queue/rto) | EME p99 | E→N demote | IMP miss | NOR miss |
|---|---|---|---|---|---|---|
| `fifo` | 73,78 ±13,12 | 69,1 / 4,7 | 746,0 ms | 24,2 | 36,80 ±13,95 | 4,54 ±7,31 |
| RF τ mặc định | 11,52 ±4,08 | 10,6 / 0,9 | 598,9 ms | 24,1 | 5,16 ±3,92 | 4,00 ±5,76 |
| **RF τ hiệu chuẩn** | **1,33 ±1,18** | 1,2 / 0,1 | **157,5 ms** | **3,4** | **1,22 ±1,00** | 3,92 ±5,58 |
| oracle | 0,17 ±0,37 | 0,2 / 0 | 46,6 ms | 0,0 | 0,05 ±0,20 | 3,93 ±6,60 |

Paired: EMERGENCY **−10,18 pp, tốt hơn 15/15 seed, sign test p = 6,1e−5**;
IMPORTANT **−3,94 pp, tốt hơn 13, hoà 1, xấu hơn 1, p = 1,8e−3**. Kết luận
mạnh hơn bảng 5 seed, nên thiên lệch lựa chọn không phải vấn đề.

**Giới hạn của điểm làm việc — chỉ áp cho lớp NORMAL.** Băng BE chạm trần 1000
gói ở **2 trong 15 seed** (drop 90 và 542 gói), và tương quan giữa số gói drop
và trễ hạn NORMAL là 0,77. NORMAL vì thế cực kỳ phụ thuộc seed: trung vị 1,20%
nhưng biên độ 0,00–18,12%, và trễ hạn của nó **100% do RTO** (cột queue = 0,00
ở mọi nhánh) vì xếp hàng tối đa ~800 ms còn hạn là 1000 ms. Kết luận về
EMERGENCY/IMPORTANT **không phụ thuộc** vào việc này (chúng nằm ở băng EF/AF31,
đỉnh 3–6 gói, 0 drop ở mọi seed). Nếu cần NORMAL thành một phép đo sạch thì
phải nâng băng BE lên ~1500–2000 gói (khi đó xếp hàng vượt 1000 ms và trễ hạn
NORMAL trở thành do queueing, liên tục, thay vì do RTO) và chạy lại toàn bộ
bảng — khoảng 20 phút cho 15 seed × 4 nhánh.

**Hệ quả cho quyết định treo #1 (DT hay RF):** dưới tiêu chú QoS có hiệu chuẩn
ngưỡng, RF đạt 2,09% còn DT bão hoà ở ~5,70% (75,2% false negative của DT có
xác suất bằng đúng 0, chỉ 80 giá trị xác suất khác nhau). **Chọn RF**, nhưng lý
do là recall khẩn cấp sau hiệu chuẩn, không phải F1.

### Pha A: bộ đo + bộ đánh dấu lại (27/08) — ĐÃ CHỐT, 15 seed

`output/qos_meter/` (140 lần chạy). Mục tiêu: làm cho chi phí của việc nâng lớp
khác 0, vì không có nó thì mọi chính sách promotion đều suy biến thành "nâng
tất cả".

**Hiện thực**: thùng thẻ một tốc độ cho mỗi lớp trong `MqttBrokerApp::Forward`
(`protocols.cc`), bản tin vượt hồ sơ bị **hạ lớp theo bậc** EMERGENCY →
IMPORTANT → NORMAL, không bị loại bỏ. Cờ `--meterEfKbps`, `--meterAf31Kbps`,
`--meterBurstBytes`. Hai cột mới trong `rl_deliveries.csv`: `served_class`,
`meter_demoted`. Backup: `output/code_backup_pre_qos/protocols.{cc,h}`,
`scada.cc.pre_meter`. Hồi quy mặc định: `rl_transitions.csv` và
`qos_queues.csv` trùng md5, `rl_deliveries.csv` trùng trên 14 cột cũ.

**Ba quyết định thiết kế, đều do đo mới thấy:**

1. **Không dùng `TbfQueueDisc` làm hàng đợi con của band.** Bộ hẹn giờ của nó
   gọi `Simulator::Schedule(delay, &QueueDisc::Run, this)` — tự đánh thức chính
   nó — nhưng queue disc con không được `TrafficControlLayer` gắn
   `NetDeviceQueueInterface`, nên band bị chặn sẽ đứng tới khi có sự kiện khác
   kích hoạt root. Với band EF chỉ 0,5 msg/s thì đó là tạo tác tệ hơn hiện
   tượng cần nghiên cứu. ns-3.47 không có HTB.
2. **Hồ sơ phải theo giá trị tuyệt đối, không theo phần trăm link.** Hai band
   ưu tiên chỉ chở **1,3–4,3 kbps trên link 5 000 kbps**; hồ sơ "5% dung lượng"
   = 250 kbps, gấp 60–190 lần tải thật, không bao giờ ràng buộc.
3. **Burst phải đặt theo byte, không theo ms của tốc độ lớp.** 100 ms ở 2 kbps
   = 25 B < một gói (~190 B) nên thùng không bao giờ đủ thẻ cho một gói và
   **mọi bản tin đều bị hạ lớp** bất kể tốc độ. Mặc định 2000 B, sàn 500 B.

**Kết quả — trễ hạn theo lớp thật (%), 15 seed cho hồ sơ 2 và 4 kbps:**

| Hồ sơ EF/AF31 | \multicolumn EMERGENCY | | | | IMPORTANT | | | |
|---|---|---|---|---|---|---|---|---|
| | τ mặc định | τ B=2% | τ B=3% | oracle | τ mặc định | τ B=2% | τ B=3% | oracle |
| 2 kbps | 13,35 | **10,56** | 10,67 | 2,33 | **8,94** | 13,98 | 19,98 | 4,00 |
| 4 kbps | 12,17 | 6,61 | **3,45** | 1,15 | **6,31** | 7,19 | 11,55 | 1,41 |
| không policing | 11,52 | — | **1,33** | 0,17 | 5,16 | — | **1,22** | 0,05 |
| 1,5 kbps (5 seed) | **15,05** | 17,11 | 18,79 | 5,18 | **16,07** | 18,31 | 25,24 | 10,11 |

Kiểm định dấu theo cặp (τ B=3% trừ τ mặc định):

| Hồ sơ | EMERGENCY | IMPORTANT |
|---|---|---|
| không policing | **−10,18 pp** (15/0, p = 1e−4) | **−3,94 pp** (13/1, p = 1,8e−3) |
| 4 kbps | **−8,71 pp** (14/1, p = 1e−3) | **+5,24 pp** (1/12, p = 3,4e−3) |
| 2 kbps | −2,69 pp (9/5, p = 0,42 — hết ý nghĩa) | **+11,03 pp** (0/15, p = 1e−4) |

**Ba phát biểu đã chốt:**

1. **Có đảo dấu thật ở lớp IMPORTANT.** Cùng một thay đổi ngưỡng: không policing
   thì tốt hơn 3,94 pp (p = 1,8e−3), policing 2 kbps thì **xấu hơn 11,03 pp**
   (p = 1e−4). Cả hai chiều đều có ý nghĩa thống kê. Nguyên nhân: nâng lớp đẩy
   4,28 kbps vào band cam kết 2 kbps nên chính IMPORTANT thật bị hạ lớp (46,97%).
2. **Ở lớp EMERGENCY lợi ích không đảo dấu mà tiêu biến đơn điệu**: −10,18 →
   −8,71 → −2,69 (không còn ý nghĩa) khi hồ sơ siết từ ∞ về 2 kbps. Ở hồ sơ
   2 kbps, τ B=2% và B=3% ngang nhau (+0,10 pp, p = 0,79) — cực trị đã dịch từ
   "càng mạnh càng tốt" sang "vừa phải".
3. **Cực trị khác nhau giữa hai lớp ở cùng một hồ sơ.** Ở 2 kbps: EMERGENCY tốt
   nhất với τ B=2%, IMPORTANT tốt nhất với τ mặc định. Đây là xung đột giữa hai
   lớp trên cùng một ngân sách — đúng loại bài toán mà một bộ điều khiển có
   trạng thái mới xử lý được, và là lý do pha B có nghĩa.

**Hai cảnh báo:**

- **Chính bộ đo cũng có giá.** Ở hồ sơ 2 kbps, oracle trễ hạn 2,33% so với
  0,17% khi không policing; ở 4 kbps là 1,15%. Cam kết 2 kbps chỉ gấp 1,3 lần
  tải thật của lớp (1,54 kbps) nên các cụm vượt cam kết. Không được đọc bảng
  này như "policing làm QoS tốt hơn" — nó làm bài toán *đo được*, không làm nó
  tốt hơn.
- **Hồ sơ 1,5 kbps là SLA đặt sai**, cam kết nằm dưới tải thật nên oracle cũng
  mất 5,18%; chỉ giữ lại để cho thấy biên dưới.

**Việc còn lại của pha A**: hiệu chuẩn lại τ dưới hàm chi phí *có* policing —
chi phí báo động sai giờ khác 0 và bằng xác suất một bản tin nâng lớp oan chiếm
chỗ của một bản tin khẩn cấp thật. Biên ngưỡng trong `tab:qos-bien-nguong` của
báo cáo được tính khi chi phí đó bằng 0 nên chỉ đúng cho chế độ không policing.

**Pha B chưa bắt đầu**: vòng điều khiển kín đặt lại $r_c$ lúc chạy theo công
thức (1.1) của lý thuyết tuần 9, chu kỳ < 100 ms, kèm ba biện pháp ổn định.

### Pha B: vòng điều khiển kín trên hồ sơ từng lớp (27/08) — ĐÃ CHỐT, 15 seed

`output/qos_ctrl/` (45 lần chạy) + `output/qos_meter/ef2_af2_tau_b3_*`.
Hiện thực trong `RunQosController` (`scada.cc`), đúng ba khối của lý thuyết
tuần 9: cảm biến ($\lambda_c$ tại bộ đo, tín hiệu vi phạm chọn được giữa tỉ lệ
trễ hạn tại Master hoặc **tỉ lệ bị hạ lớp tại bộ đo**), bộ điều khiển theo công
thức (1.1) với $\kappa$ = 3,0/1,5 lấy từ tác tử định tuyến, cơ quan chấp hành
`SetClassRate`. Ba biện pháp ổn định: EWMA, biên chết 5%, giới hạn tốc độ thay
đổi. Chu kỳ 100 ms. Cờ: `--qosCtrl`, `--qosCtrlBudget`, `--qosCtrlMs`,
`--qosCtrlMemMs`, `--qosCtrlBeta`, `--qosCtrlMinFrac`, `--qosCtrlMaxStep`,
`--qosCtrlDemoteSignal`. CSV mới: `qos_control.csv`. Hồi quy: mặc định trùng
`rl_transitions.csv`; chế độ meter tĩnh trùng md5 `rl_deliveries.csv` với lượt
trước khi refactor API bộ đo.

**Thí nghiệm**: cùng ngân sách $C$ = 4 kbps, cùng τ B=3%, chỉ khác chính sách
phân bổ. Ba tỉ lệ chia tĩnh so với vòng kín, 15 seed.

| | EME miss | IMP miss | Chi phí $3\mu_E + 1{,}5\mu_I$ |
|---|---|---|---|
| tĩnh 1/3 kbps | 17,82 | **15,86** | 77,23 |
| tĩnh 2/2 kbps | 10,67 | 19,98 | 61,96 |
| tĩnh 3/1 kbps | **6,51** | 26,06 | **58,61** |
| **vòng kín** | 11,80 | 18,28 | 62,81 |

Paired trên chi phí tổng hợp: dynamic − tĩnh 1/3 = **−14,43** (13/2,
p = 7,4e−3); dynamic − tĩnh 2/2 = +0,84 (8/7, p = 1,0); dynamic − tĩnh 3/1 =
+4,20 (7/8, p = 1,0). Theo từng lớp: dynamic tốt hơn tĩnh 2/2 ở IMPORTANT
(−1,70 pp, 11/1, p = 6,3e−3) và hoà ở EMERGENCY (+1,13 pp, p = 0,77).

**Kết luận của pha B: vòng kín hoà với các tỉ lệ chia tĩnh hợp lý và bảo vệ
đáng kể trước một tỉ lệ chia đặt sai, nhưng không thắng tỉ lệ chia tĩnh tốt
nhất.** Cùng hình dạng với kết quả RL định tuyến ("hoà với heuristic, không bao
giờ thắng"). Ba nguyên nhân, đều đo được:

1. **Công thức (1.1) chia theo $\lambda_c$ nên nó chống lại chính thứ tự
   nghiêm trọng.** Ở kịch bản `normal`, EMERGENCY chỉ đề nghị 0,05 msg/s nên
   được cấp hồ sơ nhỏ nhất (1,45 kbps) — đúng chỗ mà giá trị của lớp này nằm ở
   các lần đến thưa. Không thể phân bổ theo tốc độ đến cho một lớp mà giá trị
   nằm ở tính hiếm.
2. **Xung đột lấy mẫu giới hạn thời gian phản ứng ở thang giây.** Chu kỳ phải
   < 100 ms nhưng EMERGENCY 1 msg/s → mỗi cửa sổ 0,1 bản tin, $\lambda$ nhảy
   0 → 8,9 kbps khi có một bản tin. Chỉ EWMA bộ nhớ 5 s dùng được.
3. **Hai lớp xung đột trực tiếp trên một ngân sách dùng chung**, nên mọi bộ
   phân bổ đều rơi trên cùng một biên. Vòng kín chỉ thắng nếu điểm tối ưu
   *dịch chuyển theo thời gian* nhiều hơn sai số theo dõi; đo được nó dịch từ
   1,45 lên 1,85 kbps qua ba kịch bản — nhỏ hơn nhiễu giữa các seed.

**Hai lỗi thiết kế đã tìm ra và sửa trong lúc làm** (đáng ghi vào báo cáo):

- `SetClassProfile` nạp đầy lại thùng thẻ, nên gọi nó mỗi chu kỳ sẽ **vô hiệu
  hoá policing hoàn toàn**. Phải có `SetClassRate` đổi tốc độ mà giữ nguyên số
  thẻ (dồn thẻ theo tốc độ cũ tới thời điểm đổi rồi mới đổi).
- $\mu_c$ đo theo *lớp được gán* thì **mù với chính thiệt hại bộ điều khiển gây
  ra**: bản tin EMERGENCY bị hạ lớp được ghi vào nhóm NORMAL nên
  $\mu_{EME} = 0$ đúng lúc hồ sơ EMERGENCY quá nhỏ. Cấu hình đầu tiên vì thế
  đẩy EMERGENCY xuống sàn 0,5 kbps trong khi IMPORTANT được 3,38. Tín hiệu hạ
  lớp đo tại bộ đo khắc phục được (sàn tăng lên 1,47 kbps).

### Thang so sánh bắt buộc

Không thể kết luận "QoS động tốt hơn" nếu chỉ chạy QoS động. Bốn mốc, cùng
seed, cùng lưu lượng:

| Mốc | Ý nghĩa |
|-----|---------|
| FIFO không QoS | sàn dưới |
| DSCP tĩnh + nhãn ML | hệ thống hiện tại |
| DSCP động + nhãn ML | phương án đề xuất |
| DSCP động + **nhãn đúng (oracle)** | trần trên |

Dòng cuối hay bị bỏ sót nhưng quan trọng nhất: khoảng cách giữa dòng 3 và 4
là **cái giá của sai số bộ phân loại**, tách bạch khỏi công của cơ chế QoS.

Chỉ số: tỉ lệ trễ hạn theo lớp (chính), độ trễ p99 (không phải trung bình),
tỉ lệ mất gói, mức bỏ đói lớp NORMAL. Dữ liệu có sẵn trong
`rl_deliveries.csv`: `traffic_class`, `delay_ms`, `deadline_ms`, `deadline_met`.

---

## 6. Báo cáo LaTeX

Thư mục: `/mnt/d/HCMUT/Đồ án chuyên ngành/PNT_253_GD2_023_Report`

Cấu trúc: `main.tex` → `Giaidoan2.tex` → `fixGD1/{lythuyet,kientruc,phanloai,ketqua}.tex`

**Số liệu trong `ketqua.tex` đã lạc hậu ba lần.** Nó đang chứa F1 macro trực
tuyến 0,9652 (DT) / 0,9770 (RF) — số của mốc 02:34 ngày 21/08, tương ứng mô
hình trong `output/model_backup_pre_p3`. Số hiện tại là 0,9409 / 0,9467.

Cần viết lại khi quay lại báo cáo:
- Toàn bộ bảng số trong `ketqua.tex`
- Bảng cấu hình `tab:cau-hinh-mo-hinh` trong `phanloai.tex`
- Mục hạn chế: hạn chế #3 cũ ("bản tin đầu chùm bị bỏ sót") **đã được chứng
  minh là sai** — tỉ lệ sai theo vị trí là 5,1% / 0% / 2,9% / 3,3%, không tập
  trung ở đầu chùm
- **Thêm mốc so sánh tầm thường** (mục 4) — chuẩn mực phương pháp, hiện báo
  cáo chỉ so gộp vs theo-giao-thức, cả hai đều là học máy

**Hai điểm code dễ hiểu sai, đã phát hiện khi rà soát bản thảo:**

1. **DSCP ở chặng truy nhập không có tác dụng gì.** Hàng đợi bốn băng chỉ được
   cài trên `gwBrokerDevs`, `meshDevs`, `brkMasterDev`; chặng thiết bị↔Station
   giữ FqCoDel mặc định, mà `Ipv4QueueDiscItem::Hash` chỉ băm src/dst/proto/hai
   cổng — **không có byte TOS**. Nên `LabelToTos` (kể cả AF21 cho OPC-UA) không
   quyết định băng ở đâu cả. Hệ quả: băng 2 luôn rỗng trên mọi liên kết có hàng
   đợi bốn băng, và **chính sách đánh dấu DSCP tĩnh của Giai đoạn 1 chưa từng có
   hiệu lực trong mô phỏng** — cần rà lại nếu báo cáo GD1 có nói ngược lại.
2. **Phản hồi cho vòng điều khiển tính trên lớp ĐƯỢC GÁN, không phải lớp thật.**
   `g_qosCtrl[info.trafficClass]` với `deadline = RlDeadlineMs(info.trafficClass)`.
   Lớp thật chỉ dùng để đánh giá. Đây chính là lý do phải có tín hiệu hạ lớp.

**Phần QoS đã tách thành hai file riêng (27/08, bản thứ ba):**

`Giaidoan2.tex` nay nạp sáu file theo thứ tự: `lythuyet`, `kientruc`,
`phanloai`, **`thietkeqos`**, `ketqua`, **`ketquaqos`**.

- `fixGD1/thietkeqos.tex` — `\section{Thiết kế QoS động}` (147 dòng, 3 bảng):
  Các khối chức năng của nút DiffServ; Bộ phân loại và bộ đánh dấu; Bộ đo và cơ
  chế đánh dấu lại; Vòng điều khiển phân bổ băng thông; Cấu hình thí nghiệm và
  các mốc so sánh.
- `fixGD1/ketquaqos.tex` — `\section{Kết quả khối QoS động}` (390 dòng, 12
  bảng): Điểm làm việc của thí nghiệm; Kết quả của bộ phân loại và bộ đánh dấu;
  Kết quả khi band ưu tiên có cam kết tốc độ; Kết quả của vòng điều khiển; Tổng
  hợp; Hạn chế.
- Quy ước trình bày theo yêu cầu người dùng: tiêu đề đặt theo **cái được thiết
  kế** chứ không phải lý do chọn; **không dùng `subsubsection`**, thay bằng
  `\textbf{a)}`, `\textbf{b)}`... với `\vspace{0.3cm}` trước các ý từ b) trở đi;
  câu ngắn, ít ngắt đoạn.
- Đã kiểm: env khớp, **15/15 bảng đúng số cột**, 0 `subsubsection`, không nhãn
  trùng, không ref treo (một ref treo còn lại nằm trong comment có sẵn ở
  `phanloai.tex:53`), `\cite` đều hợp lệ. **Chưa biên dịch** (máy không có LaTeX).
- Backup: `*.bak_preqos` (trước khi có QoS), `*.bak_qos2` (bản gộp lần 1),
  `*.bak_qos3` (trước khi tách file), `Giaidoan2.tex.bak_qos3`.
- **Chưa có hình nào** cho phần QoS. Ba hình đáng làm, dữ liệu sẵn: chiếm dụng
  band BE theo thời gian, CDF độ trễ bốn mốc theo lớp thật, quỹ đạo $r_c$ của
  vòng điều khiển theo ba kịch bản.
- Khối comment `Ánh xạ các khối chức năng vào mô hình DiffServ` ở
  `kientruc.tex` dòng 223–267 trùng với `tab:qos-anh-xa-diffserv`, nên xoá hẳn.

Có 7 file `.tex.bak*` trong `fixGD1/` là các bản trước khi sửa.

**Lưu ý**: hơn một nửa `lythuyet.tex` đang bị comment (419/795 dòng), làm 7
tham chiếu bị treo. Chưa xử lý vì đó là chỉnh sửa của người dùng.

---

## 7. Backup

| Thư mục | Giờ | Nội dung |
|---------|-----|----------|
| `output/model_backup_pre_p3` | 06:51 | 9 tệp — mô hình của **báo cáo hiện tại** |
| `output/code_backup_pre_p1p2` | 07:05 | 20 tệp — trước khi sửa đường cơ sở |
| `output/code_backup_pre_p6` | 08:05 | 27 tệp — trước khi sửa mô hình payload |
| `output/code_backup_pre_p9` | 08:42 | 3 tệp — sau P6, trước P9 |
| `output/code_backup_pre_selfix` | 11:15 | 2 tệp — trước sửa bộ chọn mô hình |
| `output/code_backup_pre_selfix2` | 12:26 | 2 tệp — trước sửa nhánh dự phòng |
| `output/code_backup_pre_selfix3` | — | 1 tệp — trước sàn precision |
| **`output/snapshot_dtrf_20260827_0040`** | 00:40 | **57 tệp — TRẠNG THÁI HIỆN TẠI, đầy đủ nhất** |

Snapshot có `README.md` riêng mô tả chi tiết và cách khôi phục.

**Hai cái bẫy khi đổi backup:**

1. **`static_assert` không bắt được lỗi trộn lẫn.** Mọi bản đều khai báo 20
   đặc trưng cùng tên cùng thứ tự, nhưng P1 đổi **ý nghĩa** của các đặc trưng
   đường cơ sở mà không đổi tên. Ghép `behavior_features.cc` của P6 với mô
   hình của P12 sẽ biên dịch sạch, chạy bình thường, nhưng dự đoán sai âm
   thầm. **Luôn khôi phục trọn cụm `scratch_scada/*` và `ml/*` từ đúng một
   thư mục.**

2. **Dữ liệu không đi theo backup.** Mỗi phiên bản code sinh lưu lượng khác
   nhau. Sau khi đổi phải sinh lại 14 lần chạy (~6 phút).

Repo **không có git**. Bảy thư mục này là toàn bộ mạng an toàn.

---

## 8. Quy trình chạy lại dữ liệu

```bash
cd ~/ns3-major-project/ns-allinone-3.47/ns-3.47
PY=~/ns3-major-project/.venv/bin/python

# 8 lan chay huan luyen
for r in 1 2 3 4 5 9 10 11; do d=output/ml_train/run$r
  ./ns3 run "scada --run=$r --sceneDur=100 --rlMode=off --packetCsv=1 \
      --featureCsv=0 --flowXml=0 --runtimeMlCsv=0 --outDir=$d/"
  $PY ml/build_behavior_features.py --packets $d/scada_packets.csv \
      --out $d/scada_features.csv
done
# 4 lan kiem dinh -> output/ml_test/run{6,12,13,14}
# 2 lan kiem tra  -> output/ml_final/run{7,8}
```

Mô phỏng tất định theo `--run=N` nên tái lập được chính xác.

Sinh hình + bảng: `bash ml/make_report_figs.sh` (dùng `SKIP_DATA=1 SKIP_TUNE=1`
để chỉ vẽ lại, không ghi đè mô hình).

Bảng số liệu ra terminal: `python3 ml/report_tables.py --tables output/report_figs/tables`

---

## 9. Quyết định đang treo

1. **Chọn DT hay RF** làm cấu hình đề xuất. Khuyến nghị RF.
2. **DT/IEC-104 không có điểm làm việc nào đạt sàn precision 0,80** — chấp
   nhận và ghi nhận, hay hạ sàn xuống 0,70?
3. **Ràng buộc $r_{\min} = 0{,}95$ chỉ DNP3 đạt.** Giữ nguyên và ghi là chưa
   đạt, hay hạ xuống mức khả thi?
4. **Hướng "QoS động"** — chưa chốt (mục 5).
5. **`git init`?** Đã đề xuất, chưa được chấp thuận.
