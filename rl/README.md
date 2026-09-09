# Gateway Q-learning

Pipeline triển khai:

```text
OT event -> urgency/semantic class -> DSCP -> RL path -> Broker -> Master
```

Ba gateway chạy ba agent độc lập. Action chọn một trong ba destination/path đã
thiết lập; application gửi ngay, còn decision window 100 ms chỉ giữ action ổn
định và không buffer bản tin.

## State và Q-table

Schema hiện tại là `health_best_v4_sev`:

```text
(traffic_class, health_path0, health_path1, health_path2, best_current_path)
```

Có 3 class, `3^3 = 27` tổ hợp health và 3 giá trị best path, tổng cộng 243
state/gateway và 3 action/state. `previous_path` không còn là chiều riêng; nó
chỉ tác động gián tiếp qua switching cost/hysteresis. File khác schema bị từ
chối khi load.

Health path dùng queue occupancy, delivery delay và loss EWMA. RED khi queue
`>= 0.70`, loss `>= 0.05` hoặc delay `>= 80 ms`; YELLOW khi queue `>= 0.30`,
loss `>= 0.01` hoặc delay `>= 30 ms`.

## Feedback và recovery

Timeout theo class là `min(rlTimeoutMs, deadline + 50 ms)`. Timestamp bắt đầu
từ OT source event và được giữ qua lazy TCP connection/pending MQTT queue, nên
timeout và delay delivery cùng một clock.

Mỗi timeout làm tăng loss EWMA. `--rlLossRecoveryMs=2000` cho loss tự suy giảm
theo hàm mũ ngay cả khi safe mask tạm thời không gửi thêm traffic lên path đó.
Đặt `0` cho ablation/legacy. Thay đổi này không đổi state encoding nhưng đổi
transition dynamics, vì vậy Q-table v4 cũ phải được đánh giá lại trước khi dùng
làm kết quả chính.

Safe mask mặc định chỉ cho action trong health bin tốt nhất. Cùng mask được dùng
cho exploration, Bellman bootstrap và deployment. Khi state chưa thấy, tất cả
path RED, hoặc action học được thua continuous path cost quá guard margin, agent
fallback sang heuristic và ghi `degraded_fallback=1`.

## Train

Profile `qos` triển khai Q-table đã chọn tại
`rl/outputs/qtable_rf_qos.csv`. Không huấn luyện ghi đè trực tiếp file triển
khai; hãy dùng tên candidate, đánh giá trên seed chưa thấy rồi mới thay thế.

Script mặc định huấn luyện với RF và profile QoS hiện hành. Cứ mỗi 10 episode,
Q-table được checkpoint để tránh mất một chính sách tốt khi các cập nhật sau
làm giảm chất lượng.

```bash
python3 rl/train_qlearning.py \
  --episodes 50 --run-start 1100 --scene-dur 40 \
  --profile qos --mode rf \
  --qtable rl/outputs/qtable_rf_candidate.csv \
  --out output/rl_train_rf_candidate
```

Kiểm tra script train có truyền `--rlLossRecoveryMs` đúng cấu hình muốn công
bố. Dùng `--resume` chỉ với cùng schema và cùng dynamics. Số episode lớn hơn
không mặc nhiên tốt hơn; chọn checkpoint bằng tập validation tách biệt.

## Evaluate

Chạy `off`, `heuristic` và `qtable` trên cùng các run ID chưa từng train, rồi:

```bash
python3 rl/evaluate_rl.py \
  --input off=output/rl_eval/off/run160 \
  --input heuristic=output/rl_eval/heuristic/run160 \
  --input qtable=output/rl_eval/qtable/run160 \
  --out output/rl_eval/summary.csv
```

Báo cáo theo traffic class: P95/P99 delay, loss, deadline miss, reward, switching,
coverage/visit count và fallback rate. Với safe mask, kiểm tra
`non_min_health_action_rate == 0`.

## Deploy

`--profile=qos` mặc định nạp Q-table RF đã được chọn. Có thể ghi đè rõ ràng để
thực hiện ablation:

```bash
./ns3 run "scada --profile=qos --mode=rf --rlMode=qtable \
  --rlQTable=rl/outputs/qtable_rf_qos.csv"
./ns3 run "scada --profile=qos --mode=rf --rlMode=heuristic"
./ns3 run "scada --profile=qos --mode=rf --rlMode=off"
```

Ở chế độ `qtable`, safety mask và heuristic fallback vẫn được giữ cho state
chưa được học, toàn bộ tuyến suy giảm, hoặc action học được kém hơn tuyến an
toàn quá guard margin.
