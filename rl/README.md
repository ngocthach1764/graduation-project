# Gateway Q-learning

The deployed pipeline is:

```text
OT packet -> DT urgency -> semantic class -> DSCP queue -> RL path -> Broker -> Master
```

The RL action selects one of three pre-established destinations. Static /32
routes force remote destinations over the corresponding gateway mesh link.
Packets are sent immediately; a 100 ms decision window only keeps the selected
path stable and never buffers application traffic.

State per gateway:

```text
(traffic_class, health_path0, health_path1, health_path2,
 best_current_path, previous_path)
```

There are 729 states per gateway, three actions per state, and three independent
gateway tables. `best_current_path` is computed from the same measured
delay/loss and northbound QueueDisc occupancy available to the heuristic. It
removes the heuristic's observability advantage while Q-learning still chooses
the action and can optimize future reward and switching cost.

Q-table rows carry the schema tag `health_best_prev_v3_sev`. Older 243-state and
`health_best_prev_v2` tables are rejected instead of being silently interpreted
with the new encoding or the old reward scale.

Reward per decision window, where `severity` is 3.0 for EMERGENCY, 1.5 for
IMPORTANT and 1.0 for NORMAL:

```text
clip(1
     - 0.75 * normalized_delay
     - 3.00 * severity * loss_rate
     - 2.00 * severity * deadline_miss_rate
     - 0.75 * max(0, max_normalized_delay - 0.50)
     - 0.25 * queue_occupancy
     - 0.15 * path_switched,
     -2 * severity, 1)
```

Everything slower than the feedback timeout collapses into one `lost` bucket
regardless of how late it eventually arrives, so per-class severity is the only
lever that separates a missed alarm from a late telemetry sample. Weighting loss
flat previously let the agent trade an EMERGENCY timeout for a marginal
average-delay gain on telemetry, and the fixed `-2` floor saturated so early
that a window losing three of eight EMERGENCY messages scored the same as one
losing all of them. States are class-strided and argmax never compares across
classes, so scaling the reward per class does not distort action selection.

The rotating training load defaults to 115% of one core link and uses EF TOS,
so congestion remains observable even when private QoS protects SCADA traffic.
Queue occupancy is normalized to one priority-band limit.  A Q-value hysteresis
margin of `0.20 * severity` prevents path oscillation for statistically
insignificant gains; it scales with severity because severity also scales the
Q magnitudes, so a fixed margin would brake proportionally less on exactly the
class where path churn costs most.
Delivery feedback times out at `class_deadline + 50 ms` (capped by
`rlTimeoutMs`) so a failed EMERGENCY path is marked unhealthy promptly instead
of waiting for the old 1500 ms global timeout.

Safe action masking is enabled by default.  For each encoded state, Q-learning
may choose only paths in the best currently available health bin.  The
heuristic baseline remains unmasked.  Bellman bootstrapping, forced coverage,
epsilon exploration, unseen-state fallback, and deployed Q-table inference all
use the same mask, so training and runtime constraints are consistent.
Set `--rlSafeMask=false` only for an ablation run.  Runtime transition logs
include `action_health` and `min_health`; safe Q-table runs must report a zero
`non_min_health_action_rate` in `evaluate_rl.py`.

The three-bin state can hide large continuous differences between paths in the
same health bin. Safe-RL therefore guards the learned action with the current
delay, queue, and loss cost. It falls back to the lowest-cost allowed path when
all paths are RED, the state is unseen, or the learned path exceeds the best
continuous cost by the class-specific guard margin. Such decisions record
`degraded_fallback=1`. Outside the guard, the Q-table remains in control.

## Train

```bash
python3 rl/train_qlearning.py \
  --episodes 50 \
  --run-start 100 \
  --scene-dur 60 \
  --qtable rl/outputs/qtable.csv \
  --out output/rl_train
```

Use `--resume` to continue an existing table. Training uses DT classification,
private QoS, path-specific congestion, stress mode, epsilon decay, and disables
large raw packet/FlowMonitor XML outputs.

## Evaluate

Run `off`, `heuristic`, and `qtable` with identical unseen run IDs, then:

```bash
python3 rl/evaluate_rl.py \
  --input off=output/rl_eval/off/run160 \
  --input heuristic=output/rl_eval/heuristic/run160 \
  --input qtable=output/rl_eval/qtable/run160 \
  --out output/rl_eval/summary.csv
```

Repeat `--input` with the same label to aggregate multiple runs. Report P95/P99
delay, loss, deadline misses, reward, and path switching by traffic class.

Use `--pcap=true` on a short verification run. MQTT traffic for a remote action
must appear on both the selected mesh capture and selected northbound capture.
