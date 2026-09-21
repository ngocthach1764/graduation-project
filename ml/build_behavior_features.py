#!/usr/bin/env python3
"""Build causal per-flow-window features from scada_packets.csv.

Each output row is a decision point for one flow and summarizes its trailing
one-second window. Every feature uses only the current or earlier packets.
Simulator-only service requirements provide the training target but are never
included in the feature vector.
"""
import argparse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd


HISTORY_SECONDS = 2.0
ALPHA = 0.08
EPS = 1e-6
SILENT_GAP_CAP = 10.0
ZSCORE_CAP = 10.0
SIZE_BINS = np.array([0, 16, 32, 64, 96, 160, 256, 512, 1024, np.inf],
                     dtype=float)

FEATURES_BEHAVIOR20 = [
    'pkt_count_1s', 'current_pkt_size', 'avg_pkt_size', 'max_pkt_size',
    'pkt_size_std', 'pkt_size_entropy', 'inter_arrival_mean',
    'inter_arrival_min', 'inter_arrival_std', 'current_size_baseline_ratio',
    'time_since_last_pkt', 'silent_gap_ratio', 'pkt_rate_delta',
    'current_size_zscore', 'burst_count_100ms', 'burst_count_500ms',
    'short_long_rate_ratio', 'baseline_pkt_rate_zscore', 'baseline_size_zscore',
    'uplink_downlink_ratio',
]

REQUIRED_COLUMNS = [
    'run_id', 't', 'node_id', 'device_id', 'protocol_id', 'protocol',
    'direction', 'pkt_size', 'incident_active', 'is_warmup',
    'is_transition', 'train_usable', 'message_kind', 'scenario',
    'scenario_start', 'device_role',
]

LEGACY_SERVICE_NAMES = {
    'EMERGENCY': 'TIME_CRITICAL',
    'IMPORTANT': 'OPERATIONAL',
    'NORMAL': 'MONITORING',
}


def entropy_from_sizes(sizes):
    if not sizes:
        return 0.0
    hist, _ = np.histogram(np.asarray(sizes, dtype=float), bins=SIZE_BINS)
    probs = hist[hist > 0].astype(float) / float(len(sizes))
    return float(-(probs * np.log2(probs)).sum()) if len(probs) else 0.0


def clipped_z(value, mean, std_floor):
    return float(np.clip((value - mean) / max(std_floor, EPS),
                         -ZSCORE_CAP, ZSCORE_CAP))


@dataclass
class CausalState:
    run_id: int
    device_id: int
    protocol_id: int
    protocol: str
    direction: str
    device_role: str
    scenario: str = ''
    scenario_start: float = 0.0
    history: deque = field(default_factory=deque)
    prev_pkt_t: float | None = None
    warm_times: list = field(default_factory=list)
    warm_sizes: list = field(default_factory=list)
    baseline_ready: bool = False
    base_rate: float = 0.0
    base_size: float = 0.0
    base_iat: float = 1.0
    rate_var: float = 1.0
    size_var: float = 1.0
    current_bucket: int | None = None
    bucket_count: int = 0
    data_bucket_count: int = 0
    data_bucket_size_sum: float = 0.0

    def reset_scenario(self, scenario, scenario_start):
        self.scenario = str(scenario)
        self.scenario_start = float(scenario_start)
        self.history.clear()
        self.prev_pkt_t = None
        self.warm_times = []
        self.warm_sizes = []
        self.baseline_ready = False
        self.base_rate = 0.0
        self.base_size = 0.0
        self.base_iat = 1.0
        self.rate_var = 1.0
        self.size_var = 1.0
        self.current_bucket = None
        self.bucket_count = 0
        self.data_bucket_count = 0
        self.data_bucket_size_sum = 0.0

    def _update_baseline_bucket(self, count, data_count, avg_size):
        if not self.baseline_ready:
            return
        rate_std = max(np.sqrt(self.rate_var),
                       0.05 * max(self.base_rate, 1.0), 0.5)
        size_std = max(np.sqrt(self.size_var),
                       0.05 * max(self.base_size, 1.0), 1.0)
        # Deployment has no ground-truth label. Update only from buckets that
        # remain inside the current observable baseline envelope.
        if abs(count - self.base_rate) > 3.0 * rate_std:
            return
        if data_count > 0 and abs(avg_size - self.base_size) > 3.0 * size_std:
            return
        old_rate = self.base_rate
        self.base_rate = ALPHA * count + (1.0 - ALPHA) * self.base_rate
        self.rate_var = (ALPHA * (count - old_rate) ** 2 +
                         (1.0 - ALPHA) * self.rate_var)
        if data_count > 0:
            old_size = self.base_size
            self.base_size = (ALPHA * avg_size +
                              (1.0 - ALPHA) * self.base_size)
            self.size_var = (ALPHA * (avg_size - old_size) ** 2 +
                             (1.0 - ALPHA) * self.size_var)

    def advance_buckets(self, t):
        target = int(np.floor(t))
        if self.current_bucket is None:
            self.current_bucket = target
            return
        while self.current_bucket < target:
            avg = (self.data_bucket_size_sum / self.data_bucket_count
                   if self.data_bucket_count else self.base_size)
            self._update_baseline_bucket(self.bucket_count,
                                         self.data_bucket_count, avg)
            self.current_bucket += 1
            self.bucket_count = 0
            self.data_bucket_count = 0
            self.data_bucket_size_sum = 0.0

    def initialize_baseline(self, t):
        if self.baseline_ready:
            return
        duration = max(float(t) - self.scenario_start, 1.0)
        n_bins = max(1, int(np.ceil(duration)))
        edges = self.scenario_start + np.arange(n_bins + 1, dtype=float)
        if edges[-1] < t:
            edges = np.append(edges, float(t))
        counts, _ = np.histogram(np.asarray(self.warm_times), bins=edges)
        self.base_rate = float(len(self.warm_times) / duration)
        self.rate_var = float(np.var(counts)) if len(counts) > 1 else 1.0
        if self.warm_sizes:
            self.base_size = float(np.mean(self.warm_sizes))
            self.size_var = (float(np.var(self.warm_sizes))
                             if len(self.warm_sizes) > 1 else 1.0)
        else:
            self.base_size = 1.0
            self.size_var = 1.0
        if len(self.warm_times) > 1:
            self.base_iat = float(np.mean(np.diff(self.warm_times)))
        else:
            self.base_iat = 1.0 / max(self.base_rate, EPS)
        self.baseline_ready = True

    def add_message(self, row, downlink_times):
        t = float(row.t)
        size = float(row.pkt_size)
        scenario_start = float(row.scenario_start)
        if self.scenario != str(row.scenario) or abs(
                self.scenario_start - scenario_start) > EPS:
            self.reset_scenario(row.scenario, scenario_start)

        self.advance_buckets(t)
        warmup = int(row.is_warmup)
        transition = int(row.is_transition)
        raw_class = (str(row.service_class) if hasattr(row, 'service_class')
                     else str(row.label))
        message_service_class = LEGACY_SERVICE_NAMES.get(raw_class, raw_class)
        raw_usable = int(row.train_usable)

        data_message = str(row.message_kind) != 'PROTOCOL'
        if warmup:
            self.warm_times.append(t)
            if data_message:
                self.warm_sizes.append(size)
        elif not self.baseline_ready:
            self.initialize_baseline(t)

        time_since_last = (0.0 if self.prev_pkt_t is None
                           else max(0.0, t - self.prev_pkt_t))
        self.prev_pkt_t = t

        while self.history and self.history[0][0] < t - HISTORY_SECONDS:
            self.history.popleft()
        self.history.append((t, size, message_service_class))

        current = [(pt, ps, pc) for pt, ps, pc in self.history
                   if pt >= t - 1.0]
        previous = [(pt, ps, pc) for pt, ps, pc in self.history
                    if t - 2.0 <= pt < t - 1.0]
        times = [v[0] for v in current]
        sizes = [v[1] for v in current]
        window_classes = [v[2] for v in current]
        if 'TIME_CRITICAL' in window_classes:
            service_class = 'TIME_CRITICAL'
        elif 'OPERATIONAL' in window_classes:
            service_class = 'OPERATIONAL'
        else:
            service_class = 'MONITORING'
        pkt_count = float(len(sizes))
        byte_count = float(sum(sizes))
        avg_size = byte_count / pkt_count
        max_size = float(max(sizes))
        size_std = float(np.std(sizes, ddof=1)) if len(sizes) > 1 else 0.0
        size_entropy = entropy_from_sizes(sizes)

        iats = np.diff(np.asarray(times, dtype=float))
        iat_mean = float(iats.mean()) if len(iats) else time_since_last
        iat_min = float(iats.min()) if len(iats) else time_since_last
        iat_std = float(iats.std(ddof=1)) if len(iats) > 1 else 0.0
        iat_cov = iat_std / max(iat_mean, EPS) if iat_mean > 0 else 0.0

        burst_100 = sum(1 for pt, _, _ in current if pt >= t - 0.100)
        burst_500 = sum(1 for pt, _, _ in current if pt >= t - 0.500)
        prev_count = float(len(previous))
        prev_bytes = float(sum(v[1] for v in previous))

        if self.baseline_ready:
            rate_std = max(np.sqrt(self.rate_var),
                           0.05 * max(self.base_rate, 1.0), 0.5)
            size_std_base = max(np.sqrt(self.size_var),
                                0.05 * max(self.base_size, 1.0), 1.0)
            baseline_rate_z = clipped_z(
                pkt_count, self.base_rate, rate_std)
            baseline_size_z = clipped_z(
                avg_size, self.base_size, size_std_base)
            current_size_z = clipped_z(
                size, self.base_size, size_std_base)
            current_size_ratio = min(
                size / max(self.base_size, EPS), SILENT_GAP_CAP)
            silent_gap_ratio = min(
                time_since_last / max(self.base_iat, EPS), SILENT_GAP_CAP)
            burst_score = min(
                burst_100 / max(self.base_rate * 0.1, 1.0),
                SILENT_GAP_CAP)
        else:
            baseline_rate_z = baseline_size_z = current_size_z = 0.0
            current_size_ratio = 1.0
            silent_gap_ratio = burst_score = 0.0

        short_long_rate_ratio = float(burst_100) / max(pkt_count, 1.0)

        while downlink_times and downlink_times[0] < t - 1.0:
            downlink_times.popleft()
        down_count = len(downlink_times)

        self.bucket_count += 1
        if data_message:
            self.data_bucket_count += 1
            self.data_bucket_size_sum += size
        return {
            'run_id': self.run_id,
            'device_id': self.device_id,
            'protocol_id': self.protocol_id,
            'protocol': self.protocol,
            'direction': self.direction,
            'device_role': self.device_role,
            'scenario': self.scenario,
            'message_kind': str(row.message_kind),
            'packet_t': t,
            't_start': t,
            't_end': t,
            'window_id': int(np.floor(t)),
            'incident_active': int(service_class != 'MONITORING'),
            'is_warmup': warmup,
            'is_transition': transition,
            'train_usable': int(raw_usable == 1 and self.baseline_ready and
                                warmup == 0 and transition == 0),
            'service_class': service_class,
            'pkt_count_1s': pkt_count,
            'current_pkt_size': size,
            'byte_count_1s': byte_count,
            'avg_pkt_size': avg_size,
            'max_pkt_size': max_size,
            'pkt_size_std': size_std,
            'pkt_size_entropy': size_entropy,
            'inter_arrival_mean': iat_mean,
            'inter_arrival_min': iat_min,
            'inter_arrival_std': iat_std,
            'inter_arrival_cov': iat_cov,
            'current_size_baseline_ratio': current_size_ratio,
            'time_since_last_pkt': time_since_last,
            'silent_gap_ratio': silent_gap_ratio,
            'pkt_rate_delta': pkt_count - prev_count,
            'byte_rate_delta': byte_count - prev_bytes,
            'current_size_zscore': current_size_z,
            'burst_count_100ms': float(burst_100),
            'burst_count_500ms': float(burst_500),
            'burst_score': burst_score,
            'short_long_rate_ratio': short_long_rate_ratio,
            'baseline_pkt_rate_zscore': baseline_rate_z,
            'baseline_size_zscore': baseline_size_z,
            'uplink_downlink_ratio': pkt_count / max(1.0, float(down_count)),
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--packets', required=True, help='Input scada_packets.csv')
    ap.add_argument('--out', required=True, help='Output scada_features.csv')
    ap.add_argument('--direction', default='uplink')
    ap.add_argument('--chunksize', type=int, default=500_000)
    args = ap.parse_args()

    header = pd.read_csv(args.packets, nrows=0).columns.tolist()
    missing = sorted(set(REQUIRED_COLUMNS) - set(header))
    if 'service_class' not in header and 'label' not in header:
        missing.append('service_class (or legacy label)')
    if missing:
        raise SystemExit(
            'Raw packet CSV uses the old schema. Regenerate it with the '
            f'updated ns-3 code. Missing columns: {missing}')

    states = {}
    downlink_history = defaultdict(deque)
    rows = []
    total_rows = 0
    chunk_count = 0
    last_t = -np.inf

    label_column = 'service_class' if 'service_class' in header else 'label'
    use_columns = REQUIRED_COLUMNS + [label_column]
    for chunk in pd.read_csv(args.packets, usecols=use_columns,
                             chunksize=args.chunksize):
        chunk_count += 1
        total_rows += len(chunk)
        for row in chunk.itertuples(index=False):
            t = float(row.t)
            if t + EPS < last_t:
                raise SystemExit('scada_packets.csv is not time ordered')
            last_t = t
            key = (int(row.run_id), int(row.device_id), int(row.protocol_id))
            if row.direction == 'downlink':
                q = downlink_history[key]
                q.append(t)
                while q and q[0] < t - 1.0:
                    q.popleft()
                continue
            if row.direction != args.direction:
                continue

            st = states.get(key)
            if st is None:
                st = CausalState(
                    int(row.run_id), int(row.device_id), int(row.protocol_id),
                    str(row.protocol), str(row.direction), str(row.device_role))
                states[key] = st
            rows.append(st.add_message(row, downlink_history[key]))

        if chunk_count % 5 == 0:
            print(f'  processed {total_rows:,} packet rows; '
                  f'causal message samples so far: {len(rows):,}')

    if not rows:
        raise SystemExit(f'No packets found for direction={args.direction}')

    out = pd.DataFrame(rows).sort_values(
        ['run_id', 'packet_t', 'device_id']).reset_index(drop=True)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(path, index=False)

    usable = out[out['train_usable'] == 1]
    print(f'Wrote {path} ({len(out)} rows, {len(usable)} train usable)')
    print(usable['service_class'].value_counts())
    print('\nUsable message kinds:')
    print(usable.groupby(['service_class', 'message_kind']).size())


if __name__ == '__main__':
    main()
