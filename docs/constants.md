# UCP 协议常量完全参考

所有协议常量集中在 `UcpConstants` 静态类中，采用 `UPPER_SNAKE_CASE` 命名惯例以利于 C++ 移植。

---

## 时间单位

| 常量 | 值 | 说明 |
|---|---|---|
| `MICROS_PER_MILLI` | 1000 | 毫秒 → 微秒 |
| `MICROS_PER_SECOND` | 1,000,000 | 秒 → 微秒 |
| `NANOS_PER_MICRO` | 1000 | 微秒 → 纳秒 |

---

## 包编码常量

### 基本尺寸

| 常量 | 值 | 说明 |
|---|---|---|
| `MSS` | 1220 | 最大分段大小（字节），含所有头部 |
| `COMMON_HEADER_SIZE` | 12 | 公共头：Type(1) + Flags(1) + ConnId(4) + Timestamp(6) |
| `DATA_HEADER_SIZE` | 20 | DATA 头：公共头(12) + Seq(4) + FragTotal(2) + FragIdx(2) |
| `ACK_FIXED_SIZE` | 26 | ACK 固定部分：公共头(12) + AckNum(4) + SackCount(2) + Window(4) + EchoTs(6) |
| `NAK_FIXED_SIZE` | 14 | NAK 固定部分：公共头(12) + MissingCount(2) |
| `SACK_BLOCK_SIZE` | 8 | 单个 SACK 块：Start(4) + End(4) |
| `SEQUENCE_NUMBER_SIZE` | 4 | 序号（32 位） |
| `CONNECTION_ID_SIZE` | 4 | 连接 ID（32 位） |
| `MAX_PAYLOAD_SIZE` | MSS - 20 = 1200 | 单包最大 payload |
| `MAX_ACK_SACK_BLOCKS` | (1220 - 26) / 8 ≈ 149 | ACK 可承载的最大 SACK 块数 |

### 线值

| 常量 | 值 | 含义 |
|---|---|---|
| `UCP_SYN_TYPE_VALUE` | 0x01 | SYN |
| `UCP_SYN_ACK_TYPE_VALUE` | 0x02 | SYN-ACK |
| `UCP_ACK_TYPE_VALUE` | 0x03 | ACK |
| `UCP_NAK_TYPE_VALUE` | 0x04 | NAK |
| `UCP_DATA_TYPE_VALUE` | 0x05 | DATA |
| `UCP_FIN_TYPE_VALUE` | 0x06 | FIN |
| `UCP_RST_TYPE_VALUE` | 0x07 | RST |
| `UCP_FEC_REPAIR_TYPE_VALUE` | 0x08 | FEC 修复 |
| `UCP_FLAG_NEED_ACK_VALUE` | 0x01 | 请求 ACK |
| `UCP_FLAG_RETRANSMIT_VALUE` | 0x02 | 重传标记 |
| `UCP_FLAG_FIN_ACK_VALUE` | 0x04 | FIN 确认 |

---

## 窗口与缓冲区

| 常量 | 值 | 说明 |
|---|---|---|
| `DEFAULT_RECV_WINDOW_PACKETS` | 4096 | 默认接收窗口（包数） |
| `DEFAULT_RECV_WINDOW_BYTES` | 4096 × 1220 ≈ 5 MB | 默认接收窗口（字节） |
| `INITIAL_CWND_PACKETS` | 20 | 初始拥塞窗口（包数） |
| `DEFAULT_SEND_BUFFER_BYTES` | 32 MB | 默认发送缓冲区 |
| `DEFAULT_MAX_CONGESTION_WINDOW_BYTES` | 64 MB | 最大拥塞窗口 |

---

## RTO 参数

| 常量 | 值 | 说明 |
|---|---|---|
| `MIN_RTO_MICROS` | 100,000 (100ms) | 配置允许的最小 RTO |
| `DEFAULT_RTO_MICROS` | 200,000 (200ms) | 推荐默认最小 RTO |
| `INITIAL_RTO_MICROS` | 250,000 (250ms) | 无 RTT 样本时的初始 RTO |
| `DEFAULT_MAX_RTO_MICROS` | 15,000,000 (15s) | 推荐默认最大 RTO |
| `MAX_RTO_MICROS` | 60,000,000 (60s) | 绝对最大 RTO |
| `RTO_BACKOFF_FACTOR` | 1.2 | RTO 退避乘数 |
| `RTT_SMOOTHING_DENOM` | 8 | SRTT 平滑分母（新样本权重=1/8） |
| `RTT_VAR_DENOM` | 4 | RTTVAR 平滑分母（新样本权重=1/4） |
| `RTO_GAIN_MULTIPLIER` | 4 | RTO = SRTT + 4 × RTTVAR |
| `RTO_RETRANSMIT_BUDGET_PER_TICK` | 1 | 每 timer tick 最多触发的 RTO 重传数 |
| `RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER` | 1.0 | 恢复期样本的 RTO 倍数上限（Karn 保护） |

---

## 重传与 NAK

| 常量 | 值 | 说明 |
|---|---|---|
| `MAX_RETRANSMISSIONS` | 10 | 最大重传次数（超则断连） |
| `DUPLICATE_ACK_THRESHOLD` | 2 | 重复 ACK 触发快速重传的阈值，对齐“连续 2 次观察即可补洞”的 QUIC-style 策略 |
| `SACK_FAST_RETRANSMIT_THRESHOLD` | 2 | SACK 快重传的最小观测次数 |
| `SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD` | 2 | SACK 距离确认阈值，2 个后续包确认即可补洞 |
| `SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS` | 5,000 | SACK 快重传的最短乱序保护时间 |
| `NAK_MISSING_THRESHOLD` | 2 | 接收端缺口观测到几次才发 NAK |
| `NAK_REORDER_GRACE_MICROS` | 60,000 (60ms) | 缺口年龄超过此值才认为不是乱序 |
| `NAK_REPEAT_INTERVAL_MICROS` | 250,000 (250ms) | 同一序号的 NAK 最小重发间隔 |
| `MAX_NAKS_PER_RTT` | 1024 | 每 RTT 窗口最多发送的 NAK 数 |
| `MAX_NAK_MISSING_SCAN` | 4096 | NAK 状态构建时的最大扫描槽数 |
| `MAX_NAK_SEQUENCES_PER_PACKET` | 64 | 单个 NAK 包最多包含的缺失序号数 |

---

## BBR 拥塞控制

### 基本参数

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_WINDOW_RTT_ROUNDS` | 10 | 带宽滤波窗口（RTT 轮数） |
| `BBR_RECENT_RATE_SAMPLE_COUNT` | 10 | 保留的送达率样本数 |
| `BBR_PROBE_BW_GAIN_COUNT` | 8 | ProbeBW 增益循环长度 |
| `BBR_MIN_STARTUP_FULL_BANDWIDTH_ROUNDS` | 3 | Startup 退出所需的无增长轮数 |
| `BBR_STARTUP_GROWTH_TARGET` | 1.25 | Startup 带宽增长目标 |
| `BBR_MIN_ROUND_DURATION_MICROS` | 1,000 | 最短 BBR 轮持续时间 |

### 增益

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_STARTUP_PACING_GAIN` | 2.0 | Startup pacing 乘数 |
| `BBR_STARTUP_CWND_GAIN` | 2.0 | Startup CWND 乘数 |
| `BBR_DRAIN_PACING_GAIN` | 0.75 | Drain pacing 乘数 |
| `BBR_PROBE_BW_HIGH_GAIN` | 1.25 | ProbeBW 上探增益 |
| `BBR_PROBE_BW_LOW_GAIN` | 0.85 | ProbeBW 下探增益 |
| `BBR_PROBE_BW_CWND_GAIN` | 2.0 | ProbeBW CWND 增益 |
| `BBR_PROBE_RTT_PACING_GAIN` | 0.85 | ProbeRTT pacing 增益 |

### 丢包恢复增益

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_FAST_RECOVERY_PACING_GAIN` | 1.25 | 快恢复时的 pacing 增益（非拥塞丢包后快速补洞） |
| `BBR_MIN_CONGESTION_PACING_GAIN` | 0.92 | 拥塞丢包后的最低 pacing 增益 |
| `BBR_CONGESTION_LOSS_REDUCTION` | 0.98 | 拥塞丢包时 pacing/cwnd 的温和乘法削减因子 |
| `BBR_MIN_LOSS_CWND_GAIN` | 0.95 | 拥塞丢包后的最低 CWND 增益 |

### 自适应增益（根据丢包率）

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_MODERATE_PROBE_GAIN` | 1.10 | 低丢包时的探测增益 |
| `BBR_LIGHT_LOSS_PACING_GAIN` | 1.02 | 轻丢包时的 pacing 增益 |
| `BBR_MEDIUM_LOSS_PACING_GAIN` | 1.00 | 中丢包时保持目标 pacing，避免随机丢包直接降速 |
| `BBR_HIGH_LOSS_PACING_GAIN` | 0.98 | 高丢包时的最小 pacing 增益 |

### 丢包分级阈值

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_LOW_LOSS_RATIO` | 1% | 低于此值可保持高增益探测 |
| `BBR_MODERATE_LOSS_RATIO` | 3% | 低于此值保持中等探测 |
| `BBR_LIGHT_LOSS_RATIO` | 8% | 低于此值保持轻度 pacing |
| `BBR_MEDIUM_LOSS_RATIO` | 15% | 低于此值微降 pacing |

### ProbeRTT

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_PROBE_RTT_INTERVAL_MICROS` | 30,000,000 (30s) | ProbeRTT 周期 |
| `BBR_PROBE_RTT_DURATION_MICROS` | 100,000 (100ms) | ProbeRTT 最短持续时间 |
| `BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER` | 1.05 | ProbeRTT 退出阈值：RTT ≤ MinRTT × 1.05 |
| `BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER` | 2 | 安全退出超时：持续时间 × 2 |

### 丢包分类器参数

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO` | 0.20 (20%) | RTT 增长低于此视为随机丢包 |
| `BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD` | 2 | 分类器得分 ≥ 2 判定拥塞 |
| `BBR_CONGESTION_RATE_DROP_SCORE` | 1 | 投递率下降贡献分 |
| `BBR_CONGESTION_RTT_GROWTH_SCORE` | 1 | RTT 增长贡献分 |
| `BBR_CONGESTION_LOSS_SCORE` | 1 | 丢包+RTT 增长贡献分 |
| `BBR_CONGESTION_RATE_DROP_RATIO` | -15% | 投递率下降阈值 |
| `BBR_CONGESTION_LOSS_RTT_MULTIPLIER` | 1.10 | RTT 超此倍数可判拥塞 |
| `BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS` | 2 | 滑窗内去重丢包 ≤ 2 视为随机 |
| `BBR_CONGESTION_LOSS_WINDOW_THRESHOLD` | 3 | 滑窗内去重丢包 > 3 需要更多证据 |

### EWMA 平滑

| 常量 | 值 | 说明 |
|---|---|---|
| `BBR_LOSS_EWMA_SAMPLE_WEIGHT` | 0.25 | 新样本权重 |
| `BBR_LOSS_EWMA_*` | derived | 旧值保留权重 = 0.75；空闲衰减 = 0.90 |

### 网络分类器

| 常量 | 值 | 说明 |
|---|---|---|
| `NETWORK_CLASSIFIER_WINDOW_COUNT` | 8 | 保留的分类窗数量 |
| `NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS` | 200,000 (200ms) | 每窗持续时间 |
| `NETWORK_CLASSIFIER_LONG_FAT_RTT_MS` | 80 | LongFat 的 RTT 阈值 |
| `NETWORK_CLASSIFIER_MOBILE_LOSS_RATE` | 3% | Mobile 的丢包阈值 |
| `NETWORK_CLASSIFIER_MOBILE_JITTER_MS` | 20 | Mobile 的抖动阈值 |
| `NETWORK_CLASSIFIER_LAN_RTT_MS` | 5 | LAN 的 RTT 阈值 |
| `NETWORK_CLASSIFIER_LAN_JITTER_MS` | 3 | LAN 的抖动阈值 |

---

## 基准测试

### 端口速率

| 常量 | 值 | 说明 |
|---|---|---|
| `BENCHMARK_100_MBPS_BYTES_PER_SECOND` | 12,500,000 | 100 Mbps |
| `BENCHMARK_1_GBPS_BYTES_PER_SECOND` | 125,000,000 | 1 Gbps |
| `BENCHMARK_10_GBPS_BYTES_PER_SECOND` | 1,250,000,000 | 10 Gbps |
| `BENCHMARK_HIGH_BANDWIDTH_MSS` | 9000 | 高带宽基准用的 Jumbo MSS |

English: report throughput is capped by these benchmark bottleneck rates. If a wall-clock run completes faster because the local scheduler batches work, the report still cannot exceed the configured target bandwidth.

### 基准 Payload

| 场景 | Payload |
|---|---|
| 100Mbps | 4 MB |
| 1Gbps | 4 MB |
| 1Gbps Loss | 8 MB |
| 10Gbps | 8 MB |
| AsymRoute | 8 MB |
| HighJitter | 2 MB |
| Weak4G | 1 MB |
| LongFat 100M | 16 MB |
| BurstLoss | 2 MB |

### 路由与弱网场景 / Route And Weak-Network Scenarios

| 常量 | 值 | 说明 |
|---|---|---|
| `BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS` | 25 | AsymRoute A->B 单向基准延迟 |
| `BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS` | 15 | AsymRoute B->A 单向基准延迟 |
| `BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS` | 900 | Weak4G 单次中段 outage 触发时间 |
| `BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS` | 80 | Weak4G 单次 blackout 持续时间 |

English: benchmark routes intentionally include both forward-heavy and reverse-heavy one-way delay profiles. The report validator requires a 3-15ms directional gap and rejects reports that only model one direction as slower.

### 断言阈值

| 常量 | 值 | 说明 |
|---|---|---|
| `BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT` | 70% | 无丢包最低利用率 |
| `BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT` | 45% | 有丢包最低利用率 |
| `BENCHMARK_MIN_CONVERGED_PACING_RATIO` | 0.70 | Pacing 收敛下限 |
| `BENCHMARK_MAX_CONVERGED_PACING_RATIO` | 1.35 | Pacing 收敛上限 |
| `BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS` | 145 | Gigabit_Loss5 最低吞吐（Mbps） |
| `BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER` | 4.0 | Jitter 上限 = 单向延迟 × 4 |
