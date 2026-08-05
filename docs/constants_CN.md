# PPP PRIVATE NETWORK™ X — 通用通信协议 (UCP) — 常量参考

[English](constants.md) | [文档索引](index_CN.md)

所有协议常量按子系统分类组织。时间值以微秒为单位（除非另有说明），大小以字节为单位。每个表都引用定义源文件并注明实现差异。

定义文件：
- `Ucp/UcpConstants.cs` — C# 参考实现
- `cpp/include/ucp/ucp_constants.h` — C++ 原生实现
- `linux/tcp_kcc.c` — Linux 内核模块：KCC v2.0（Geodesic Congestion Control，含 KF (KCC Forwarding) 组件）
- `Ucp.Tests/UcpBenchmarkConstants.cs` — 基准测试常量

## 0. 时间单位转换

| 常量 | 值 | 定义位置 |
|---|---|---|
| MICROS_PER_MILLI | 1000 | UcpConstants.cs, ucp_constants.h |
| MICROS_PER_SECOND | 1000000 | UcpConstants.cs, ucp_constants.h |
| NANOS_PER_MICRO | 1000 | ucp_constants.h (仅 C++) |
| NANOS_PER_MILLI | 1000000 | ucp_constants.h (仅 C++) |

## 1. 包编码与线格式

### 头部大小

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| MSS | 1220 | 适配 IPv6 最小 MTU (1280) 减去头部 | 两者 |
| COMMON_HEADER_SIZE | 12 | Type(1)+Flags(1)+ConnId(4)+Timestamp(6) | 两者 |
| DATA_HEADER_SIZE | 20 | 公共头(12)+SeqNum(4)+FragTotal(2)+FragIndex(2) | 两者 |
| DATA_HEADER_SIZE_WITH_ACK | 36 | 20+AckNum(4)+SackCount(2)+Window(4)+EchoTs(6) | 两者 |
| ACK_FIXED_SIZE | 28 | 公共头(12)+AckNum(4)+SackCount(2)+Window(4)+EchoTs(6) | 两者 |
| NAK_FIXED_SIZE | 18 | 公共头(12)+AckNum(4)+MissingCount(2) | 两者 |
| MAX_PAYLOAD_SIZE | 1200 | MSS(1220) - DATA_HEADER_SIZE(20) | 两者 |
| SACK_BLOCK_SIZE | 8 | StartSeq(4)+EndSeq(4) | 两者 |
| SEQUENCE_NUMBER_SIZE | 4 | uint32 | 两者 |
| ACK_NUMBER_SIZE | 4 | uint32 | 两者 |
| CONNECTION_ID_SIZE | 4 | uint32 | 两者 |
| ACK_TIMESTAMP_FIELD_SIZE | 6 | uint48，约 8.9 年范围（2^48 微秒） | 两者 |
| PACKET_TYPE_FIELD_SIZE | 1 | byte | 两者 |
| PACKET_FLAGS_FIELD_SIZE | 1 | byte | 两者 |
| SESSION_KEY_SIZE | 8 | ulong，仅 C# | UcpConstants.cs |

### 序列化位宽

| 常量 | 值 | 定义位置 |
|---|---|---|
| UINT16_BITS | 16 | 两者 |
| UINT24_BITS | 24 | 两者 |
| UINT32_BITS | 32 | 两者 |
| UINT40_BITS | 40 | 两者 |
| UINT48_BITS | 48 | ucp_constants.h (仅 C++) |
| UINT56_BITS | 56 | ucp_constants.h (仅 C++) |
| BYTE_BITS | 8 | 两者 |
| UINT48_MASK | 0x0000FFFFFFFFFFFF | 两者 |

### 线格式类型与标志字节

| 常量 | 值 | 含义 | 定义位置 |
|---|---|---|---|
| UCP_SYN_TYPE_VALUE | 0x01 | 连接请求 | UcpConstants.cs |
| UCP_SYN_ACK_TYPE_VALUE | 0x02 | 连接接受 | UcpConstants.cs |
| UCP_ACK_TYPE_VALUE | 0x03 | 累积确认 | UcpConstants.cs |
| UCP_NAK_TYPE_VALUE | 0x04 | 否定确认 | UcpConstants.cs |
| UCP_DATA_TYPE_VALUE | 0x05 | 应用数据 | UcpConstants.cs |
| UCP_FIN_TYPE_VALUE | 0x06 | 优雅关闭 | UcpConstants.cs |
| UCP_RST_TYPE_VALUE | 0x07 | 硬重置 | UcpConstants.cs |
| UCP_FEC_REPAIR_TYPE_VALUE | 0x08 | FEC 修复包 | UcpConstants.cs |
| UCP_FLAG_NEED_ACK_VALUE | 0x01 | 请求立即 ACK | UcpConstants.cs |
| UCP_FLAG_RETRANSMIT_VALUE | 0x02 | 重传标识 | UcpConstants.cs |
| UCP_FLAG_FIN_ACK_VALUE | 0x04 | FIN 已确认 | UcpConstants.cs |
| UCP_FLAG_HAS_ACK_VALUE | 0x08 | 捎带 ACK 存在 | UcpConstants.cs |
| UCP_FLAG_PRIORITY_MASK | 0x30 | 2 位优先级字段 | UcpConstants.cs |
| UCP_FLAG_MTU_PROBE_VALUE | 0x40 | DPLPMTUD MTU 探测 | UcpConstants.cs |
| UCP_FLAG_PATH_CHALLENGE_VALUE | 0x80 | 路径挑战/响应 | UcpConstants.cs |
| UCP_FLAGS_NONE_VALUE | 0x00 | 空标志 | UcpConstants.cs |

### 计算常量

| 常量 | 值 | 定义位置 |
|---|---|---|
| MAX_ACK_SACK_BLOCKS | (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE = 149 | UcpConstants.cs |

## 2. 窗口与缓冲区大小

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| DEFAULT_RECV_WINDOW_PACKETS | 4096 | 默认 MSS 下约 5 MB | 两者 |
| INITIAL_CWND_PACKETS | 10 | 约 12 KB，符合 IW10 标准 | 两者 |
| DEFAULT_SEND_BUFFER_BYTES | 33,554,432 (32 MB) | 吸收 10 Gbps 应用写入 | 两者 |
| DEFAULT_DELAYED_ACK_TIMEOUT_MICROS | 100 | 子 RTT 批量确认 | 两者 |
| DEFAULT_MAX_BANDWIDTH_WASTE_RATIO | 0.25 (25%) | 重传开销上限 | 两者 |
| DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT | 25% | 用户可见丢包上限 | 两者 |
| MIN_MAX_BANDWIDTH_LOSS_PERCENT | 15% | 验证下限 | 两者 |
| MAX_MAX_BANDWIDTH_LOSS_PERCENT | 35% | 验证上限 | 两者 |
| UDP_SOCKET_BUFFER_BYTES | 4,194,304 (4 MB) | 套接字缓冲区吸收突发 | UcpConstants.cs |
| DEFAULT_MAX_CONGESTION_WINDOW_BYTES | 67,108,864 (64 MB) | 在途字节硬上限 | 两者 |
| DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND | 12,500,000 (100 Mbps) | 服务器出口上限 | 两者 |
| DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND | 同服务器带宽 | KCC 初始估计值 | 两者 |
| DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND | 同服务器带宽 | Pacing 速率上限 | 两者 |

## 3. Pacing 与队列

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| DEFAULT_MIN_PACING_INTERVAL_MICROS | 0 | 无人工包间隔下限 | 两者 |
| DEFAULT_PACING_BUCKET_DURATION_MICROS | 10,000 (10 ms) | Token Bucket 填充窗口 | 两者 |
| FAIR_QUEUE_ROUND_MILLISECONDS | 10 ms | 公平队列信用分配周期 | 两者 |
| MAX_BUFFERED_FAIR_QUEUE_ROUNDS | 4 | 空闲连接最大信用累积 | 两者 |
| DEFAULT_PACING_WAIT_MICROS | 1000 (1 ms) | 速率未知时的后备间隔 | UcpConstants.cs |
| SendQuantumBytes (配置) | 1220 (MSS) | 最小发送量子 | UcpConfiguration.cs |

## 4. RTO 与恢复定时器

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| MIN_RTO_MICROS | 50,000 (50 ms) | 配置验证下限 | 两者 |
| DEFAULT_RTO_MICROS | 50,000 (50 ms) | 测得 SRTT 前的默认值 | 两者 |
| INITIAL_RTO_MICROS | 50,000 (50 ms) | 首个 RTT 样本前使用 | 两者 |
| DEFAULT_MAX_RTO_MICROS | 15,000,000 (15 s) | 正常操作时的上限 | 两者 |
| MAX_RTO_MICROS | 60,000,000 (60 s) | 绝对硬上限 | 两者 |
| RTO_BACKOFF_FACTOR | 1.2 | 每次超时的乘法因子 (TCP 为 2.0) | 两者 |
| MAX_RETRANSMISSIONS | 10 | 断开前最大重传次数 | 两者 |
| RTO_RETRANSMIT_BUDGET_PER_TICK | 4 段/tick | 每定时器 tick 最大 RTO 重传数 | 两者 |
| RTO_ACK_PROGRESS_SUPPRESSION_MICROS | 2000 (2 ms) | ACK 进展后的抑制窗口 | 两者 |
| URGENT_RETRANSMIT_BUDGET_PER_RTT | 8192 段/RTT | 绕过 pacer 的紧急重传上限 | 两者 |
| URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT | 75% | 紧急探测的空闲百分比 | 两者 |

### RFC 6298 RTO 计算

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| RTT_VAR_DENOM | 4 | RTTVAR EWMA 的 beta = 1/4 | 两者 |
| RTT_SMOOTHING_DENOM | 8 | SRTT EWMA 的 alpha = 1/8 | 两者 |
| RTO_GAIN_MULTIPLIER | 4 | RTO = SRTT + K x RTTVAR 中的 K=4 | 两者 |
| RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER | 4.0 | 恢复期间 Karn 算法阈值 | 两者 |
| RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER | 2 | 退避 RTO 上限为 2 x MIN_RTO | 两者 |

## 5. KCC 拥塞控制（3 模式状态机）

**流量控制边界**：STARTUP 阶段（达到满带宽前），可发送上限为对端宣告的接收窗口——初始 cwnd 不限制首次突发。达到满带宽后，上限为 min(cwnd, 对端宣告的接收窗口)。STARTUP 阶段对端宣告的 `WindowSize` 才是在途字节的权威硬上限（标准 TCP/QUIC 流量控制）。


### 5.1 核心 KCC 增益

这些增益由 C# 和 C++ 实现的 UcpCongestionControl 使用。内核模块 (tcp_kcc.c) 内部实现了相同的增益（KCC_HIGH_GAIN=739、KCC_DRAIN_GAIN=88、KCC_CWND_GAIN=512 及 PROBE_BW pacing_gain 循环表）。

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| UCP_STARTUP_PACING_GAIN | **2.887** (739/256) | Startup Pacing 增益（739/256 = 2.887x；内核 KCC_HIGH_GAIN = ceil(2885 × BBR_UNIT / 1000) = 739） | UcpConstants.cs / UcpConfiguration |
| UCP_STARTUP_CWND_GAIN | **2.887** (739/256) | Startup CWND 增益 | UcpConstants.cs / UcpConfiguration |
| UCP_DRAIN_PACING_GAIN | **0.344** (88/256) | UCP 排空 Pacing 增益 | UcpConstants.cs / UcpConfiguration |
| UCP_PROBE_BW_HIGH_GAIN | 1.25 | 向上探测 (+25%) | UcpConstants.cs / UcpConfiguration |
| UCP_PROBE_BW_LOW_GAIN | 0.75 | 向下探测（排空队列） | UcpConstants.cs / UcpConfiguration |

### 5.2 KCC 状态机参数

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| UCP_BW_RT_CYCLE_LEN | 10 | 瓶颈带宽最大值过滤器窗口（RTT 轮数） | UcpConstants.cs / UcpConfiguration |

### 5.3 MinRTT 过滤器

MinRTT 跟踪由 Geodesic 估计器 G1（瞬时下降收敛）与 G3（双阈值路径增长检测）自动处理。

### 5.5 在途数据护栏

在途界限由 BDP 估计与各模式 CWND 增益推导，没有独立的在途增益常量。

### 5.6 CWND 增益

CWND 增益由拥塞控制算法按模式设置：STARTUP 中 2.887x（739/256），DRAIN 中 2.887x（739/256），PROBE_BW 中 2.0x（KCC_CWND_GAIN，匹配 UcpCongestionControl 标准行为）。

### 5.7 增益表与循环

| 常量 | 值 | 说明 | 定义位置 |
|------|-------|-------|------------|
| UCP_GAIN_SLOTS | 256 | PROBE_BW 增益表大小（KCC_GAIN_SLOTS） | UcpConstants.cs / UcpConfiguration |
| kcc_probe_bw_cycle_len | 8 | 2 的幂循环长度（KCC_CYCLE_LEN） | UcpConstants.cs / UcpConfiguration |
| kcc_cwnd_min_target | 4 | 最小 CWND 目标（包数，UCP_CWND_MIN_TARGET） | UcpConstants.cs / UcpConfiguration |
| UCP_KCC_FULL_BW_THRESH | 320（BBR 单位下 1.25x） | Startup 退出增长阈值（125/100） | UcpConstants.cs / UcpConfiguration |
| kcc_full_bw_cnt | 3 | 增长低于阈值的轮次数 | UcpConstants.cs / UcpConfiguration |
| kcc_bw_rt_cycle_len | 10 | 带宽滑动窗口最大值过滤器（kcc_bw_rt_cycle_len） | UcpConstants.cs / UcpConfiguration |

### 5.7.1 ECN 常量

| 参数 | 默认值 | 说明 | 定义位置 |
|---|---|---|---|
| kcc_ecn_enable | 0 | ECN 主开关（默认禁用） | UcpConstants.cs / UcpConfiguration |
| kcc_ecn_backoff_num/den | 20/100 | ECN 退避比例（20%） | UcpConstants.cs / UcpConfiguration |
| kcc_ecn_ewma_retained/total | 3/4 | ECN 标记率 EWMA 权重 | UcpConstants.cs / UcpConfiguration |
| kcc_ecn_idle_decay_num/den | 31/32 | 空闲时每 ACK ECN 衰减 | UcpConstants.cs / UcpConfiguration |

### 5.7.2 LT BW 常量

| 参数 | 默认值 | 说明 | 定义位置 |
|---|---|---|---|
| kcc_lt_intvl_min_rtts | 4 | LT 有效间隔最小 RTT 数 | UcpConstants.cs / UcpConfiguration |
| kcc_lt_intvl_max_mult | 4 | LT 间隔超时乘数 | UcpConstants.cs / UcpConfiguration |
| kcc_lt_loss_thresh | 50 | 最小丢包率（KCC_LT_LOSS_THRESH，约 20%：50/256） | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_ratio_num/den | 1/8 | LT BW 相对容差 | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_diff | 500 | LT BW 绝对容差（字节/秒） | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_ithresh | 5000 | LT BW srtt/min_rtt 绝对容差（微秒） | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_ema_num/den | 1/2 | LT BW EMA 系数 | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_max_rtts | 48 | LT BW 激活最大 RTT 数 | UcpConstants.cs / UcpConfiguration |

### 5.7.3 ACK 聚合常量

ACK 聚合补偿使用双窗口测量与 5-RTT 轮换（KCC_AGG_WINDOW_ROTATION_RTTS = 5，匹配 tcp_kcc.c kcc_update_ack_aggregation）。CWND 奖励由 `extra_acked`（超出 pacing 推导预期的已确认字节）按 kcc_extra_acked_gain（256 = 1.0x）缩放，受最大毫秒比例与最大窗口 RTT 数约束，每 epoch 记账上限为 ACK_EPOCH_MAX。

| 参数 | 默认值 | 说明 | 定义位置 |
|---|---|---|---|
| kcc_agg_window_rotation_rtts | 5 | 窗口轮换间隔（RTT 数） | UcpConstants.cs / UcpConfiguration |
| kcc_extra_acked_gain | 256 | extra_acked CWND 奖励增益（256 = 1.0x） | UcpConstants.cs / UcpConfiguration |
| KCC_EXTRA_ACKED_MAX_MS_RATIO | 100 | 最大 extra_acked 奖励（毫秒比例） | UcpConstants.cs / UcpConfiguration |
| KCC_EXTRA_ACKED_WIN_RTTS_MAX | 31 | 最大 extra_acked 窗口（RTT 数） | UcpConstants.cs / UcpConfiguration |
| KCC_ACK_EPOCH_MAX | 0x100000 | 每 epoch extra-acked 记账上限 | UcpConstants.cs / UcpConfiguration |

### 5.7.4 拥塞控制信号集成

拥塞控制基于以下信号进行决策：Geodesic 估计器传播延迟估计（RTT 样本）、排队延迟 EWMA（队列信号）、抖动 EWMA（路径稳定性信号）、ECN 标记比例 EWMA（拥塞信号）、ACK 聚合补偿（流量模式信号）。FEC 和 NAK 为拥塞控制引擎提供辅助投递率样本，以改善带宽/延迟估计精度。

### 5.8 RTT 与丢包率阈值

| 常量 | 值 | 条件 | 定义位置 |
|---|---|---|---|
（拥塞控制器不使用固定 RTT/丢包分级阈值；信号包括测地线传播延迟估计、排队延迟 EWMA、抖动 EWMA、ECN 标记比例 EWMA 与 ACK 聚合补偿。）

### 5.9 带宽过滤器与 EWMA

| 常量 | 值 | 定义位置 |
|---|---|---|
| UCP_INITIAL_RTTVAR_DIVISOR | 2 | UcpConstants.cs |

### 5.10 双向拥塞检测

已在 KCC 2.0 中移除：双向拥塞检测（UCP_BIDIR_*）未在任何 UCP 代码库中实现。

## 6. NAK、SACK 与丢包检测

### 基于 SACK 的快重传

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| DUPLICATE_ACK_THRESHOLD | 3 | 触发快重传的重复 ACK 数（标准 TCP 行为） | 两者 |
| SACK_FAST_RETRANSMIT_THRESHOLD | 2 | 首个空洞需要的 SACK 块数 | 两者 |
| SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD | 48 序号 | ACK 必须超过空洞 48 个序号 | 两者 |
| SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS | 5000 (5 ms) | 重传前空洞最小存在时间 | 两者 |
| DEFAULT_ACK_SACK_BLOCK_LIMIT | 2 | 每 ACK 最大 SACK 块数（QUIC 标准） | 两者 |
| MAX_SACK_SEND_COUNT | 2 | 每 SACK 范围最大发送次数 | UcpConstants.cs |
| SACK_SEND_COUNT_PURGE_THRESHOLD | 1024 | 字典清理阈值 | UcpConstants.cs |

### NAK 三级置信度系统

| 常量 | 值 | 置信度 | 定义位置 |
|---|---|---|---|
| NAK_MISSING_THRESHOLD | 2 | NAK 候选的观测次数 | 两者 |
| NAK_REORDER_GRACE_MICROS | 2000 (2 ms) | 低层保护期下限：max(2000, min(RTT/2, MIN_RTO)) | 两者 |
| NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD | 32 | 32 个到达 -> 中等置信 | 两者 |
| NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS | 1000 (1 ms) | 中层保护期 = max(baseGrace/2, 1000) | 两者 |
| NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD | 128 | 128 个到达 -> 高置信 | 两者 |
| NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS | 1000 (1 ms) | 高层保护期 = max(baseGrace/2, 1000) | 两者 |
| NAK_REPEAT_INTERVAL_MICROS | 5000 (5 ms) | 同一缺口重复 NAK 最小间隔 | UcpConstants.cs |
| MAX_NAK_SEQUENCES_PER_PACKET | 256 | 每 NAK 包最大条目数 | 两者 |
| MAX_NAK_MISSING_SCAN | 16384 | 每周期扫描上限 | 两者 |
| MAX_NAKS_PER_RTT | 1024 | NAK 发送上限 | 两者 |

### 尾部丢包与提前重传

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS | 4 | RFC 5827 提前重传触发 | 两者 |
| TLP_MAX_INFLIGHT_SEGMENTS | 2 | 尾部丢包探测触发 | 两者 |
| TLP_TIMEOUT_RTT_RATIO | 1.5 | TLP 定时器 = 1.5 x SRTT | 两者 |
| IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD | 4 | 触发立即 ACK 的乱序包数 | 两者 |
| REORDERED_ACK_MIN_INTERVAL_MICROS | 250 | 立即 ACK 的最小间隔 | 两者 |

## 7. 前向纠错 (FEC)

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| FecGroupSize (配置) | 8（默认） | 每修复组数据包数 | UcpConfiguration.cs |
| FecRedundancy (配置) | 0.0（默认） | 默认禁用 | UcpConfiguration.cs |
| MAX_FEC_SLOT_LENGTH | 1200 | 最大修复负载（匹配 MSS） | UcpConstants.cs |
| GF256_GENERATOR_POLY | 0x11d | Reed-Solomon 域多项式 | UcpConstants.cs |
| FEC_MAX_SEND_GROUPS | 16 | 出站组保留上限 | UcpConstants.cs |
| FEC_MAX_RECV_GROUPS | 16 | 入站组保留上限 | UcpConstants.cs |
| FEC_MAX_REPAIR_GROUPS | 16 | 孤立修复组上限 | UcpConstants.cs |
| FEC_ADAPTIVE_MIN_LOSS_PERCENT | 2% | 自适应 FEC 激活阈值 | UcpConstants.cs |
| ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT | 2% | 在此丢包率开始注入 | UcpConstants.cs |

## 8. CID 迁移

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| CID_ROTATE_INTERVAL_MICROS | 60,000,000 (60 s) | CID 轮换周期 | UcpConstants.cs |
| CID_RETIRE_AGE_MICROS | 120,000,000 (120 s) | 额外 CID 保留后回收 | UcpConstants.cs |
| CID_ROTATE_SEQUENCE_MARKER | 0xFFFFFFFF | 标记轮换 DATA 包的保留序号 | UcpConstants.cs |
| CID_ROTATE_ACK_TIMEOUT_MICROS | 5,000,000 (5 s) | 轮换 ACK 超时 | UcpConstants.cs |

## 9. DPLPMTUD（路径 MTU 发现）

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| MTU_PROBE_BASE | 1200 | IPv6 最小 MTU | UcpConstants.cs |
| MTU_PROBE_MAX | 1500 | 以太网 MTU 上限 | UcpConstants.cs |
| MTU_PROBE_INTERVAL_MICROS | 600,000,000 (10 分钟) | 定期重新探测间隔 | UcpConstants.cs |
| MTU_PROBE_TIMEOUT_MICROS | 10,000,000 (10 s) | 在途探测超时 | UcpConstants.cs |

## 10. 路径挑战（迁移安全）

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| PATH_CHALLENGE_TIMEOUT_MICROS | 2,000,000 (2 s) | 挑战响应超时 | UcpConstants.cs |
| PATH_CHALLENGE_RATE_LIMIT_MICROS | 5,000,000 (5 s) | 挑战最小间隔 | UcpConstants.cs |
| PATH_CHALLENGE_MAX_ATTEMPTS | 3 | 无条件接受前的连续尝试次数 | UcpConstants.cs |

## 11. 连接与会话管理

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| KEEP_ALIVE_INTERVAL_MICROS | 1,000,000 (1 s) | NAT/防火墙刷新间隔 | 两者 |
| DISCONNECT_TIMEOUT_MICROS | 4,000,000 (4 s) | 连接死亡检测 | 两者 |
| TIMER_INTERVAL_MILLISECONDS | 1 ms | 事件循环 tick | 两者 |
| FAIR_QUEUE_ROUND_MILLISECONDS | 10 ms | 信用分配周期 | 两者 |
| CONNECT_TIMEOUT_MILLISECONDS | 5000 (5 s) | 握手完成期限 | 两者 |
| CLOSE_WAIT_TIMEOUT_MILLISECONDS | 1000 (1 s) | 强制关闭前等待 FIN-ACK 时间 | 两者 |
| PAWS_TIMEOUT_MICROS | 60,000,000 (60 s) | 过期包拒绝窗口 | 两者 |
| MIN_TIMER_WAIT_MILLISECONDS | 1 ms | 避免忙等的休眠下限 | 两者 |
| MIN_HANDSHAKE_WAIT_MILLISECONDS | 100 ms | SYN 重传下限 | 两者 |
| MAX_RTT_SAMPLES | 1024 | 诊断环形缓冲区大小 | 两者 |
| HIGH_LATENCY_THRESHOLD_MICROS | 30,000 (30 ms) | 延迟 ACK 上限触发 | UcpConstants.cs |
| CONNECTION_ID_SIZE | 4 字节 (32 位) | 约 42.9 亿唯一 ID | 两者 |
| SEQUENCE_NUMBER_SIZE | 4 字节 (32 位) | 约 42.9 亿序号；按 1200B MSS、10 Gbps 计算完整回绕约需 4123 秒 | 两者 |

## 12. Geodesic 估计器模块参数

| 参数 | 默认值 | 说明 | 定义位置 |
|---|---|---|---|
| kcc_p_est_init | **1000** | 初始收敛代理，匹配 tcp_kcc.c | tcp_kcc.c |
| kcc_p_est_max | 1,000,000 | p_est 绝对上限 | tcp_kcc.c |
| kcc_p_est_floor | 10 | p_est 下限 | tcp_kcc.c |
| kcc_scale | 1024 | 定点缩放系数（2 的幂） | tcp_kcc.c |
| kcc_min_samples | 5 | min_rtt 接管前最小样本数 | tcp_kcc.c |
| kcc_rtt_sample_max_us | 500,000 | RTT 样本上限（微秒） | tcp_kcc.c |

p_est 是 Geodesic 估计器的标量置信代理（init = 1000，floor = 10，max = 1,000,000）。所有增益固定（无增益衰减）。

### 12.1 KCC 2.0 内核常量（tcp_kcc.c）

`linux/tcp_kcc.c` 中定义的完整 KCC 2.0 常量集：

| 常量 | 值 | 用途 |
|---|---|---|
| KCC_BW_SCALE / KCC_BW_UNIT | 24 / 1<<24 | 投递率定点表示 |
| KCC_BBR_SCALE / KCC_BBR_UNIT | 8 / 256 | 增益定点表示（BBR_UNIT = 256） |
| KCC_SCALE_SHIFT / KCC_SCALE | 10 / 1024 | Geodesic x_est 定点表示 |
| G2_GROWTH_NUM / DEN | 122 / 1000 | G2 向上有界增长（每 RTT 12.2%） |
| G3_FAST_TH_NUM / DEN | 11 / 10 | G3 快路径增长阈值（1.10x） |
| G3_SLOW_TH_NUM / DEN | 21 / 20 | G3 慢路径增长阈值（1.05x） |
| G3_FAST_CNT | 6 | 更新 min_rtt 所需连续快事件数 |
| G3_SLOW_CNT | 7 | 更新 min_rtt 所需连续慢事件数 |
| KCC_LOCK_THRESH_US | 5000 | 低于 5 ms 时 min_rtt 锁定 |
| KCC_FAST_ONLY_THRESH_US | 7500 | 高于 7.5 ms 时仅启用 G3 快路径 |
| KCC_STALENESS_RNDS | 128 | Geodesic 下拉前的过期轮数 |
| KCC_P_EST_INIT | 1000 | 初始收敛代理 |
| KCC_P_EST_FLOOR | 10 | p_est 下限 |
| KCC_P_EST_DECAY_SHIFT | 4 | p_est 衰减（接近 min_rtt） |
| KCC_P_EST_GROWTH_SHIFT | 3 | p_est 增长（高于 1.10x min_rtt） |
| KCC_P_EST_MAX | 1,000,000 | p_est 上限 |
| KCC_MIN_SAMPLES | 5 | Geodesic min_rtt 接管前最小样本数 |
| KCC_HIGH_GAIN | 739 | STARTUP pacing/cwnd 增益（2.887x） |
| KCC_DRAIN_GAIN | 88 | DRAIN pacing 增益（0.344x） |
| KCC_CWND_GAIN | 512 | PROBE_BW cwnd 增益（2.0x） |
| KCC_FULL_BW_THRESH | 320 | Startup 退出阈值（1.25x） |
| KCC_FULL_BW_CNT | 3 | 无 ≥1.25x 增长的轮数 |
| KCC_CYCLE_LEN | 8 | PROBE_BW 增益循环长度 |
| KCC_PACING_INIT_GAIN | 739 | 由 RTT 推导的初始 pacing 增益 |
| KCC_MIN_TSO_RATE | 1,200,000 | TSO 除数切换阈值 |
| KCC_MIN_TSO_RATE_DIV | 8 | 默认 TSO 除数 |
| KCC_LT_INTVL_MIN_RTTS | 4 | LT 间隔最小 RTT 数 |
| KCC_LT_LOSS_THRESH | 50 | LT 丢包率阈值 |
| KCC_LT_BW_RATIO_NUM / DEN | 1 / 8 | LT BW 相对容差 |
| KCC_LT_BW_DIFF | 500 | LT BW 绝对容差（字节/秒） |
| KCC_LT_BW_MAX_RTTS | 48 | LT BW 激活上限（RTT 数） |
| KCC_LT_BW_EMA_NUM / DEN | 1 / 2 | LT BW EMA 系数 |
| KCC_LT_BW_ITHRESH | 5000 | LT BW srtt/min_rtt 容差（微秒） |
| KCC_KF_CHI2_NUM / DEN | 384 / 100 | KF 卡方门控阈值 |
| KCC_KF_Q_SHIFT | 20 | KF 过程噪声协方差位移 |
| KCC_KF_STEADY_R_PCT | 5 | KF 稳态测量噪声百分比 |
| KCC_KF_STARTUP_R_PCT | 15 | KF 启动期测量噪声百分比 |
| KCC_KF_OVERFLOW_GUARD | 1<<31 | KF 溢出防护 |
| KCC_KF_CWND_SEGS_MAX | 20000 | KF 初始 cwnd 上限（段数） |
| KCC_KF_DISCOUNT_NUM / DEN | 50 / 100 | KF 初始带宽折扣 |
| KCC_EXTRA_ACKED_MAX_MS_RATIO | 100 | ACK 聚合奖励上限（毫秒比例） |
| KCC_EXTRA_ACKED_WIN_RTTS_MAX | 31 | ACK 聚合窗口上限（RTT 数） |
| KCC_AGG_WINDOW_ROTATION_RTTS | 5 | ACK 聚合双窗口轮换 |
| KCC_ACK_EPOCH_MAX | 0x100000 | 每 epoch extra-acked 记账上限 |
| KCC_ECN_BACKOFF_NUM / DEN | 20 / 100 | ECN 退避比例（默认禁用，kcc_ecn_enable = 0） |

## 13. 基准测试负载

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| BENCHMARK_100M_PAYLOAD_BYTES | 500 KB | 每次基准测试传输大小 | UcpBenchmarkConstants.cs |
| BENCHMARK_100M_LOSS_PAYLOAD_BYTES | 500 KB | 有损 100M 路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES | 200 KB | 高丢包 + 高 RTT | UcpBenchmarkConstants.cs |
| BENCHMARK_MOBILE_3G_PAYLOAD_BYTES | 300 KB | 移动 3G 路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_MOBILE_4G_PAYLOAD_BYTES | 300 KB | 移动 4G 路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_PAYLOAD_BYTES | 300 KB | 弱 4G 路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_SATELLITE_PAYLOAD_BYTES | 300 KB | 卫星路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_VPN_PAYLOAD_BYTES | 500 KB | VPN 隧道路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_1G_PAYLOAD_BYTES | 500 KB | 1 Gbps 无丢包 | UcpBenchmarkConstants.cs |
| BENCHMARK_1G_LOSS_PAYLOAD_BYTES | 500 KB | 1 Gbps 有丢包 | UcpBenchmarkConstants.cs |
| BENCHMARK_10G_PAYLOAD_BYTES | 500 KB | 10 Gbps | UcpBenchmarkConstants.cs |
| BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES | 500 KB | 长肥管道 100M | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_PAYLOAD_BYTES | 500 KB | 非对称路由 | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES | 500 KB | 高抖动路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_BURST_LOSS_PAYLOAD_BYTES | 500 KB | 突发丢包场景 | UcpBenchmarkConstants.cs |

## 14. 基准验收标准

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT | 70% | 无丢包路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT | 45% | 有损路径 | UcpBenchmarkConstants.cs |
| BENCHMARK_MIN_CONVERGED_PACING_RATIO | 0.05 | 下限 | UcpBenchmarkConstants.cs |
| BENCHMARK_MAX_CONVERGED_PACING_RATIO | 5.0 | 上限 | UcpBenchmarkConstants.cs |
| BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER | 4.0 | 抖动/传播延迟比 | UcpBenchmarkConstants.cs |
| BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS | 10 Mbps | 千兆 + 5% 丢包 | UcpBenchmarkConstants.cs |

## 15. 路由与弱网模拟

| 常量 | 值 | 说明 | 定义位置 |
|---|---|---|---|
| BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS | 25 ms | A->B 传播延迟 | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS | 15 ms | B->A 传播延迟 | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_JITTER_MILLISECONDS | 8 ms | 非对称抖动 | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_RANDOM_LOSS_RATE | 0.005 (0.5%) | 非对称丢包 | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS | 50 ms | 高抖动延迟 | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS | 25 ms | 高抖动范围 | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_LOSS_RATE | 0.005 (0.5%) | 高抖动丢包 | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_DELAY_MILLISECONDS | 80 ms | 弱 4G 延迟 | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_LOSS_RATE | 0.05 (5%) | 弱 4G 丢包 | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS | 900 ms | 断网周期 | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS | 80 ms | 断网持续时间 | UcpBenchmarkConstants.cs |
| BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS | 25 ms | 突发丢包延迟 | UcpBenchmarkConstants.cs |
| BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS | 4 ms | 突发丢包抖动 | UcpBenchmarkConstants.cs |

## 17. C# 与 C++ 实现差异

所有线格式常量（包类型编码、头部大小、KCC 增益、NAK 阈值、SACK 限制、FEC 多项式）在 C# 和 C++ 之间完全相同，以保证互操作性。以下默认值因平台调度差异而不同：

| 常量 | C# 默认值 | C++ 默认值 | 原因 |
|---|---|---|---|
| TIMER_INTERVAL_MILLISECONDS | 1 ms | 1 ms | 两者相同（历史上曾有差异） |
| MAX_BUFFERED_FAIR_QUEUE_ROUNDS | 4 | 4 | 两者相同（历史上曾有差异） |

## 18. Linux 内核模块 (KCC) 差异

`linux/tcp_kcc.c` 中的内核模块实现了 KCC v2.0（Geodesic Congestion Control），共享相同的拥塞控制设计理念，但由于内核集成约束，某些常量使用不同的值：

| 常量 | C#/C++ 库 | 内核 | 说明 |
|---|---|---|---|---|
| UCP_DRAIN_PACING_GAIN | 0.344 (88/256) | 0.344 | 所有实现均使用相同 0.344 排空 pacing 增益（88/256）|
| UCP_CWND_GAIN | 2.0 | 2.0 | 所有实现均在 PROBE_BW 中使用 cwnd_gain = 2.0（UCP 标准） |
| SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS | 5,000 | 不适用 | 内核依赖 TCP 栈的乱序处理 |

**关键**：内核的 `KCC_HIGH_GAIN`（启动 pacing 增益）= 739 BBR_UNIT ≈ 2.887x，计算公式为 `BBR_UNIT * 2885 / 1000 + 1` = 739（等价于 ceil(2885 × BBR_UNIT / 1000) = 739）。三个实现均使用 2.887x（739/256）作为有效启动 pacing 增益。

## 跨平台实现

本常量参考适用于三个 UCP 实现：

- **C# (.NET 8)**：参考实现。常量定义于 `UcpConstants.cs`，通过 `UcpConfiguration.cs` 暴露。
- **C++ (C++17)**：原生实现，线格式常量完全相同。详见 `cpp/docs/constants_CN.md`。
- **Linux 内核模块 (KCC)**：内核态实现，遵循相同常量以保证线格式兼容性。详见 `linux/README.md`。

---

## 许可证与商标

MIT 许可证。完整文本见 [LICENSE](../LICENSE)。

版权所有 (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ 是 PPP PRIVATE NETWORK 的商标。
