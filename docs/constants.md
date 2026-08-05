# PPP PRIVATE NETWORK™ X — Universal Communication Protocol (UCP) — Constants Reference

[Chinese](constants_CN.md) | [Documentation Index](index.md)

All protocol constants organized by subsystem. Time values are in microseconds unless stated otherwise; sizes are in bytes. Each table references the defining source file and notes implementation differences.

Defining files:
- `Ucp/UcpConstants.cs` — C# reference implementation
- `cpp/include/ucp/ucp_constants.h` — C++ native implementation
- `linux/tcp_kcc.c` — Linux kernel module: KCC v2.0 (Geodesic Congestion Control, with KF (KCC Forwarding) component)
- `Ucp.Tests/UcpBenchmarkConstants.cs` — Benchmark test constants

## 0. Time Unit Conversions

| Constant | Value | Defined In |
|---|---|---|
| MICROS_PER_MILLI | 1000 | UcpConstants.cs, ucp_constants.h |
| MICROS_PER_SECOND | 1000000 | UcpConstants.cs, ucp_constants.h |
| NANOS_PER_MICRO | 1000 | ucp_constants.h (C++ only) |
| NANOS_PER_MILLI | 1000000 | ucp_constants.h (C++ only) |

## 1. Packet Encoding & Wire Format

### Header Sizes

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| MSS | 1220 | Fits IPv6 min-MTU (1280) minus headers | Both |
| COMMON_HEADER_SIZE | 12 | Type(1)+Flags(1)+ConnId(4)+Timestamp(6) | Both |
| DATA_HEADER_SIZE | 20 | Common(12)+SeqNum(4)+FragTotal(2)+FragIndex(2) | Both |
| DATA_HEADER_SIZE_WITH_ACK | 36 | 20+AckNum(4)+SackCount(2)+Window(4)+EchoTs(6) | Both |
| ACK_FIXED_SIZE | 28 | Common(12)+AckNum(4)+SackCount(2)+Window(4)+EchoTs(6) | Both |
| NAK_FIXED_SIZE | 18 | Common(12)+AckNum(4)+MissingCount(2) | Both |
| MAX_PAYLOAD_SIZE | 1200 | MSS(1220) - DATA_HEADER_SIZE(20) | Both |
| SACK_BLOCK_SIZE | 8 | StartSeq(4)+EndSeq(4) | Both |
| SEQUENCE_NUMBER_SIZE | 4 | uint32 | Both |
| ACK_NUMBER_SIZE | 4 | uint32 | Both |
| CONNECTION_ID_SIZE | 4 | uint32 | Both |
| ACK_TIMESTAMP_FIELD_SIZE | 6 | uint48, ~8.9 years range (2^48 us) | Both |
| PACKET_TYPE_FIELD_SIZE | 1 | byte | Both |
| PACKET_FLAGS_FIELD_SIZE | 1 | byte | Both |
| SESSION_KEY_SIZE | 8 | ulong, C# only | UcpConstants.cs |

### Bit Counts for Serialization

| Constant | Value | Defined In |
|---|---|---|
| UINT16_BITS | 16 | Both |
| UINT24_BITS | 24 | Both |
| UINT32_BITS | 32 | Both |
| UINT40_BITS | 40 | Both |
| UINT48_BITS | 48 | ucp_constants.h (C++ only) |
| UINT56_BITS | 56 | ucp_constants.h (C++ only) |
| BYTE_BITS | 8 | Both |
| UINT48_MASK | 0x0000FFFFFFFFFFFF | Both |

### Wire-Format Type and Flag Bytes

| Constant | Value | Meaning | Defined In |
|---|---|---|---|
| UCP_SYN_TYPE_VALUE | 0x01 | Connection request | UcpConstants.cs |
| UCP_SYN_ACK_TYPE_VALUE | 0x02 | Connection acceptance | UcpConstants.cs |
| UCP_ACK_TYPE_VALUE | 0x03 | Cumulative ACK | UcpConstants.cs |
| UCP_NAK_TYPE_VALUE | 0x04 | Negative ACK | UcpConstants.cs |
| UCP_DATA_TYPE_VALUE | 0x05 | Application data | UcpConstants.cs |
| UCP_FIN_TYPE_VALUE | 0x06 | Graceful close | UcpConstants.cs |
| UCP_RST_TYPE_VALUE | 0x07 | Hard reset | UcpConstants.cs |
| UCP_FEC_REPAIR_TYPE_VALUE | 0x08 | FEC repair packet | UcpConstants.cs |
| UCP_FLAG_NEED_ACK_VALUE | 0x01 | Immediate ACK requested | UcpConstants.cs |
| UCP_FLAG_RETRANSMIT_VALUE | 0x02 | Retransmission | UcpConstants.cs |
| UCP_FLAG_FIN_ACK_VALUE | 0x04 | FIN acknowledged | UcpConstants.cs |
| UCP_FLAG_HAS_ACK_VALUE | 0x08 | Piggybacked ACK present | UcpConstants.cs |
| UCP_FLAG_PRIORITY_MASK | 0x30 | 2-bit priority field | UcpConstants.cs |
| UCP_FLAG_MTU_PROBE_VALUE | 0x40 | DPLPMTUD MTU probe | UcpConstants.cs |
| UCP_FLAG_PATH_CHALLENGE_VALUE | 0x80 | Path challenge/response | UcpConstants.cs |
| UCP_FLAGS_NONE_VALUE | 0x00 | Empty flags | UcpConstants.cs |

### Computed Constants

| Constant | Value | Defined In |
|---|---|---|
| MAX_ACK_SACK_BLOCKS | (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE = 149 | UcpConstants.cs |

## 2. Window & Buffer Sizes

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| DEFAULT_RECV_WINDOW_PACKETS | 4096 | ~5 MB at default MSS | Both |
| INITIAL_CWND_PACKETS | 10 | ~12 KB, TCP IW10 (RFC 6928) | Both |
| DEFAULT_SEND_BUFFER_BYTES | 33,554,432 (32 MB) | Absorbs app writes at 10 Gbps | Both |
| DEFAULT_DELAYED_ACK_TIMEOUT_MICROS | 100 | Sub-RTT batching | Both |
| DEFAULT_MAX_BANDWIDTH_WASTE_RATIO | 0.25 (25%) | Retransmit overhead ceiling | Both |
| DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT | 25% | User-facing loss ceiling | Both |
| MIN_MAX_BANDWIDTH_LOSS_PERCENT | 15% | Validation floor | Both |
| MAX_MAX_BANDWIDTH_LOSS_PERCENT | 35% | Validation ceiling | Both |
| UDP_SOCKET_BUFFER_BYTES | 4,194,304 (4 MB) | Socket buffer for burst absorption | UcpConstants.cs |
| DEFAULT_MAX_CONGESTION_WINDOW_BYTES | 67,108,864 (64 MB) | Hard cap for bytes in flight | Both |
| DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND | 12,500,000 (100 Mbps) | Server egress cap | Both |
| DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND | Same as server bandwidth | Initial KCC estimate | Both |
| DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND | Same as server bandwidth | Pacing rate ceiling | Both |

## 3. Pacing & Queuing

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| DEFAULT_MIN_PACING_INTERVAL_MICROS | 0 | No artificial inter-packet gap | Both |
| DEFAULT_PACING_BUCKET_DURATION_MICROS | 10,000 (10 ms) | Token bucket refill window | Both |
| FAIR_QUEUE_ROUND_MILLISECONDS | 10 ms | Fair-queue credit distribution cycle | Both |
| MAX_BUFFERED_FAIR_QUEUE_ROUNDS | 4 | Max credit accumulation for idle connections | Both |
| DEFAULT_PACING_WAIT_MICROS | 1000 (1 ms) | Fallback gap when rate unknown | UcpConstants.cs |
| SendQuantumBytes (config) | 1220 (MSS) | Minimum transmit quantum | UcpConfiguration.cs |

## 4. RTO & Recovery Timers

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| MIN_RTO_MICROS | 50,000 (50 ms) | Config validation floor | Both |
| DEFAULT_RTO_MICROS | 50,000 (50 ms) | Default before measured SRTT | Both |
| INITIAL_RTO_MICROS | 50,000 (50 ms) | Before first RTT sample | Both |
| DEFAULT_MAX_RTO_MICROS | 15,000,000 (15 s) | Upper cap during normal operation | Both |
| MAX_RTO_MICROS | 60,000,000 (60 s) | Absolute hard ceiling | Both |
| RTO_BACKOFF_FACTOR | 1.2 | Multiplier per timeout (vs TCP 2.0) | Both |
| MAX_RETRANSMISSIONS | 10 | Max attempts before teardown | Both |
| RTO_RETRANSMIT_BUDGET_PER_TICK | 4 segments/tick | Max RTO retransmits per timer tick | Both |
| RTO_ACK_PROGRESS_SUPPRESSION_MICROS | 2000 (2 ms) C# / 50000 (50 ms) C++ | Reserved constant; RTO suppression path removed in both implementations (RTO is the last-resort recovery) | Both |
| URGENT_RETRANSMIT_BUDGET_PER_RTT | 8192 segments/RTT | Max urgent retransmits bypassing pacer | Both |
| URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT | 75% | Idle percentage for urgent probe | Both |

### RFC 6298 RTO Computation

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| RTT_VAR_DENOM | 4 | beta = 1/4 for RTTVAR EWMA | Both |
| RTT_SMOOTHING_DENOM | 8 | alpha = 1/8 for SRTT EWMA | Both |
| RTO_GAIN_MULTIPLIER | 4 | K = 4 in RTO = SRTT + K x RTTVAR | Both |
| RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER | 4.0 | Karn's algorithm threshold during recovery | Both |
| RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER | 2 | Backed-off RTO floored at 2 x MIN_RTO | Both |

## 5. KCC Congestion Control (3-mode state machine)

**Flow control boundary**: During STARTUP (before full bandwidth is reached), the sendable upper limit is the peer-declared receive window — the initial cwnd does NOT cap the first burst. Once full bandwidth is reached, the upper limit is min(cwnd, peer-declared receive window). The peer-advertised `WindowSize` is the authoritative hard cap on bytes in flight during STARTUP (standard TCP/QUIC flow control).

### 5.1 Core KCC Gains

These gains are used by UcpCongestionControl in C# and C++ implementations. The kernel module (tcp_kcc.c) implements the same gains internally (KCC_HIGH_GAIN = 739, KCC_DRAIN_GAIN = 88, KCC_CWND_GAIN = 512, and the PROBE_BW pacing_gain cycle table).

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| UCP_STARTUP_PACING_GAIN | **2.887** (739/256) | Startup pacing gain (739/256 = 2.887x; kernel KCC_HIGH_GAIN = ceil(2885 × BBR_UNIT / 1000) = 739) | UcpConstants.cs / UcpConfiguration |
| UCP_STARTUP_CWND_GAIN | **2.887** (739/256) | Startup CWND gain | UcpConstants.cs / UcpConfiguration |
| UCP_DRAIN_PACING_GAIN | **0.344** (88/256) | UCP drain pacing gain | UcpConstants.cs / UcpConfiguration |
| UCP_PROBE_BW_HIGH_GAIN | 1.25 | Up-probe (+25%) | UcpConstants.cs / UcpConfiguration |
| UCP_PROBE_BW_LOW_GAIN | 0.75 | Down-probe (drain queue) | UcpConstants.cs / UcpConfiguration |

### 5.2 KCC State Machine Parameters

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| UCP_BW_RT_CYCLE_LEN | 10 | Bottleneck bandwidth max-filter window (RTT rounds) | UcpConstants.cs / UcpConfiguration |

### 5.3 MinRTT Filter

MinRTT tracking is handled automatically by the geodesic estimator G1 (instant-down convergence) and G3 (dual-threshold path-increase detection).

### 5.5 Inflight Guardrails

Inflight bounds are derived from the BDP estimate and per-mode CWND gains; there are no separate inflight gain constants.

### 5.6 CWND Gain

CWND gain is set per-mode by the congestion control algorithm: 2.887x (739/256) in STARTUP, 2.887x (739/256) in DRAIN, 2.0x in PROBE_BW (KCC_CWND_GAIN, matching standard UcpCongestionControl behavior).

### 5.7 Gain Table & Cycle

| Constant | Value | Notes | Defined In |
|----------|-------|-------|------------|
| UCP_GAIN_SLOTS | 256 | PROBE_BW gain table size (KCC_GAIN_SLOTS) | UcpConstants.cs / UcpConfiguration |
| kcc_probe_bw_cycle_len | 8 | Power-of-2 cycle length (KCC_CYCLE_LEN) | UcpConstants.cs / UcpConfiguration |
| kcc_cwnd_min_target | 4 | Minimum CWND target in packets (UCP_CWND_MIN_TARGET) | UcpConstants.cs / UcpConfiguration |
| UCP_KCC_FULL_BW_THRESH | 320 (1.25x in BBR units) | Startup exit growth threshold (125/100) | UcpConstants.cs / UcpConfiguration |
| kcc_full_bw_cnt | 3 | Rounds with growth below threshold | UcpConstants.cs / UcpConfiguration |
| kcc_bw_rt_cycle_len | 10 | BW sliding-window max filter (kcc_bw_rt_cycle_len) | UcpConstants.cs / UcpConfiguration |

### 5.7.1 ECN Constants

| Parameter | Default | Description | Defined In |
|-----------|---------|-------------|------------|
| kcc_ecn_enable | 0 | ECN master switch (disabled by default) | UcpConstants.cs / UcpConfiguration |
| kcc_ecn_backoff_num/den | 20/100 | ECN backoff fraction (20%) | UcpConstants.cs / UcpConfiguration |
| kcc_ecn_ewma_retained/total | 3/4 | ECN mark ratio EWMA weight | UcpConstants.cs / UcpConfiguration |
| kcc_ecn_idle_decay_num/den | 31/32 | Idle ECN decay per ACK | UcpConstants.cs / UcpConfiguration |

(ECN backoff triggers when qdelay_avg exceeds the dynamic congestion threshold max(25% of min_rtt, 500 us); there is no fixed qdelay threshold.)

### 5.7.2 LT BW Constants

| Parameter | Default | Description | Defined In |
|-----------|---------|-------------|------------|
| kcc_lt_intvl_min_rtts | 4 | LT valid interval min RTTs | UcpConstants.cs / UcpConfiguration |
| kcc_lt_intvl_max_mult | 4 | LT interval timeout multiplier | UcpConstants.cs / UcpConfiguration |
| kcc_lt_loss_thresh | 50 | Min loss ratio (KCC_LT_LOSS_THRESH, ~20%: 50/256) | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_ratio_num/den | 1/8 | LT BW relative tolerance | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_diff | 500 | LT BW absolute tolerance (bytes/s) | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_ithresh | 5000 | LT BW srtt/min_rtt absolute tolerance (us) | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_ema_num/den | 1/2 | LT BW EMA coefficient | UcpConstants.cs / UcpConfiguration |
| kcc_lt_bw_max_rtts | 48 | Max RTTs with LT BW active before reset | UcpConstants.cs / UcpConfiguration |

### 5.7.3 ACK Aggregation Constants

ACK aggregation compensation uses a dual-window measurement with a 5-RTT rotation (KCC_AGG_WINDOW_ROTATION_RTTS = 5, matching tcp_kcc.c kcc_update_ack_aggregation). The cwnd bonus is computed from `extra_acked` (bytes ACKed beyond the pacing-derived expectation) scaled by kcc_extra_acked_gain (256 = 1.0x), bounded by the max ms ratio and max window RTTs, with per-epoch accounting capped at ACK_EPOCH_MAX.

| Parameter | Default | Description | Defined In |
|-----------|---------|-------------|------------|
| kcc_agg_window_rotation_rtts | 5 | Window rotation interval (RTTs) | UcpConstants.cs / UcpConfiguration |
| kcc_extra_acked_gain | 256 | extra_acked cwnd bonus gain (256 = 1.0x) | UcpConstants.cs / UcpConfiguration |
| KCC_EXTRA_ACKED_MAX_MS_RATIO | 100 | Max extra_acked bonus (ms ratio) | UcpConstants.cs / UcpConfiguration |
| KCC_EXTRA_ACKED_WIN_RTTS_MAX | 31 | Max extra_acked window (RTTs) | UcpConstants.cs / UcpConfiguration |
| KCC_ACK_EPOCH_MAX | 0x100000 | Per-epoch extra-acked accounting cap | UcpConstants.cs / UcpConfiguration |

### 5.7.4 Congestion Control Signal Integration

The congestion controller bases decisions on the following signals: geodesic propagation delay estimate (RTT samples), queuing delay EWMA (queue signal), jitter EWMA (path stability signal), ECN marking ratio EWMA (congestion signal), and ACK aggregation compensation (traffic pattern signal). FEC and NAK provide auxiliary delivery-rate samples to the congestion control engine for improved bandwidth/delay estimation accuracy.

### 5.8 RTT & Loss Ratio Thresholds

The congestion controller does not use fixed RTT/loss ratio tiers. Signals are: geodesic propagation delay estimate (RTT samples), queuing delay EWMA (queue signal), jitter EWMA (path stability signal), ECN marking ratio EWMA (congestion signal), and ACK aggregation compensation (traffic pattern signal).

### 5.9 Bandwidth Filter & EWMA

| Constant | Value | Defined In |
|---|---|---|
| UCP_MIN_ROUND_DURATION_MICROS | 1000 (1 ms) | Both |
| UCP_INITIAL_RTTVAR_DIVISOR | 2 | UcpConstants.cs |

### 5.10 Bidirectional Congestion Detection

Removed in KCC 2.0: bidirectional congestion detection (UCP_BIDIR_*) is not implemented in any UCP codebase.

## 6. NAK, SACK & Loss Detection

### SACK-Based Fast Retransmit

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| DUPLICATE_ACK_THRESHOLD | 3 | Dup ACKs to trigger FR (standard TCP behavior) | Both |
| SACK_FAST_RETRANSMIT_THRESHOLD | 2 | SACK blocks needed for first hole | Both |
| SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD | 48 seqs | ACK must advance 48 past hole | Both |
| SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS | 5000 (5 ms) | Min hole age before retransmit | Both |
| DEFAULT_ACK_SACK_BLOCK_LIMIT | 2 | Max SACK blocks per ACK (QUIC standard) | Both |
| MAX_SACK_SEND_COUNT | 2 | Max sends per SACK range | UcpConstants.cs |
| SACK_SEND_COUNT_PURGE_THRESHOLD | 1024 | Dictionary purge threshold | UcpConstants.cs |

### NAK Three-Tier Confidence System

| Constant | Value | Confidence | Defined In |
|---|---|---|---|
| NAK_MISSING_THRESHOLD | 2 | Observations before NAK-eligible | Both |
| NAK_REORDER_GRACE_MICROS | 2000 (2 ms) | baseGrace floor: max(2000, min(RTT/2, MIN_RTO)) for Low tier | Both |
| NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD | 32 | 32 arrivals -> medium confidence | Both |
| NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS | 1000 (1 ms) | Medium tier grace = max(baseGrace/2, 1000) | Both |
| NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD | 128 | 128 arrivals -> high confidence | Both |
| NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS | 1000 (1 ms) | High tier grace = max(baseGrace/2, 1000) | Both |
| NAK_REPEAT_INTERVAL_MICROS | 5000 (5 ms) | Min between re-NAKs for same gap (declared; repeat suppression actually uses per-sequence until-data-arrives marking) | UcpConstants.cs |
| MAX_NAK_SEQUENCES_PER_PACKET | 256 | Max entries per NAK packet | Both |
| MAX_NAK_MISSING_SCAN | 16384 | Scan ceiling per cycle | Both |
| MAX_NAKS_PER_RTT | 1024 | NAK emission ceiling | Both |

### Tail Loss & Early Retransmit

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS | 4 | RFC 5827 early retransmit trigger | Both |
| TLP_MAX_INFLIGHT_SEGMENTS | 2 | Tail-loss probe trigger | Both |
| TLP_TIMEOUT_RTT_RATIO | 1.5 | TLP timer = 1.5 x SRTT | Both |
| IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD | 4 | Reordered packets forcing immediate ACK | Both |
| REORDERED_ACK_MIN_INTERVAL_MICROS | 250 | Min spacing between immediate ACKs | Both |

## 7. Forward Error Correction (FEC)

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| FecGroupSize (config) | 8 (default) | Data packets per repair group | UcpConfiguration.cs |
| FecRedundancy (config) | 0.0 (default) | Disabled by default | UcpConfiguration.cs |
| MAX_FEC_SLOT_LENGTH | 1200 | Max repair payload (matches MSS) | UcpConstants.cs |
| GF256_GENERATOR_POLY | 0x11d | Reed-Solomon field polynomial | UcpConstants.cs |
| FEC_MAX_SEND_GROUPS | 16 | Outbound group retention limit | UcpConstants.cs |
| FEC_MAX_RECV_GROUPS | 16 | Inbound group retention limit | UcpConstants.cs |
| FEC_MAX_REPAIR_GROUPS | 16 | Orphaned repair group limit | UcpConstants.cs |
| FEC_ADAPTIVE_MIN_LOSS_PERCENT | 2% | Adaptive FEC activation threshold | UcpConstants.cs |
| ADAPTIVE_FEC_LOSS_THRESHOLD_PERCENT | 2% | Injection begins at this loss level | UcpConstants.cs |

## 8. CID Migration

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| CID_ROTATE_INTERVAL_MICROS | 60,000,000 (60 s) | CID rotation period | UcpConstants.cs |
| CID_RETIRE_AGE_MICROS | 120,000,000 (120 s) | Extra CID retention before retirement | UcpConstants.cs |
| CID_ROTATE_SEQUENCE_MARKER | 0xFFFFFFFF | Reserved seqnum marking rotation DATA packets | UcpConstants.cs |
| CID_ROTATE_ACK_TIMEOUT_MICROS | 5,000,000 (5 s) | ACK timeout for rotation | UcpConstants.cs |

## 9. DPLPMTUD (Path MTU Discovery)

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| MTU_PROBE_BASE | 1200 | IPv6 minimum MTU | UcpConstants.cs |
| MTU_PROBE_MAX | 1500 | Ethernet MTU ceiling | UcpConstants.cs |
| MTU_PROBE_INTERVAL_MICROS | 600,000,000 (10 min) | Periodic re-probe interval | UcpConstants.cs |
| MTU_PROBE_TIMEOUT_MICROS | 10,000,000 (10 s) | In-flight probe timeout | UcpConstants.cs |

## 10. Path Challenge (Migration Security)

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| PATH_CHALLENGE_TIMEOUT_MICROS | 2,000,000 (2 s) | Challenge response timeout | UcpConstants.cs |
| PATH_CHALLENGE_RATE_LIMIT_MICROS | 5,000,000 (5 s) | Min interval between challenges | UcpConstants.cs |
| PATH_CHALLENGE_MAX_ATTEMPTS | 3 | Consecutive attempts before unconditional accept | UcpConstants.cs |

## 11. Connection & Session Management

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| KEEP_ALIVE_INTERVAL_MICROS | 1,000,000 (1 s) | NAT/firewall refresh interval | Both |
| DISCONNECT_TIMEOUT_MICROS | 4,000,000 (4 s) | Connection death detection | Both |
| TIMER_INTERVAL_MILLISECONDS | 1 ms | Event loop tick | Both |
| FAIR_QUEUE_ROUND_MILLISECONDS | 10 ms | Credit distribution cycle | Both |
| CONNECT_TIMEOUT_MILLISECONDS | 5000 (5 s) | Handshake completion deadline | Both |
| CLOSE_WAIT_TIMEOUT_MILLISECONDS | 1000 (1 s) | FIN-ACK wait before forced close | Both |
| PAWS_TIMEOUT_MICROS | 60,000,000 (60 s) | Stale packet rejection window | Both |
| MIN_TIMER_WAIT_MILLISECONDS | 1 ms | Sleep floor to avoid busy-spin | Both |
| MIN_HANDSHAKE_WAIT_MILLISECONDS | 100 ms | SYN retransmission floor | Both |
| MAX_RTT_SAMPLES | 1024 | Diagnostic ring buffer size | Both |
| HIGH_LATENCY_THRESHOLD_MICROS | 30,000 (30 ms) | Delayed-ACK cap trigger | UcpConstants.cs |
| CONNECTION_ID_SIZE | 4 bytes (32 bits) | ~4.29B unique IDs | Both |
| SEQUENCE_NUMBER_SIZE | 4 bytes (32 bits) | ~4.29B seqs; at 1200B MSS and 10 Gbps a full wrap takes ~4123s | Both |

## 12. Geodesic Estimator Constants

| Parameter | Default | Notes | Defined In |
|---|---|---|---|
| kcc_p_est_init | **1000** | Initial convergence proxy, matches tcp_kcc.c | tcp_kcc.c |
| kcc_p_est_max | 1,000,000 | p_est absolute upper bound | tcp_kcc.c |
| kcc_p_est_floor | 10 | p_est lower bound | tcp_kcc.c |
| kcc_scale | 1024 | Fixed-point scale (power of 2) | tcp_kcc.c |
| kcc_min_samples | 5 | Min samples before min_rtt takeover | tcp_kcc.c |
| kcc_rtt_sample_max_us | 500,000 | RTT sample ceiling (us) | tcp_kcc.c |

p_est is a scalar confidence proxy for the geodesic estimator (init = 1000, floor = 10, max = 1,000,000). All gains are fixed (no gain decay).

### 12.1 KCC 2.0 Kernel Constants (tcp_kcc.c)

The full KCC 2.0 constant set defined in `linux/tcp_kcc.c`:

| Constant | Value | Purpose |
|---|---|---|
| KCC_BW_SCALE / KCC_BW_UNIT | 24 / 1<<24 | Delivery-rate fixed point |
| KCC_BBR_SCALE / KCC_BBR_UNIT | 8 / 256 | Gain fixed point (BBR_UNIT = 256) |
| KCC_SCALE_SHIFT / KCC_SCALE | 10 / 1024 | Geodesic x_est fixed point |
| G2_GROWTH_NUM / DEN | 122 / 1000 | G2 upward bounded growth per RTT (12.2%) |
| G3_FAST_TH_NUM / DEN | 11 / 10 | G3 fast path-increase threshold (1.10x) |
| G3_SLOW_TH_NUM / DEN | 21 / 20 | G3 slow path-increase threshold (1.05x) |
| G3_FAST_CNT | 6 | Consecutive fast events to update min_rtt |
| G3_SLOW_CNT | 7 | Consecutive slow events to update min_rtt |
| KCC_LOCK_THRESH_US | 5000 | min_rtt lock below 5 ms |
| KCC_FAST_ONLY_THRESH_US | 7500 | G3 fast-only above 7.5 ms |
| KCC_STALENESS_RNDS | 128 | Staleness rounds before geodesic pull-down |
| KCC_P_EST_INIT | 1000 | Initial convergence proxy |
| KCC_P_EST_FLOOR | 10 | p_est lower bound |
| KCC_P_EST_DECAY_SHIFT | 4 | p_est decay (near min_rtt) |
| KCC_P_EST_GROWTH_SHIFT | 3 | p_est growth (above 1.10x min_rtt) |
| KCC_P_EST_MAX | 1,000,000 | p_est upper bound |
| KCC_MIN_SAMPLES | 5 | Samples before geodesic min_rtt takeover |
| KCC_HIGH_GAIN | 739 | STARTUP pacing/cwnd gain (2.887x) |
| KCC_DRAIN_GAIN | 88 | DRAIN pacing gain (0.344x) |
| KCC_CWND_GAIN | 512 | PROBE_BW cwnd gain (2.0x) |
| KCC_FULL_BW_THRESH | 320 | Startup exit threshold (1.25x) |
| KCC_FULL_BW_CNT | 3 | Rounds without >= 1.25x growth |
| KCC_CYCLE_LEN | 8 | PROBE_BW gain cycle length |
| KCC_PACING_INIT_GAIN | 739 | Initial pacing gain from RTT |
| KCC_MIN_TSO_RATE | 1,200,000 | TSO divisor switch threshold |
| KCC_MIN_TSO_RATE_DIV | 8 | Default TSO divisor |
| KCC_LT_INTVL_MIN_RTTS | 4 | LT interval minimum RTTs |
| KCC_LT_LOSS_THRESH | 50 | LT loss ratio threshold |
| KCC_LT_BW_RATIO_NUM / DEN | 1 / 8 | LT BW relative tolerance |
| KCC_LT_BW_DIFF | 500 | LT BW absolute tolerance (bytes/s) |
| KCC_LT_BW_MAX_RTTS | 48 | LT BW active cap (RTTs) |
| KCC_LT_BW_EMA_NUM / DEN | 1 / 2 | LT BW EMA coefficient |
| KCC_LT_BW_ITHRESH | 5000 | LT BW srtt/min_rtt tolerance (us) |
| KCC_KF_CHI2_NUM / DEN | 384 / 100 | KF chi-square gating threshold |
| KCC_KF_Q_SHIFT | 20 | KF process-noise covariance shift |
| KCC_KF_STEADY_R_PCT | 5 | KF steady-state measurement noise % |
| KCC_KF_STARTUP_R_PCT | 15 | KF startup measurement noise % |
| KCC_KF_OVERFLOW_GUARD | 1<<31 | KF overflow guard |
| KCC_KF_CWND_SEGS_MAX | 20000 | KF initial cwnd cap (segments) |
| KCC_KF_DISCOUNT_NUM / DEN | 50 / 100 | KF initial bandwidth discount |
| KCC_EXTRA_ACKED_MAX_MS_RATIO | 100 | ACK aggregation bonus cap (ms ratio) |
| KCC_EXTRA_ACKED_WIN_RTTS_MAX | 31 | ACK aggregation window cap (RTTs) |
| KCC_AGG_WINDOW_ROTATION_RTTS | 5 | ACK aggregation dual-window rotation |
| KCC_ACK_EPOCH_MAX | 0x100000 | Per-epoch extra-acked accounting cap |
| KCC_ECN_BACKOFF_NUM / DEN | 20 / 100 | ECN backoff fraction (disabled by default, kcc_ecn_enable = 0) |

## 13. Benchmark Payloads

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| BENCHMARK_100M_PAYLOAD_BYTES | 500 KB | Transfer size per benchmark run | UcpBenchmarkConstants.cs |
| BENCHMARK_100M_LOSS_PAYLOAD_BYTES | 500 KB | Lossy 100M path | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES | 200 KB | High loss + high RTT | UcpBenchmarkConstants.cs |
| BENCHMARK_MOBILE_3G_PAYLOAD_BYTES | 300 KB | Mobile 3G path | UcpBenchmarkConstants.cs |
| BENCHMARK_MOBILE_4G_PAYLOAD_BYTES | 300 KB | Mobile 4G path | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_PAYLOAD_BYTES | 300 KB | Weak 4G path | UcpBenchmarkConstants.cs |
| BENCHMARK_SATELLITE_PAYLOAD_BYTES | 300 KB | Satellite path | UcpBenchmarkConstants.cs |
| BENCHMARK_VPN_PAYLOAD_BYTES | 500 KB | VPN tunnel path | UcpBenchmarkConstants.cs |
| BENCHMARK_1G_PAYLOAD_BYTES | 500 KB | 1 Gbps no-loss | UcpBenchmarkConstants.cs |
| BENCHMARK_1G_LOSS_PAYLOAD_BYTES | 500 KB | 1 Gbps with loss | UcpBenchmarkConstants.cs |
| BENCHMARK_10G_PAYLOAD_BYTES | 500 KB | 10 Gbps | UcpBenchmarkConstants.cs |
| BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES | 500 KB | Long fat pipe 100M | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_PAYLOAD_BYTES | 500 KB | Asymmetric route | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES | 500 KB | High jitter path | UcpBenchmarkConstants.cs |
| BENCHMARK_BURST_LOSS_PAYLOAD_BYTES | 500 KB | Burst loss scenario | UcpBenchmarkConstants.cs |

## 14. Benchmark Acceptance Criteria

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT | 70% | No-loss paths | UcpBenchmarkConstants.cs |
| BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT | 45% | Lossy paths | UcpBenchmarkConstants.cs |
| BENCHMARK_MIN_CONVERGED_PACING_RATIO | 0.05 | Lower bound | UcpBenchmarkConstants.cs |
| BENCHMARK_MAX_CONVERGED_PACING_RATIO | 5.0 | Upper bound | UcpBenchmarkConstants.cs |
| BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER | 4.0 | Jitter / propagation delay | UcpBenchmarkConstants.cs |
| BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS | 10 Mbps | Gigabit + 5% loss | UcpBenchmarkConstants.cs |

## 15. Route & Weak-Network Simulation

| Constant | Value | Notes | Defined In |
|---|---|---|---|
| BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS | 25 ms | A->B propagation | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS | 15 ms | B->A propagation | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_JITTER_MILLISECONDS | 8 ms | Asymmetric jitter | UcpBenchmarkConstants.cs |
| BENCHMARK_ASYM_RANDOM_LOSS_RATE | 0.005 (0.5%) | Asymmetric loss | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS | 50 ms | High jitter delay | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS | 25 ms | High jitter range | UcpBenchmarkConstants.cs |
| BENCHMARK_HIGH_JITTER_LOSS_RATE | 0.005 (0.5%) | High jitter loss | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_DELAY_MILLISECONDS | 80 ms | Weak 4G delay | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_LOSS_RATE | 0.05 (5%) | Weak 4G loss | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS | 900 ms | Blackout period | UcpBenchmarkConstants.cs |
| BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS | 80 ms | Blackout duration | UcpBenchmarkConstants.cs |
| BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS | 25 ms | Burst loss delay | UcpBenchmarkConstants.cs |
| BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS | 4 ms | Burst loss jitter | UcpBenchmarkConstants.cs |

## 16. C# vs C++ Implementation Differences

All wire-format constants (packet type codes, header sizes, KCC gains, NAK thresholds, SACK limits, FEC polynomial) are identical between C# and C++ to guarantee interoperability. The following defaults differ due to platform scheduling differences:

| Constant | C# Default | C++ Default | Reason |
|---|---|---|---|
| TIMER_INTERVAL_MILLISECONDS | 1 ms | 1 ms | Same in both (was historically different) |
| MAX_BUFFERED_FAIR_QUEUE_ROUNDS | 4 | 4 | Same in both (was historically different) |
| INITIAL_CWND_PACKETS | 10 | 10 | Same in both (TCP IW10, RFC 6928); docs previously misstated as 20 |

## 18. Linux Kernel Module (KCC) Differences

The kernel module in `linux/tcp_kcc.c` implements KCC v2.0 (Geodesic Congestion Control) and shares the same congestion control design philosophy but uses different values for certain constants due to kernel integration constraints:

| Constant | C#/C++ Lib | Kernel | Notes |
|---|---|---|---|---|
| UCP_DRAIN_PACING_GAIN | 0.344 (88/256) | 0.344 | All implementations use same 0.344 drain pacing gain — UcpCongestionControl drain pacing gain |
| UCP_CWND_GAIN | 2.0 | 2.0 | All implementations use cwnd_gain = 2.0 in PROBE_BW (UCP standard) |
| SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS | 5,000 | Not in kernel | Kernel relies on TCP stack reorder handling |

**CRITICAL**: The kernel's `KCC_HIGH_GAIN` (startup pacing gain) = 739 BBR_UNIT ≈ 2.887x, computed as `BBR_UNIT * 2885 / 1000 + 1` = 739 (equivalent to ceil(2885 × BBR_UNIT / 1000) = 739). All three implementations use 2.887x (739/256) as the effective startup pacing gain.

## Cross-Platform Implementations

This constants reference applies to three UCP implementations:

- **C# (.NET 8)**: Reference implementation. Constants defined in `UcpConstants.cs`, exposed through `UcpConfiguration.cs`.
- **C++ (C++17)**: Native implementation with identical wire-format constants. See `cpp/docs/constants_EN.md`.
- **Linux Kernel Module (KCC)**: Kernel-space implementation following the same constants for wire-format compatibility. Module source: tcp_kcc.c (KCC v2.0 Geodesic Congestion Control). See `linux/README.md`.

---

## License and Trademark

MIT License. See [LICENSE](../LICENSE) for full text.

Copyright (c) 2026 PPP PRIVATE NETWORK™ X

PPP PRIVATE NETWORK™ is a trademark of PPP PRIVATE NETWORK.


