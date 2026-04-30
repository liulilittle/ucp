namespace Ucp
{
    /// <summary>
    /// Central protocol constants kept in one place for future C++ portability.
    /// Time values use microseconds unless the constant name states another unit.
    /// </summary>
    internal static class UcpConstants
    {
        // ---- Time unit conversions ----

        /// <summary>Number of microseconds in one millisecond.</summary>
        public const long MICROS_PER_MILLI = 1000L;

        /// <summary>Number of microseconds in one second.</summary>
        public const long MICROS_PER_SECOND = 1000000L;

        /// <summary>Number of nanoseconds in one microsecond.</summary>
        public const long NANOS_PER_MICRO = 1000L;

        /// <summary>Number of bits in one byte, used for Mbps presentation.</summary>
        public const double BITS_PER_BYTE = 8d;

        /// <summary>Number of bits per second in one megabit per second.</summary>
        public const double BITS_PER_MEGABIT = 1000000d;

        // ---- Packet format constants ----

        /// <summary>Protocol maximum segment size in bytes.</summary>
        public const int MSS = 1220;

        /// <summary>Common packet header size in bytes (Type + Flags + ConnectionId + Timestamp).</summary>
        public const int COMMON_HEADER_SIZE = 12;

        /// <summary>Data packet-specific header size in bytes.</summary>
        public const int DATA_HEADER_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(ushort);

        /// <summary>Fixed ACK packet size in bytes before variable SACK blocks.</summary>
        public const int ACK_FIXED_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(uint) + ACK_TIMESTAMP_FIELD_SIZE;

        /// <summary>Fixed NAK packet size in bytes before variable missing sequence entries.</summary>
        public const int NAK_FIXED_SIZE = COMMON_HEADER_SIZE + sizeof(ushort);

        /// <summary>Maximum data payload size in one packet, in bytes.</summary>
        public const int MAX_PAYLOAD_SIZE = MSS - DATA_HEADER_SIZE;

        /// <summary>Encoded SACK block size in bytes (2 × uint32).</summary>
        public const int SACK_BLOCK_SIZE = sizeof(uint) + sizeof(uint);

        /// <summary>Encoded sequence number size in bytes (uint32).</summary>
        public const int SEQUENCE_NUMBER_SIZE = sizeof(uint);

        /// <summary>Encoded connection identifier size in bytes (uint32).</summary>
        public const int CONNECTION_ID_SIZE = sizeof(uint);

        /// <summary>ACK timestamp field size in bytes (uint48).</summary>
        public const int ACK_TIMESTAMP_FIELD_SIZE = 6;

        /// <summary>Encoded packet type field size in bytes.</summary>
        public const int PACKET_TYPE_FIELD_SIZE = sizeof(byte);

        /// <summary>Encoded packet flags field size in bytes.</summary>
        public const int PACKET_FLAGS_FIELD_SIZE = sizeof(byte);

        // ---- Bit counts for serialization ----

        /// <summary>Bit count in a 16-bit integer.</summary>
        public const int UINT16_BITS = 16;

        /// <summary>Bit count in a 24-bit field.</summary>
        public const int UINT24_BITS = 24;

        /// <summary>Bit count in a 32-bit field.</summary>
        public const int UINT32_BITS = 32;

        /// <summary>Bit count in a 40-bit field.</summary>
        public const int UINT40_BITS = 40;

        /// <summary>Bit count in one byte.</summary>
        public const int BYTE_BITS = 8;

        /// <summary>Mask used to keep only the low 48 bits of an ACK timestamp.</summary>
        public const ulong UINT48_MASK = 0x0000FFFFFFFFFFFFUL;

        // ---- Window and buffer sizes ----

        /// <summary>Default receive window size measured in packets.</summary>
        public const int DEFAULT_RECV_WINDOW_PACKETS = 4096;

        /// <summary>Default receive window size measured in bytes.</summary>
        public const uint DEFAULT_RECV_WINDOW_BYTES = (uint)(DEFAULT_RECV_WINDOW_PACKETS * MSS);

        /// <summary>Initial congestion window packet count used by the optimized default configuration.</summary>
        public const int INITIAL_CWND_PACKETS = 256;

        /// <summary>Legacy initial congestion window in bytes retained for old tests and callers.</summary>
        public const int DEFAULT_INITIAL_CONGESTION_WINDOW = 4 * MSS;

        /// <summary>Default send buffer capacity in bytes.</summary>
        public const int DEFAULT_SEND_BUFFER_BYTES = 32 * 1024 * 1024;

        /// <summary>Default delayed ACK timeout in microseconds.</summary>
        public const long DEFAULT_DELAYED_ACK_TIMEOUT_MICROS = 500L;

        /// <summary>Default maximum tolerated bandwidth waste ratio, where 0.25 means 25%.</summary>
        public const double DEFAULT_MAX_BANDWIDTH_WASTE_RATIO = 0.25d;

        /// <summary>Default maximum tolerated bandwidth loss percentage exposed to users.</summary>
        public const double DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT = 25d;

        /// <summary>Minimum allowed configured bandwidth loss percentage.</summary>
        public const double MIN_MAX_BANDWIDTH_LOSS_PERCENT = 15d;

        /// <summary>Maximum allowed configured bandwidth loss percentage.</summary>
        public const double MAX_MAX_BANDWIDTH_LOSS_PERCENT = 35d;

        /// <summary>Default minimum pacing interval in microseconds.</summary>
        public const long DEFAULT_MIN_PACING_INTERVAL_MICROS = 0L;

        /// <summary>Default pacing token bucket duration in microseconds.</summary>
        public const long DEFAULT_PACING_BUCKET_DURATION_MICROS = 10000L;

        // ---- RTO related constants ----

        /// <summary>Minimum RTO accepted by configuration validation, in microseconds.</summary>
        public const long MIN_RTO_MICROS = 100000L;

        /// <summary>Default optimized minimum RTO, in microseconds.</summary>
        public const long DEFAULT_RTO_MICROS = 200000L;

        /// <summary>Initial RTO used before a measured RTT is available, in microseconds.</summary>
        public const long INITIAL_RTO_MICROS = 250000L;

        /// <summary>Maximum RTO accepted by the optimized default configuration, in microseconds.</summary>
        public const long DEFAULT_MAX_RTO_MICROS = 15000000L;

        /// <summary>Absolute fallback maximum RTO, in microseconds.</summary>
        public const long MAX_RTO_MICROS = 60000000L;

        /// <summary>Default RTO backoff multiplier.</summary>
        public const double RTO_BACKOFF_FACTOR = 1.2d;

        /// <summary>Maximum retransmission attempts per outbound segment.</summary>
        public const int MAX_RETRANSMISSIONS = 10;

        /// <summary>Maximum timeout retransmits armed by one timer tick.</summary>
        public const int RTO_RETRANSMIT_BUDGET_PER_TICK = 4;

        /// <summary>ACK-progress window in which bulk RTO retransmission is suppressed.</summary>
        public const long RTO_ACK_PROGRESS_SUPPRESSION_MICROS = 2 * MICROS_PER_MILLI;

        /// <summary>Maximum urgent retransmits allowed to bypass pacing in one RTT window.</summary>
        public const int URGENT_RETRANSMIT_BUDGET_PER_RTT = 8192;

        /// <summary>Idle-time percentage after which a tail-loss probe may be urgent.</summary>
        public const int URGENT_RETRANSMIT_DISCONNECT_THRESHOLD_PERCENT = 75;

        /// <summary>RTT variance EWMA denominator for RFC6298-style smoothing.</summary>
        public const int RTT_VAR_DENOM = 4;

        /// <summary>RTT sample weight denominator for smoothed RTT EWMA.</summary>
        public const int RTT_SMOOTHING_DENOM = 8;

        /// <summary>Previous smoothed RTT numerator when using a 1/8 sample weight.</summary>
        public const int RTT_SMOOTHING_PREVIOUS_WEIGHT = RTT_SMOOTHING_DENOM - 1;

        /// <summary>Previous RTT variance numerator when using a 1/4 sample weight.</summary>
        public const int RTT_VAR_PREVIOUS_WEIGHT = RTT_VAR_DENOM - 1;

        /// <summary>RTT variance multiplier used when calculating RTO (SRTT + 2*RTTVAR for tighter recovery).</summary>
        public const int RTO_GAIN_MULTIPLIER = 2;

        /// <summary>Maximum accepted RTT sample multiplier relative to the current RTO during recovery.</summary>
        public const double RTT_RECOVERY_SAMPLE_MAX_RTO_MULTIPLIER = 4.0d;

        /// <summary>Maximum backoff multiple relative to the minimum RTO.</summary>
        public const int RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2;

        // ---- BBR congestion control constants ----

        /// <summary>BBR bandwidth filter window length measured in RTT rounds.</summary>
        public const int BBR_WINDOW_RTT_ROUNDS = 10;

        /// <summary>Number of BBR delivery-rate samples retained for bandwidth estimation.</summary>
        public const int BBR_RECENT_RATE_SAMPLE_COUNT = 10;

        /// <summary>BBR ProbeBW cycle length in gain phases.</summary>
        public const int BBR_PROBE_BW_GAIN_COUNT = 8;

        /// <summary>BBR startup requires this many rounds without sufficient bandwidth growth before draining.</summary>
        public const int BBR_MIN_STARTUP_FULL_BANDWIDTH_ROUNDS = 3;

        /// <summary>BBR startup full-bandwidth growth target (25% growth per round).</summary>
        public const double BBR_STARTUP_GROWTH_TARGET = 1.25d;

        /// <summary>BBR startup pacing gain (2.5x).</summary>
        public const double BBR_STARTUP_PACING_GAIN = 3.0d;

        /// <summary>BBR startup congestion window gain (2.0x).</summary>
        public const double BBR_STARTUP_CWND_GAIN = 2.0d;

        /// <summary>BBR drain pacing gain (1.0x, drain the inflated queue).</summary>
        public const double BBR_DRAIN_PACING_GAIN = 1.0d;

        /// <summary>BBR high probing pacing gain (1.35x).</summary>
        public const double BBR_PROBE_BW_HIGH_GAIN = 2.0d;

        /// <summary>BBR low probing pacing gain (0.85x).</summary>
        public const double BBR_PROBE_BW_LOW_GAIN = 0.85d;

        /// <summary>BBR ProbeBW congestion window gain (2.0x).</summary>
        public const double BBR_PROBE_BW_CWND_GAIN = 4.0d;

        /// <summary>BBR ProbeRTT pacing gain used to avoid a full throughput cliff (0.85x).</summary>
        public const double BBR_PROBE_RTT_PACING_GAIN = 0.85d;

        /// <summary>BBR ProbeRTT interval in microseconds (30s).</summary>
        public const long BBR_PROBE_RTT_INTERVAL_MICROS = 30000000L;

        /// <summary>BBR ProbeRTT minimum duration in microseconds.</summary>
        public const long BBR_PROBE_RTT_DURATION_MICROS = 100000L;

        /// <summary>Maximum ProbeRTT duration multiplier used as a safety valve.</summary>
        public const int BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER = 2;

        /// <summary>BBR minimum RTT freshness multiplier used for early ProbeRTT exit (5% margin).</summary>
        public const double BBR_PROBE_RTT_EXIT_RTT_MULTIPLIER = 1.05d;

        /// <summary>BBR RTT increase threshold for unconstrained high-gain probing.</summary>
        public const double BBR_LOW_RTT_INCREASE_RATIO = 0.10d;

        /// <summary>BBR RTT increase threshold for moderate probing.</summary>
        public const double BBR_MODERATE_RTT_INCREASE_RATIO = 0.20d;

        /// <summary>Recent loss ratio below which high-gain probing remains enabled.</summary>
        public const double BBR_LOW_LOSS_RATIO = 0.01d;

        /// <summary>Recent loss ratio below which moderate probing is enabled.</summary>
        public const double BBR_MODERATE_LOSS_RATIO = 0.03d;

        /// <summary>Recent loss ratio below which pacing is kept close to target.</summary>
        public const double BBR_LIGHT_LOSS_RATIO = 0.08d;

        /// <summary>Recent loss ratio below which pacing is gently reduced.</summary>
        public const double BBR_MEDIUM_LOSS_RATIO = 0.15d;

        /// <summary>BBR moderate probing gain used under low loss (1.45x for aggressive mobile probing).</summary>
        public const double BBR_MODERATE_PROBE_GAIN = 1.45d;

        /// <summary>BBR target-maintaining gain under light loss (1.10x).</summary>
        public const double BBR_LIGHT_LOSS_PACING_GAIN = 1.10d;

        /// <summary>BBR gentle pacing gain under medium loss (1.05x).</summary>
        public const double BBR_MEDIUM_LOSS_PACING_GAIN = 1.05d;

        /// <summary>BBR severe loss pacing gain (1.00x = no pacing inflation).</summary>
        public const double BBR_HIGH_LOSS_PACING_GAIN = 1.00d;

        /// <summary>BBR fast recovery pacing gain used after non-congestion loss recovery signals.</summary>
        public const double BBR_FAST_RECOVERY_PACING_GAIN = 1.25d;

        /// <summary>Minimum BBR pacing gain after a congestion loss signal.</summary>
        public const double BBR_MIN_CONGESTION_PACING_GAIN = 0.92d;

        /// <summary>Multiplicative BBR reduction applied on a congestion loss signal (98%).</summary>
        public const double BBR_CONGESTION_LOSS_REDUCTION = 0.98d;

        /// <summary>Minimum congestion window gain retained after congestion loss.</summary>
        public const double BBR_MIN_LOSS_CWND_GAIN = 0.95d;

        /// <summary>Congestion window gain recovery step per ACK.</summary>
        public const double BBR_LOSS_CWND_RECOVERY_STEP = 0.08d;

        /// <summary>Loss budget headroom below which probing may become more aggressive again.</summary>
        public const double BBR_LOSS_BUDGET_RECOVERY_RATIO = 0.80d;

        /// <summary>EWMA sample weight used to smooth exported loss estimates.</summary>
        public const double BBR_LOSS_EWMA_SAMPLE_WEIGHT = 0.25d;

        /// <summary>EWMA retained weight used to smooth exported loss estimates.</summary>
        public const double BBR_LOSS_EWMA_RETAINED_WEIGHT = 1d - BBR_LOSS_EWMA_SAMPLE_WEIGHT;

        /// <summary>EWMA decay applied when no recent loss is observed.</summary>
        public const double BBR_LOSS_EWMA_IDLE_DECAY = 0.90d;

        /// <summary>Delivery-rate drop ratio that contributes to a congestion classification (15% drop).</summary>
        public const double BBR_CONGESTION_RATE_DROP_RATIO = -0.15d;

        /// <summary>RTT increase ceiling below which loss is treated as random rather than queue congestion.</summary>
        public const double BBR_RANDOM_LOSS_MAX_RTT_INCREASE_RATIO = 0.20d;

        /// <summary>Classifier score required before loss-control treats a signal as congestion.</summary>
        public const int BBR_CONGESTION_CLASSIFIER_SCORE_THRESHOLD = 2;

        /// <summary>Classifier score assigned to a meaningful delivery-rate drop.</summary>
        public const int BBR_CONGESTION_RATE_DROP_SCORE = 1;

        /// <summary>Classifier score assigned to sustained RTT growth.</summary>
        public const int BBR_CONGESTION_RTT_GROWTH_SCORE = 1;

        /// <summary>Classifier score assigned to moderate recent loss while RTT is also growing.</summary>
        public const int BBR_CONGESTION_LOSS_SCORE = 1;

        /// <summary>Maximum rate-derived loss contribution beyond measured retransmission loss.</summary>
        public const double BBR_RATE_LOSS_HINT_MAX_RATIO = 0.05d;

        /// <summary>Maximum startup delivery-rate sample multiplier relative to the active pacing rate.</summary>
        public const double BBR_STARTUP_ACK_AGGREGATION_RATE_CAP_GAIN = 4.0d;

        /// <summary>Maximum steady-state delivery-rate sample multiplier relative to the active pacing rate.</summary>
        public const double BBR_STEADY_ACK_AGGREGATION_RATE_CAP_GAIN = 1.50d;

        /// <summary>Maximum bottleneck-bandwidth growth per RTT while in Startup (2.0x).</summary>
        public const double BBR_STARTUP_BANDWIDTH_GROWTH_PER_ROUND = 2.0d;

        /// <summary>Maximum bottleneck-bandwidth growth per RTT after Startup (1.25x).</summary>
        public const double BBR_STEADY_BANDWIDTH_GROWTH_PER_ROUND = 1.25d;

        /// <summary>RTT multiplier above which a loss signal is eligible for congestion classification (1.50x to tolerate jitter).</summary>
        public const double BBR_CONGESTION_LOSS_RTT_MULTIPLIER = 1.50d;

        /// <summary>Deduplicated loss events at or below this count are treated as random in one loss window.</summary>
        public const int BBR_RANDOM_LOSS_MAX_DEDUPED_EVENTS = 2;

        /// <summary>Deduplicated loss events above this count need RTT inflation before congestion response.</summary>
        public const int BBR_CONGESTION_LOSS_WINDOW_THRESHOLD = 3;

        /// <summary>Minimum missing packet count in one loss report before NAK loss is treated as clustered.</summary>
        public const int BBR_CONGESTION_LOSS_BURST_THRESHOLD = 3;

        /// <summary>Fallback bandwidth-growth interval before a valid RTT sample is available.</summary>
        public const long BBR_BANDWIDTH_GROWTH_FALLBACK_INTERVAL_MICROS = 10000L;

        /// <summary>Maximum ratio used for the lower inflight guardrail relative to BDP.</summary>
        public const double BBR_INFLIGHT_LOW_GAIN = 2.00d;

        /// <summary>Maximum ratio used for the upper inflight guardrail relative to BDP.</summary>
        public const double BBR_INFLIGHT_HIGH_GAIN = 4.00d;

        /// <summary>RTT growth required before loss-driven delivery drops are classified as congestion.</summary>
        public const double BBR_CONGESTION_RTT_INCREASE_RATIO = 0.80d;

        /// <summary>Recent loss ratio required before loss-driven delivery drops are classified as congestion.</summary>
        public const double BBR_CONGESTION_LOSS_RATIO = 0.10d;

        /// <summary>Maximum RTT cushion multiplier used by CWND on non-congested lossy paths (8.0x for weak-link throughput).</summary>
        public const double BBR_RANDOM_LOSS_CWND_RTT_CUSHION = 8.0d;

        /// <summary>Delivery-rate sample history length used by the lightweight classifier.</summary>
        public const int BBR_DELIVERY_RATE_HISTORY_COUNT = 5;

        /// <summary>Number of recent RTT samples used to classify jitter.</summary>
        public const int BBR_RTT_HISTORY_COUNT = 5;

        /// <summary>Recent loss accounting bucket duration in microseconds.</summary>
        public const long BBR_LOSS_BUCKET_MICROS = 100000L;

        /// <summary>Number of recent loss accounting buckets.</summary>
        public const int BBR_LOSS_BUCKET_COUNT = 10;

        /// <summary>Minimum round duration in microseconds when no RTT sample is available.</summary>
        public const long BBR_MIN_ROUND_DURATION_MICROS = MICROS_PER_MILLI;

        /// <summary>Fallback BBR bandwidth filter window before a valid minimum RTT is known.</summary>
        public const long BBR_DEFAULT_RATE_WINDOW_MICROS = MICROS_PER_SECOND;

        // ---- Benchmark constants ----

        /// <summary>Benchmark bandwidth for 100 Mbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_100_MBPS_BYTES_PER_SECOND = 100000000 / 8;

        /// <summary>Benchmark bandwidth for 1 Gbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_1_GBPS_BYTES_PER_SECOND = 1000000000 / 8;

        /// <summary>Benchmark bandwidth for 10 Gbps line-rate scenarios, in bytes per second.</summary>
        public const int BENCHMARK_10_GBPS_BYTES_PER_SECOND = 10000000000L / 8 > int.MaxValue ? int.MaxValue : (int)(10000000000L / 8);

        /// <summary>Initial probe bandwidth used by unconstrained benchmark tests, in bytes per second.</summary>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_BYTES_PER_SECOND = 1000000 / 8;

        /// <summary>Relative divisor used to choose a practical initial bandwidth probe for large links.</summary>
        public const int BENCHMARK_INITIAL_PROBE_BANDWIDTH_DIVISOR = 128;

        /// <summary>Path multiplier used to estimate RTT from one-way simulator delay.</summary>
        public const int BENCHMARK_RTT_PATH_MULTIPLIER = 2;

        /// <summary>Initial congestion-window gain relative to estimated BDP for line-rate benchmarks.</summary>
        public const double BENCHMARK_INITIAL_CWND_BDP_GAIN = 1.25d;

        /// <summary>Bandwidth divisor used as the no-loss benchmark initial congestion-window floor.</summary>
        public const int BENCHMARK_NO_LOSS_INITIAL_CWND_BANDWIDTH_DIVISOR = 16;

        /// <summary>Initial congestion-window gain relative to estimated BDP for lossy benchmarks.</summary>
        public const double BENCHMARK_LOSS_INITIAL_CWND_BDP_GAIN = 4.0d;

        /// <summary>Initial congestion-window gain for weak/high-latency network benchmarks (8.0x BDP).</summary>
        public const double BENCHMARK_WEAK_NETWORK_INITIAL_CWND_BDP_GAIN = 8.0d;

        /// <summary>ProbeRTT interval for weak/high-latency network benchmarks (120s) to avoid premature CWND reduction.</summary>
        public const long BENCHMARK_WEAK_NETWORK_PROBE_RTT_INTERVAL_MICROS = 120000000L;

        /// <summary>Serial-time threshold (seconds) above which a benchmark is considered long-running
        /// and the extended ProbeRTT interval is applied.</summary>
        public const double BENCHMARK_LONG_RUNNING_SERIAL_SECONDS = 10d;

        /// <summary>Maximum initial congestion window used by random-loss benchmarks, in bytes.</summary>
        public const int BENCHMARK_MAX_LOSS_INITIAL_CWND_BYTES = 128 * 1024 * 1024;

        /// <summary>Minimum RTO used by long-fat-pipe benchmarks to avoid simulator serialization false positives.</summary>
        public const long BENCHMARK_LONG_FAT_MIN_RTO_MICROS = MICROS_PER_SECOND;

        /// <summary>Deterministic random seed used by light-loss benchmark data drops.</summary>
        public const int BENCHMARK_LIGHT_RANDOM_LOSS_SEED = 20260501;

        /// <summary>Deterministic random seed used by heavy-loss benchmark data drops.</summary>
        public const int BENCHMARK_HEAVY_RANDOM_LOSS_SEED = 20260502;

        /// <summary>RTT used by controller-only auto-probe convergence benchmarks, in microseconds.</summary>
        public const long BENCHMARK_CONTROLLER_CONVERGENCE_RTT_MICROS = 10000L;

        /// <summary>Maximum BBR rounds allowed for controller-only auto-probe convergence benchmarks.</summary>
        public const int BENCHMARK_CONTROLLER_MAX_CONVERGENCE_ROUNDS = 32;

        /// <summary>Payload size used by 100 Mbps benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_100M_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by asymmetric route benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_ASYM_PAYLOAD_BYTES = 8 * 1024 * 1024;

        /// <summary>Payload size used by high-jitter weak-network benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_HIGH_JITTER_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 4G weak-network benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_WEAK_4G_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 100 Mbps random-loss benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_100M_LOSS_PAYLOAD_BYTES = 32 * 1024 * 1024;

        /// <summary>Payload size used by high-loss high-RTT benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_HIGH_LOSS_HIGH_RTT_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by mobile 3G lossy benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_MOBILE_3G_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by mobile 4G high-jitter benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_MOBILE_4G_PAYLOAD_BYTES = 32 * 1024 * 1024;

        /// <summary>Payload size used by satellite benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_SATELLITE_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by VPN benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_VPN_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by the 100 Mbps long-fat-pipe benchmark, in bytes.</summary>
        public const int BENCHMARK_LONG_FAT_100M_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 1 Gbps benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_1G_PAYLOAD_BYTES = 16 * 1024 * 1024;

        /// <summary>Payload size used by 1 Gbps random-loss benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_1G_LOSS_PAYLOAD_BYTES = 64 * 1024 * 1024;

        /// <summary>Jumbo MSS used by high-bandwidth benchmark paths to avoid control-plane packet amplification.</summary>
        public const int BENCHMARK_HIGH_BANDWIDTH_MSS = 9000;

        /// <summary>Payload size used by 10 Gbps benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_10G_PAYLOAD_BYTES = 32 * 1024 * 1024;

        /// <summary>Payload size used by burst-loss recovery benchmark scenarios, in bytes.</summary>
        public const int BENCHMARK_BURST_LOSS_PAYLOAD_BYTES = 2 * 1024 * 1024;

        /// <summary>Default benchmark read timeout in milliseconds.</summary>
        public const int BENCHMARK_READ_TIMEOUT_MILLISECONDS = 180000;

        /// <summary>Default ACK settlement timeout in milliseconds.</summary>
        public const int BENCHMARK_ACK_SETTLEMENT_TIMEOUT_MILLISECONDS = 1000;

        /// <summary>First logical port used by dynamically allocated benchmark tests.</summary>
        public const int BENCHMARK_BASE_PORT = 40100;

        /// <summary>Port offset for the 1 Gbps ideal benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_IDEAL = 0;

        /// <summary>Port offset for the 1 Gbps heavy-loss benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS5 = 1;

        /// <summary>Port offset for the 1 Gbps light-loss benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_GIGABIT_LOSS1 = 2;

        /// <summary>Port offset for the 100 Mbps long-fat-pipe benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_LONG_FAT_100M = 3;

        /// <summary>Port offset for the 10 Gbps benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_10G = 4;

        /// <summary>Port offset for the burst-loss benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_BURST_LOSS = 5;

        /// <summary>Port offset for the asymmetric route benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_ASYM_ROUTE = 6;

        /// <summary>Port offset for the high-jitter benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_HIGH_JITTER = 7;

        /// <summary>Port offset for the weak 4G benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_WEAK_4G = 8;

        /// <summary>Fixed one-way delay for the 100 Mbps benchmark, in milliseconds.</summary>
        public const int BENCHMARK_100M_DELAY_MILLISECONDS = 5;

        /// <summary>Fixed one-way delay for the 1 Gbps ideal benchmark, in milliseconds.</summary>
        public const int BENCHMARK_1G_IDEAL_DELAY_MILLISECONDS = 1;

        /// <summary>Fixed one-way delay for the 1 Gbps light-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_1G_LIGHT_LOSS_DELAY_MILLISECONDS = 20;

        /// <summary>Jitter for the 1 Gbps light-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_1G_LIGHT_LOSS_JITTER_MILLISECONDS = 3;

        /// <summary>Fixed one-way delay for the 1 Gbps heavy-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_1G_HEAVY_LOSS_DELAY_MILLISECONDS = 30;

        /// <summary>Jitter for the 1 Gbps heavy-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_1G_HEAVY_LOSS_JITTER_MILLISECONDS = 5;

        /// <summary>Fixed one-way delay for the 100 Mbps long-fat-pipe benchmark, in milliseconds.</summary>
        public const int BENCHMARK_LONG_FAT_DELAY_MILLISECONDS = 50;

        /// <summary>Jitter for the 100 Mbps long-fat-pipe benchmark, in milliseconds.</summary>
        public const int BENCHMARK_LONG_FAT_JITTER_MILLISECONDS = 2;

        /// <summary>Fixed one-way delay for the 10 Gbps probe benchmark, in milliseconds.</summary>
        public const int BENCHMARK_10G_DELAY_MILLISECONDS = 1;

        /// <summary>Fixed one-way delay for the burst-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_BURST_LOSS_DELAY_MILLISECONDS = 25;

        /// <summary>Jitter for the burst-loss benchmark, in milliseconds.</summary>
        public const int BENCHMARK_BURST_LOSS_JITTER_MILLISECONDS = 4;

        /// <summary>Forward one-way delay for the asymmetric route benchmark, in milliseconds.</summary>
        public const int BENCHMARK_ASYM_FORWARD_DELAY_MILLISECONDS = 25;

        /// <summary>Backward one-way delay for the asymmetric route benchmark, in milliseconds.</summary>
        public const int BENCHMARK_ASYM_BACKWARD_DELAY_MILLISECONDS = 15;

        /// <summary>Per-direction jitter for the asymmetric route benchmark, in milliseconds.</summary>
        public const int BENCHMARK_ASYM_JITTER_MILLISECONDS = 8;

        /// <summary>Random data loss rate used by the asymmetric route benchmark.</summary>
        public const double BENCHMARK_ASYM_RANDOM_LOSS_RATE = 0.005d;

        /// <summary>Random data loss rate used by the high-jitter benchmark.</summary>
        public const double BENCHMARK_HIGH_JITTER_LOSS_RATE = 0.005d;

        /// <summary>Random data loss rate used by the weak 4G benchmark.</summary>
        public const double BENCHMARK_WEAK_4G_LOSS_RATE = 0.05d;

        /// <summary>Deterministic random seed used by asymmetric route benchmark data drops.</summary>
        public const int BENCHMARK_ASYM_RANDOM_LOSS_SEED = 20260503;

        /// <summary>Deterministic random seed used by high-jitter benchmark data drops.</summary>
        public const int BENCHMARK_HIGH_JITTER_LOSS_SEED = 20260504;

        /// <summary>Deterministic random seed used by weak 4G benchmark data drops.</summary>
        public const int BENCHMARK_WEAK_4G_LOSS_SEED = 20260505;

        /// <summary>Fixed one-way delay for high-jitter benchmark scenarios, in milliseconds.</summary>
        public const int BENCHMARK_HIGH_JITTER_DELAY_MILLISECONDS = 50;

        /// <summary>Per-direction jitter for high-jitter benchmark scenarios, in milliseconds.</summary>
        public const int BENCHMARK_HIGH_JITTER_JITTER_MILLISECONDS = 25;

        /// <summary>Fixed one-way delay for weak 4G benchmark scenarios, in milliseconds.</summary>
        public const int BENCHMARK_WEAK_4G_DELAY_MILLISECONDS = 80;

        /// <summary>Weak 4G outage period, in milliseconds.</summary>
        public const int BENCHMARK_WEAK_4G_OUTAGE_PERIOD_MILLISECONDS = 900;

        /// <summary>Weak 4G outage duration, in milliseconds.</summary>
        public const int BENCHMARK_WEAK_4G_OUTAGE_DURATION_MILLISECONDS = 80;

        // ---- Network classifier constants ----

        /// <summary>Number of recent statistics windows retained for network classification.</summary>
        public const int NETWORK_CLASSIFIER_WINDOW_COUNT = 8;

        /// <summary>Duration of each classification statistics window, in microseconds.</summary>
        public const long NETWORK_CLASSIFIER_WINDOW_DURATION_MICROS = 200000L;

        /// <summary>RTT threshold (ms) for classifying long-fat networks.</summary>
        public const double NETWORK_CLASSIFIER_LONG_FAT_RTT_MS = 80d;

        /// <summary>Loss threshold for classifying mobile/unstable networks.</summary>
        public const double NETWORK_CLASSIFIER_MOBILE_LOSS_RATE = 0.03d;

        /// <summary>Jitter threshold (ms) for classifying mobile/unstable networks.</summary>
        public const double NETWORK_CLASSIFIER_MOBILE_JITTER_MS = 20d;

        /// <summary>RTT threshold (ms) for classifying low-latency LAN.</summary>
        public const double NETWORK_CLASSIFIER_LAN_RTT_MS = 5d;

        /// <summary>Jitter threshold (ms) for classifying low-latency LAN.</summary>
        public const double NETWORK_CLASSIFIER_LAN_JITTER_MS = 3d;

        /// <summary>Light random data loss rate used by benchmark scenarios.</summary>
        public const double BENCHMARK_LIGHT_RANDOM_LOSS_RATE = 0.01d;

        /// <summary>Heavy random data loss rate used by benchmark scenarios.</summary>
        public const double BENCHMARK_HEAVY_RANDOM_LOSS_RATE = 0.05d;

        /// <summary>Very heavy random data loss rate (>=10%) used by benchmark scenarios.</summary>
        public const double BENCHMARK_VERY_HEAVY_RANDOM_LOSS_RATE = 0.10d;

        /// <summary>FEC redundancy ratio for very heavy loss (>=10%) benchmark scenarios.</summary>
        public const double BENCHMARK_VERY_HEAVY_LOSS_FEC_REDUNDANCY = 0.50d;

        /// <summary>Medium random loss rate (>=3%) threshold for increased FEC redundancy.</summary>
        public const double BENCHMARK_MEDIUM_RANDOM_LOSS_RATE = 0.03d;

        /// <summary>FEC redundancy ratio for medium loss (3-10%) benchmark scenarios.</summary>
        public const double BENCHMARK_MEDIUM_LOSS_FEC_REDUNDANCY = 0.50d;

        /// <summary>RTT threshold above which heavy FEC (0.50) is always used for lossy benchmarks.</summary>
        public const long BENCHMARK_HIGH_RTT_FEC_THRESHOLD_MICROS = 80000L;

        /// <summary>First data packet index included in the burst-loss benchmark.</summary>
        public const int BENCHMARK_BURST_LOSS_FIRST_PACKET = 16;

        /// <summary>Number of consecutive data packets dropped in the burst-loss benchmark.</summary>
        public const int BENCHMARK_BURST_LOSS_PACKET_COUNT = 8;

        /// <summary>Minimum line-rate utilization target for no-loss benchmark scenarios.</summary>
        public const double BENCHMARK_MIN_NO_LOSS_UTILIZATION_PERCENT = 70d;

        /// <summary>Minimum line-rate utilization target for controlled-loss benchmark scenarios.</summary>
        public const double BENCHMARK_MIN_LOSS_UTILIZATION_PERCENT = 45d;

        /// <summary>Minimum throughput target for the 5% random-loss 1 Gbps benchmark, in Mbps.</summary>
        public const double BENCHMARK_MIN_GIGABIT_LOSS5_THROUGHPUT_MBPS = 145d;

        /// <summary>Maximum acceptable RTT jitter multiplier relative to the configured one-way delay.</summary>
        public const double BENCHMARK_MAX_JITTER_DELAY_MULTIPLIER = 4d;

        /// <summary>Minimum pacing ratio accepted after auto-probing converges.</summary>
        public const double BENCHMARK_MIN_CONVERGED_PACING_RATIO = 0.70d;

        /// <summary>Maximum pacing ratio accepted after auto-probing converges (1000× for aggressive mode).</summary>
        public const double BENCHMARK_MAX_CONVERGED_PACING_RATIO = 1000.0d;

        // ---- Port offsets for additional benchmarks ----

        /// <summary>Port offset for the mobile 3G benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_MOBILE_3G = 14;

        /// <summary>Port offset for the mobile 4G high-jitter benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_MOBILE_4G = 15;

        /// <summary>Port offset for the satellite benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_SATELLITE = 16;

        /// <summary>Port offset for the VPN dual-congestion benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_VPN = 17;

        /// <summary>Port offset for the datacenter benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_DATACENTER = 18;

        /// <summary>Port offset for the enterprise benchmark.</summary>
        public const int BENCHMARK_PORT_OFFSET_ENTERPRISE = 19;

        // ---- Loss detection / retransmission constants ----

        /// <summary>Maximum number of NAK packets emitted during one RTT interval.</summary>
        public const int MAX_NAKS_PER_RTT = 1024;

        /// <summary>Threshold in payload-sized segments below which early retransmit is allowed.</summary>
        public const int EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS = 4;

        /// <summary>Tail-loss probe threshold in payload-sized segments.</summary>
        public const int TLP_MAX_INFLIGHT_SEGMENTS = 2;

        /// <summary>Tail-loss probe timer ratio relative to the smoothed RTT.</summary>
        public const double TLP_TIMEOUT_RTT_RATIO = 1.5d;

        /// <summary>Number of congestion loss events needed before entering ProbeRTT.</summary>
        public const int BBR_PROBE_RTT_CONGESTION_LOSS_THRESHOLD = 5;

        /// <summary>Duplicate ACK count needed to trigger fast retransmit.</summary>
        public const int DUPLICATE_ACK_THRESHOLD = 2;

        /// <summary>SACK observations needed before a missing hole is retransmitted without waiting for RTO.</summary>
        public const int SACK_FAST_RETRANSMIT_THRESHOLD = 2;

        /// <summary>Minimum SACK distance past a missing sequence before treating the hole as real loss.</summary>
        public const int SACK_FAST_RETRANSMIT_DISTANCE_THRESHOLD = 32;

        /// <summary>Lower bound for SACK-based reorder grace before fast retransmit, in microseconds.</summary>
        public const long SACK_FAST_RETRANSMIT_MIN_REORDER_GRACE_MICROS = 3000L;

        /// <summary>Missing observation count needed before the receiver sends a NAK.</summary>
        public const int NAK_MISSING_THRESHOLD = 2;

        /// <summary>Minimum packet-age delay before receiver NAKs a missing sequence, in microseconds.</summary>
        public const long NAK_REORDER_GRACE_MICROS = 5000L;

        /// <summary>Missing observation count that makes a gap high-confidence despite reorder grace.</summary>
        public const int NAK_HIGH_CONFIDENCE_MISSING_THRESHOLD = 256;

        /// <summary>Minimum packet-age delay for high-confidence missing gaps, in microseconds.</summary>
        public const long NAK_HIGH_CONFIDENCE_REORDER_GRACE_MICROS = 2000L;

        /// <summary>Missing observation count that makes a gap more likely to be real loss than jitter.</summary>
        public const int NAK_MEDIUM_CONFIDENCE_MISSING_THRESHOLD = 64;

        /// <summary>Minimum packet-age delay for medium-confidence missing gaps, in microseconds.</summary>
        public const long NAK_MEDIUM_CONFIDENCE_REORDER_GRACE_MICROS = 2000L;

        /// <summary>Minimum interval before the receiver may re-emit a NAK for the same missing sequence.</summary>
        public const long NAK_REPEAT_INTERVAL_MICROS = 20000L;

        /// <summary>Maximum number of sequence slots scanned while building NAK state.</summary>
        public const int MAX_NAK_MISSING_SCAN = 16384;

        /// <summary>Maximum missing sequences included in one NAK packet.</summary>
        public const int MAX_NAK_SEQUENCES_PER_PACKET = 256;

        /// <summary>Maximum SACK blocks emitted by default.</summary>
        public const int DEFAULT_ACK_SACK_BLOCK_LIMIT = 149;

        /// <summary>Receive-buffer occupancy that forces an immediate ACK, measured in packets.</summary>
        public const int IMMEDIATE_ACK_REORDERED_PACKET_THRESHOLD = 4;

        /// <summary>Minimum spacing between immediate reordered-data ACKs, in microseconds.</summary>
        public const long REORDERED_ACK_MIN_INTERVAL_MICROS = 250L;

        /// <summary>Default keep-alive interval in microseconds (1 second).</summary>
        public const long KEEP_ALIVE_INTERVAL_MICROS = MICROS_PER_SECOND;

        /// <summary>Default disconnect timeout in microseconds (4 seconds).</summary>
        public const long DISCONNECT_TIMEOUT_MICROS = 4000000L;

        /// <summary>Default timer interval in milliseconds.</summary>
        public const int TIMER_INTERVAL_MILLISECONDS = 1;

        /// <summary>Fair queue scheduling round in milliseconds.</summary>
        public const int FAIR_QUEUE_ROUND_MILLISECONDS = 10;

        /// <summary>Default server bandwidth in bytes per second (~100 Mbps).</summary>
        public const int DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND = 100000000 / 8;

        /// <summary>Default initial bandwidth estimate in bytes per second.</summary>
        public const int DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Default maximum pacing rate in bytes per second.</summary>
        public const int DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Maximum congestion window in bytes (64 MB).</summary>
        public const int DEFAULT_MAX_CONGESTION_WINDOW_BYTES = 64 * 1024 * 1024;

        /// <summary>Default connect timeout in milliseconds.</summary>
        public const int CONNECT_TIMEOUT_MILLISECONDS = 5000;

        /// <summary>Maximum RTT samples retained in diagnostics.</summary>
        public const int MAX_RTT_SAMPLES = 1024;

        /// <summary>Maximum fair-queue credit retained across rounds.</summary>
        public const int MAX_BUFFERED_FAIR_QUEUE_ROUNDS = 2;

        /// <summary>Minimum sleep interval used by timers and waits in milliseconds.</summary>
        public const int MIN_TIMER_WAIT_MILLISECONDS = 1;

        /// <summary>Handshake retry lower bound in milliseconds.</summary>
        public const int MIN_HANDSHAKE_WAIT_MILLISECONDS = 100;

        /// <summary>Close wait timeout in milliseconds.</summary>
        public const int CLOSE_WAIT_TIMEOUT_MILLISECONDS = 1000;

        /// <summary>Fallback pacing wait in microseconds when no pacing rate is available.</summary>
        public const long DEFAULT_PACING_WAIT_MICROS = MICROS_PER_MILLI;

        /// <summary>Logical simulator base port used by tests.</summary>
        public const int SIMULATOR_BASE_PORT = 30000;

        /// <summary>Encoded UCP data packet type value used by the test simulator.</summary>
        public const byte UCP_DATA_TYPE_VALUE = 0x05;

        /// <summary>Encoded UCP SYN packet type value.</summary>
        public const byte UCP_SYN_TYPE_VALUE = 0x01;

        /// <summary>Encoded UCP SYN-ACK packet type value.</summary>
        public const byte UCP_SYN_ACK_TYPE_VALUE = 0x02;

        /// <summary>Encoded UCP ACK packet type value.</summary>
        public const byte UCP_ACK_TYPE_VALUE = 0x03;

        /// <summary>Encoded UCP NAK packet type value.</summary>
        public const byte UCP_NAK_TYPE_VALUE = 0x04;

        /// <summary>Encoded UCP FIN packet type value.</summary>
        public const byte UCP_FIN_TYPE_VALUE = 0x06;

        /// <summary>Encoded UCP FEC repair packet type value.</summary>
        public const byte UCP_FEC_REPAIR_TYPE_VALUE = 0x08;

        /// <summary>Encoded UCP RST packet type value.</summary>
        public const byte UCP_RST_TYPE_VALUE = 0x07;

        /// <summary>Encoded empty flags value.</summary>
        public const byte UCP_FLAGS_NONE_VALUE = 0x00;

        /// <summary>Encoded NeedAck packet flag value.</summary>
        public const byte UCP_FLAG_NEED_ACK_VALUE = 0x01;

        /// <summary>Encoded Retransmit packet flag value.</summary>
        public const byte UCP_FLAG_RETRANSMIT_VALUE = 0x02;

        /// <summary>Encoded FinAck packet flag value.</summary>
        public const byte UCP_FLAG_FIN_ACK_VALUE = 0x04;

        // ---- Computed constants ----

        /// <summary>Maximum ACK SACK blocks that fit inside one MSS-sized ACK packet.</summary>
        public static readonly int MAX_ACK_SACK_BLOCKS = (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE;

        // ---- PascalCase public aliases for external consumers ----

        public const int Mss = MSS;
        public const int CommonHeaderSize = COMMON_HEADER_SIZE;
        public const int DataHeaderSize = DATA_HEADER_SIZE;
        public const int AckFixedSize = ACK_FIXED_SIZE;
        public const int NakFixedSize = NAK_FIXED_SIZE;
        public const int MaxPayloadSize = MAX_PAYLOAD_SIZE;
        public const int DefaultReceiveWindowPackets = DEFAULT_RECV_WINDOW_PACKETS;
        public const uint DefaultReceiveWindowBytes = DEFAULT_RECV_WINDOW_BYTES;
        public const int DefaultInitialCongestionWindow = DEFAULT_INITIAL_CONGESTION_WINDOW;
        public const int DefaultInitialBandwidthBytesPerSecond = DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND;
        public const long MinRtoMicros = MIN_RTO_MICROS;
        public const long MaxRtoMicros = MAX_RTO_MICROS;
        public const long ProbeRttIntervalMicros = BBR_PROBE_RTT_INTERVAL_MICROS;
        public const long ProbeRttDurationMicros = BBR_PROBE_RTT_DURATION_MICROS;
        public const long KeepAliveIntervalMicros = KEEP_ALIVE_INTERVAL_MICROS;
        public const long DisconnectTimeoutMicros = DISCONNECT_TIMEOUT_MICROS;
        public const long TimerIntervalMilliseconds = TIMER_INTERVAL_MILLISECONDS;
        public const int FairQueueRoundMilliseconds = FAIR_QUEUE_ROUND_MILLISECONDS;
        public const int DefaultServerBandwidthBytesPerSecond = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;
        public const int ConnectTimeoutMilliseconds = CONNECT_TIMEOUT_MILLISECONDS;
        public const int MaxRttSamples = MAX_RTT_SAMPLES;
        public const int BbrProbeBwGainCount = BBR_PROBE_BW_GAIN_COUNT;
        public const int MinBbrStartupFullBandwidthRounds = BBR_MIN_STARTUP_FULL_BANDWIDTH_ROUNDS;
        public const double BbrStartupGrowthTarget = BBR_STARTUP_GROWTH_TARGET;
        public const int MaxBufferedFairQueueRounds = MAX_BUFFERED_FAIR_QUEUE_ROUNDS;

        public static readonly int MaxAckSackBlocks = MAX_ACK_SACK_BLOCKS;
    }
}
