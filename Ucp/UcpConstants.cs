namespace Ucp
{
    /// <summary>
    /// Central protocol constants kept in one place for future C++ portability.
    /// Time values use microseconds unless the constant name states another unit.
    /// </summary>
    internal static class UcpConstants
    {
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

        /// <summary>Protocol maximum segment size in bytes.</summary>
        public const int MSS = 1220;

        /// <summary>Common packet header size in bytes.</summary>
        public const int COMMON_HEADER_SIZE = 12;

        /// <summary>Data packet-specific header size in bytes.</summary>
        public const int DATA_HEADER_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(ushort);

        /// <summary>Fixed ACK packet size in bytes before variable SACK blocks.</summary>
        public const int ACK_FIXED_SIZE = COMMON_HEADER_SIZE + sizeof(uint) + sizeof(ushort) + sizeof(uint) + ACK_TIMESTAMP_FIELD_SIZE;

        /// <summary>Fixed NAK packet size in bytes before variable missing sequence entries.</summary>
        public const int NAK_FIXED_SIZE = COMMON_HEADER_SIZE + sizeof(ushort);

        /// <summary>Maximum data payload size in one packet, in bytes.</summary>
        public const int MAX_PAYLOAD_SIZE = MSS - DATA_HEADER_SIZE;

        /// <summary>Encoded SACK block size in bytes.</summary>
        public const int SACK_BLOCK_SIZE = sizeof(uint) + sizeof(uint);

        /// <summary>Encoded sequence number size in bytes.</summary>
        public const int SEQUENCE_NUMBER_SIZE = sizeof(uint);

        /// <summary>Encoded connection identifier size in bytes.</summary>
        public const int CONNECTION_ID_SIZE = sizeof(uint);

        /// <summary>ACK timestamp field size in bytes.</summary>
        public const int ACK_TIMESTAMP_FIELD_SIZE = 6;

        /// <summary>Encoded packet type field size in bytes.</summary>
        public const int PACKET_TYPE_FIELD_SIZE = sizeof(byte);

        /// <summary>Encoded packet flags field size in bytes.</summary>
        public const int PACKET_FLAGS_FIELD_SIZE = sizeof(byte);

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

        /// <summary>Default receive window size measured in packets.</summary>
        public const int DEFAULT_RECV_WINDOW_PACKETS = 4096;

        /// <summary>Default receive window size measured in bytes.</summary>
        public const uint DEFAULT_RECV_WINDOW_BYTES = (uint)(DEFAULT_RECV_WINDOW_PACKETS * MSS);

        /// <summary>Initial congestion window packet count used by the optimized default configuration.</summary>
        public const int INITIAL_CWND_PACKETS = 20;

        /// <summary>Legacy initial congestion window in bytes retained for old tests and callers.</summary>
        public const int DEFAULT_INITIAL_CONGESTION_WINDOW = 4 * MSS;

        /// <summary>Default send buffer capacity in bytes.</summary>
        public const int DEFAULT_SEND_BUFFER_BYTES = 32 * 1024 * 1024;

        /// <summary>Default delayed ACK timeout in microseconds.</summary>
        public const long DEFAULT_DELAYED_ACK_TIMEOUT_MICROS = 2000L;

        /// <summary>Default maximum tolerated bandwidth waste ratio, where 0.25 means 25%.</summary>
        public const double DEFAULT_MAX_BANDWIDTH_WASTE_RATIO = 0.25d;

        /// <summary>Default maximum tolerated bandwidth loss percentage exposed to users.</summary>
        public const double DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT = 25d;

        /// <summary>Minimum allowed configured bandwidth loss percentage.</summary>
        public const double MIN_MAX_BANDWIDTH_LOSS_PERCENT = 15d;

        /// <summary>Maximum allowed configured bandwidth loss percentage.</summary>
        public const double MAX_MAX_BANDWIDTH_LOSS_PERCENT = 35d;

        /// <summary>Default minimum pacing interval in microseconds.</summary>
        public const long DEFAULT_MIN_PACING_INTERVAL_MICROS = MICROS_PER_MILLI;

        /// <summary>Default pacing token bucket duration in microseconds.</summary>
        public const long DEFAULT_PACING_BUCKET_DURATION_MICROS = MICROS_PER_SECOND;

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

        /// <summary>RTT variance EWMA denominator for RFC6298-style smoothing.</summary>
        public const int RTT_VAR_DENOM = 4;

        /// <summary>RTT sample weight denominator for smoothed RTT EWMA.</summary>
        public const int RTT_SMOOTHING_DENOM = 8;

        /// <summary>Previous smoothed RTT numerator when using a 1/8 sample weight.</summary>
        public const int RTT_SMOOTHING_PREVIOUS_WEIGHT = RTT_SMOOTHING_DENOM - 1;

        /// <summary>Previous RTT variance numerator when using a 1/4 sample weight.</summary>
        public const int RTT_VAR_PREVIOUS_WEIGHT = RTT_VAR_DENOM - 1;

        /// <summary>RTT variance multiplier used when calculating RTO.</summary>
        public const int RTO_GAIN_MULTIPLIER = 4;

        /// <summary>Maximum backoff multiple relative to the minimum RTO.</summary>
        public const int RTO_MAX_BACKOFF_MIN_RTO_MULTIPLIER = 2;

        /// <summary>BBR bandwidth filter window length measured in RTT rounds.</summary>
        public const int BBR_WINDOW_RTT_ROUNDS = 10;

        /// <summary>Number of BBR delivery-rate samples retained for bandwidth estimation.</summary>
        public const int BBR_RECENT_RATE_SAMPLE_COUNT = 10;

        /// <summary>BBR ProbeBW cycle length in gain phases.</summary>
        public const int BBR_PROBE_BW_GAIN_COUNT = 8;

        /// <summary>BBR startup requires this many rounds without sufficient bandwidth growth before draining.</summary>
        public const int BBR_MIN_STARTUP_FULL_BANDWIDTH_ROUNDS = 3;

        /// <summary>BBR startup full-bandwidth growth target.</summary>
        public const double BBR_STARTUP_GROWTH_TARGET = 1.25d;

        /// <summary>BBR startup pacing gain.</summary>
        public const double BBR_STARTUP_PACING_GAIN = 2.0d;

        /// <summary>BBR startup congestion window gain.</summary>
        public const double BBR_STARTUP_CWND_GAIN = 2.0d;

        /// <summary>BBR drain pacing gain.</summary>
        public const double BBR_DRAIN_PACING_GAIN = 0.75d;

        /// <summary>BBR high probing pacing gain.</summary>
        public const double BBR_PROBE_BW_HIGH_GAIN = 1.25d;

        /// <summary>BBR low probing pacing gain.</summary>
        public const double BBR_PROBE_BW_LOW_GAIN = 0.85d;

        /// <summary>BBR ProbeBW congestion window gain.</summary>
        public const double BBR_PROBE_BW_CWND_GAIN = 2.0d;

        /// <summary>BBR ProbeRTT pacing gain used to avoid a full throughput cliff.</summary>
        public const double BBR_PROBE_RTT_PACING_GAIN = 0.85d;

        /// <summary>BBR ProbeRTT interval in microseconds.</summary>
        public const long BBR_PROBE_RTT_INTERVAL_MICROS = 30000000L;

        /// <summary>BBR ProbeRTT minimum duration in microseconds.</summary>
        public const long BBR_PROBE_RTT_DURATION_MICROS = 100000L;

        /// <summary>Maximum ProbeRTT duration multiplier used as a safety valve.</summary>
        public const int BBR_PROBE_RTT_MAX_DURATION_MULTIPLIER = 2;

        /// <summary>BBR minimum RTT freshness multiplier used for early ProbeRTT exit.</summary>
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

        /// <summary>BBR moderate probing gain used under low loss.</summary>
        public const double BBR_MODERATE_PROBE_GAIN = 1.10d;

        /// <summary>BBR target-maintaining gain under light loss.</summary>
        public const double BBR_LIGHT_LOSS_PACING_GAIN = 1.02d;

        /// <summary>BBR gentle pacing gain under medium loss.</summary>
        public const double BBR_MEDIUM_LOSS_PACING_GAIN = 0.98d;

        /// <summary>BBR severe loss pacing gain.</summary>
        public const double BBR_HIGH_LOSS_PACING_GAIN = 0.95d;

        /// <summary>BBR fast recovery pacing gain used after non-congestion loss recovery signals.</summary>
        public const double BBR_FAST_RECOVERY_PACING_GAIN = 0.80d;

        /// <summary>Minimum BBR pacing gain after a congestion loss signal.</summary>
        public const double BBR_MIN_CONGESTION_PACING_GAIN = 0.92d;

        /// <summary>Multiplicative BBR reduction applied on a congestion loss signal.</summary>
        public const double BBR_CONGESTION_LOSS_REDUCTION = 0.95d;

        /// <summary>Minimum congestion window gain retained after congestion loss.</summary>
        public const double BBR_MIN_LOSS_CWND_GAIN = 0.85d;

        /// <summary>Congestion window gain recovery step per ACK.</summary>
        public const double BBR_LOSS_CWND_RECOVERY_STEP = 0.01d;

        /// <summary>Loss budget headroom below which probing may become more aggressive again.</summary>
        public const double BBR_LOSS_BUDGET_RECOVERY_RATIO = 0.80d;

        /// <summary>Maximum ratio used for the lower inflight guardrail relative to BDP.</summary>
        public const double BBR_INFLIGHT_LOW_GAIN = 0.90d;

        /// <summary>Maximum ratio used for the upper inflight guardrail relative to BDP.</summary>
        public const double BBR_INFLIGHT_HIGH_GAIN = 1.25d;

        /// <summary>Delivery-rate sample history length used by the lightweight classifier.</summary>
        public const int BBR_DELIVERY_RATE_HISTORY_COUNT = 5;

        /// <summary>Number of recent RTT samples used to classify jitter.</summary>
        public const int BBR_RTT_HISTORY_COUNT = 5;

        /// <summary>Maximum number of NAK packets emitted during one RTT interval.</summary>
        public const int MAX_NAKS_PER_RTT = 3;

        /// <summary>Threshold in payload-sized segments below which early retransmit is allowed.</summary>
        public const int EARLY_RETRANSMIT_MAX_INFLIGHT_SEGMENTS = 4;

        /// <summary>Tail-loss probe threshold in payload-sized segments.</summary>
        public const int TLP_MAX_INFLIGHT_SEGMENTS = 2;

        /// <summary>Tail-loss probe timer ratio relative to the smoothed RTT.</summary>
        public const double TLP_TIMEOUT_RTT_RATIO = 1.5d;

        /// <summary>Number of congestion loss events needed before entering ProbeRTT.</summary>
        public const int BBR_PROBE_RTT_CONGESTION_LOSS_THRESHOLD = 3;

        /// <summary>Recent loss accounting bucket duration in microseconds.</summary>
        public const long BBR_LOSS_BUCKET_MICROS = 100000L;

        /// <summary>Number of recent loss accounting buckets.</summary>
        public const int BBR_LOSS_BUCKET_COUNT = 10;

        /// <summary>Minimum round duration in microseconds when no RTT sample is available.</summary>
        public const long BBR_MIN_ROUND_DURATION_MICROS = MICROS_PER_MILLI;

        /// <summary>Fallback BBR bandwidth filter window before a valid minimum RTT is known.</summary>
        public const long BBR_DEFAULT_RATE_WINDOW_MICROS = MICROS_PER_SECOND;

        /// <summary>Duplicate ACK count needed to trigger fast retransmit.</summary>
        public const int DUPLICATE_ACK_THRESHOLD = 3;

        /// <summary>Missing observation count needed before the receiver sends a NAK.</summary>
        public const int NAK_MISSING_THRESHOLD = 3;

        /// <summary>Maximum number of sequence slots scanned while building NAK state.</summary>
        public const int MAX_NAK_MISSING_SCAN = 32;

        /// <summary>Maximum SACK blocks emitted by default.</summary>
        public const int DEFAULT_ACK_SACK_BLOCK_LIMIT = 10;

        /// <summary>Default keep-alive interval in microseconds.</summary>
        public const long KEEP_ALIVE_INTERVAL_MICROS = MICROS_PER_SECOND;

        /// <summary>Default disconnect timeout in microseconds.</summary>
        public const long DISCONNECT_TIMEOUT_MICROS = 4000000L;

        /// <summary>Default timer interval in milliseconds.</summary>
        public const int TIMER_INTERVAL_MILLISECONDS = 20;

        /// <summary>Fair queue scheduling round in milliseconds.</summary>
        public const int FAIR_QUEUE_ROUND_MILLISECONDS = 10;

        /// <summary>Default server bandwidth in bytes per second.</summary>
        public const int DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND = 100000000 / 8;

        /// <summary>Default initial bandwidth estimate in bytes per second.</summary>
        public const int DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Default maximum pacing rate in bytes per second.</summary>
        public const int DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND = DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Maximum congestion window in bytes.</summary>
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

        /// <summary>Maximum ACK SACK blocks that fit inside one MSS-sized ACK packet.</summary>
        public static readonly int MAX_ACK_SACK_BLOCKS = (MSS - ACK_FIXED_SIZE) / SACK_BLOCK_SIZE;

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
