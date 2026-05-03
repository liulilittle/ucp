using System; // Required for Math, ArgumentNullException, and framework types used in this file

namespace Ucp // UCP library root namespace — contains all protocol types, constants, and configuration
{
    /// <summary>
    /// Runtime configuration for UCP connections and servers.
    /// Controls all protocol behavior: MSS, retransmission limits, RTO bounds,
    /// BBR congestion control gains, pacing token-bucket parameters, FEC redundancy,
    /// loss-control budget, fair-queue scheduling, and keepalive/disconnect timeouts.
    ///
    /// Use <see cref="GetOptimizedConfig"/> for a production-ready default.
    /// All public members use .NET PascalCase naming.
    /// </summary>
    public class UcpConfiguration
    {
        // Backing fields for properties that need validation or conversion.
        private int _sendBufferSize = UcpConstants.DEFAULT_SEND_BUFFER_BYTES; // Default to 32 MB to absorb application writes during congestion pauses
        private long _delayedAckTimeoutMicros = UcpConstants.DEFAULT_DELAYED_ACK_TIMEOUT_MICROS; // 100 μs default — fires only when no outbound data is available for piggybacking
        private double _maxBandwidthWastePercent = UcpConstants.DEFAULT_MAX_BANDWIDTH_WASTE_RATIO; // 25% waste ceiling — caps retransmit overhead before sender backs off
        private double _maxBandwidthLossPercent = UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT; // 25% loss tolerance — balances throughput on lossy vs. congested paths
        private long _minPacingIntervalMicros = UcpConstants.DEFAULT_MIN_PACING_INTERVAL_MICROS; // 0 μs = no floor — allows sub-μs gaps at 10 Gbps line rate
        private long _pacingBucketDurationMicros = UcpConstants.DEFAULT_PACING_BUCKET_DURATION_MICROS; // 10 ms token bucket window — smooths bursts without permitting seconds-long floods
        private int _bbrWindowRtRounds = UcpConstants.BBR_WINDOW_RTT_ROUNDS; // 10 RTT rounds — enough statistical mass without retaining stale estimates
        private double _startupPacingGain = UcpConstants.BBR_STARTUP_PACING_GAIN; // 2.89× — standard IETF BBR gain derived from 2/ln(2) for rapid pipe filling
        private double _startupCwndGain = UcpConstants.BBR_STARTUP_CWND_GAIN; // 2.0× CWND headroom during Startup — prevents inflight cap from bottlenecking the pacer
        private double _drainPacingGain = UcpConstants.BBR_DRAIN_PACING_GAIN; // 1.0× — paces at exactly estimated rate to drain Startup queue
        private double _probeBwHighGain = UcpConstants.BBR_PROBE_BW_HIGH_GAIN; // 1.35× — one phase per 8-phase cycle probes for extra bandwidth
        private double _probeBwLowGain = UcpConstants.BBR_PROBE_BW_LOW_GAIN; // 0.85× — one phase per cycle drains queue accumulated during high-gain probing
        private double _probeBwCwndGain = UcpConstants.BBR_PROBE_BW_CWND_GAIN; // 2.0× CWND headroom during ProbeBW — consistent with Startup CWND gain

        /// <summary>Maximum segment size (MSS) in bytes.</summary>
        public int Mss = UcpConstants.MSS; // 1220 bytes — fits IPv6 min-MTU without IP fragmentation, critical for UDP reliability

        /// <summary>Maximum number of retransmission attempts per segment before giving up.</summary>
        public int MaxRetransmissions = UcpConstants.MAX_RETRANSMISSIONS; // 10 attempts — ~2-3 seconds of RTO timeouts before connection teardown

        /// <summary>Minimum RTO in microseconds.</summary>
        public long MinRtoMicros = UcpConstants.DEFAULT_RTO_MICROS; // 50 ms — rides through transient WiFi/4G jitter without spurious retransmits

        /// <summary>Maximum RTO in microseconds.</summary>
        public long MaxRtoMicros = UcpConstants.DEFAULT_MAX_RTO_MICROS; // 15 s — above this, the connection is likely dead rather than delayed

        /// <summary>RTO exponential backoff factor applied on each timeout.</summary>
        public double RetransmitBackoffFactor = UcpConstants.RTO_BACKOFF_FACTOR; // 1.2× per timeout — gentler than TCP's 2.0× since NAK handles most loss

        /// <summary>Interval between ProbeRTT phases in microseconds.</summary>
        public long ProbeRttIntervalMicros = UcpConstants.BBR_PROBE_RTT_INTERVAL_MICROS; // 30 s — amortizes throughput impact of brief drain to <1%

        /// <summary>Minimum duration of a ProbeRTT phase in microseconds.</summary>
        public long ProbeRttDurationMicros = UcpConstants.BBR_PROBE_RTT_DURATION_MICROS; // 100 ms — ensures at least one clean RTT sample is collected

        /// <summary>Interval between keep-alive transmissions in microseconds.</summary>
        public long KeepAliveIntervalMicros = UcpConstants.KEEP_ALIVE_INTERVAL_MICROS; // 1 s — refreshes NAT bindings and detects dead peers promptly

        /// <summary>Idle time before disconnecting due to inactivity, in microseconds.</summary>
        public long DisconnectTimeoutMicros = UcpConstants.DISCONNECT_TIMEOUT_MICROS; // 4 s — short timeout reflects UCP's real-time transport use case

        /// <summary>Timer tick interval in milliseconds.</summary>
        public int TimerIntervalMilliseconds = UcpConstants.TIMER_INTERVAL_MILLISECONDS; // 1 ms tick — needed for accurate μs-level pacing at high data rates

        /// <summary>Fair-queue scheduling round interval in milliseconds.</summary>
        public int FairQueueRoundMilliseconds = UcpConstants.FAIR_QUEUE_ROUND_MILLISECONDS; // 10 ms — balances frequent scheduling responsiveness against per-round overhead

        /// <summary>Server aggregate bandwidth limit in bytes per second.</summary>
        public int ServerBandwidthBytesPerSecond = UcpConstants.DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND; // ~100 Mbps — conservative default for shared server egress pool

        /// <summary>Connect handshake timeout in milliseconds.</summary>
        public int ConnectTimeoutMilliseconds = UcpConstants.CONNECT_TIMEOUT_MILLISECONDS; // 5 s — allows multiple SYN retransmissions at initial RTO with backoff

        /// <summary>Initial bandwidth estimate in bytes per second for BBR Startup.</summary>
        public long InitialBandwidthBytesPerSecond = UcpConstants.DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND; // Starts at server bandwidth — BBR adjusts upward from delivery rates

        /// <summary>Maximum pacing rate ceiling in bytes per second (0 = unlimited).</summary>
        public long MaxPacingRateBytesPerSecond = UcpConstants.DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND; // Starts at server bandwidth — pacer won't exceed unless BBR estimate grows

        /// <summary>Maximum congestion window in bytes (0 = unlimited).</summary>
        public int MaxCongestionWindowBytes = UcpConstants.DEFAULT_MAX_CONGESTION_WINDOW_BYTES; // 64 MB — covers all practical BDP below 10 Gbps at 100 ms RTT

        /// <summary>Initial congestion window in packet units.</summary>
        public int InitialCwndPackets = UcpConstants.INITIAL_CWND_PACKETS; // 20 packets (~24 KB) — more aggressive than TCP IW10, safe because BBR paces

        /// <summary>Receive window size in packets for flow control advertisement.</summary>
        public int RecvWindowPackets = 16384; // 16K packets (~20 MB window) — supports 1 Gbps at ~160 ms RTT without blocking sender

        /// <summary>Minimum send quantum in bytes (typically MSS).</summary>
        public int SendQuantumBytes = UcpConstants.MSS; // 1220 bytes — one packet's worth prevents sub-packet sends from fragmenting the wire

        /// <summary>Maximum SACK blocks to include in an ACK packet.</summary>
        public int AckSackBlockLimit = UcpConstants.DEFAULT_ACK_SACK_BLOCK_LIMIT; // 2 blocks — matches QUIC default, sufficient for most single-hole loss patterns

        /// <summary>Enables loss detection and bandwidth-loss-budgeted pacing control.</summary>
        public bool LossControlEnable = true; // Enabled by default — provides loss-aware pacing without waiting for congestion classifier

        /// <summary>Enables debug trace logging for congestion control decisions.</summary>
        public bool EnableDebugLog = false; // Disabled by default — avoids performance impact of debug trace in production

        /// <summary>
        /// Enables short-grace SACK repair for fast loss recovery.
        /// When enabled, SACK-based fast retransmit triggers after fewer
        /// observations, reducing tail latency on lossy and reordering paths.
        /// Matching QUIC's approach, this is true by default.
        /// </summary>
        internal bool EnableAggressiveSackRecovery = true; // Lowers SACK retransmit threshold from 3 to 2 observations, matching QUIC for lower tail latency

        /// <summary>FEC redundancy ratio (0.0 = disabled, e.g. 0.125 = 1 repair per 8 data).</summary>
        public double FecRedundancy = 0.0d; // Disabled by default — FEC only activates when loss exceeds adaptive threshold or is explicitly configured

        /// <summary>Number of data packets per FEC group.</summary>
        public int FecGroupSize = 8; // 8 data packets per repair group — balances FEC overhead against recovery granularity

        /// <summary>
        /// Send buffer capacity in bytes. Controls how many unsent segments
        /// may be queued before <c>SendAsync</c> blocks.
        /// </summary>
        public int SendBufferSize
        {
            get { return _sendBufferSize; } // Returns the current send buffer capacity — blocks SendAsync when outstanding bytes exceed this limit
            set { _sendBufferSize = value; } // Sets send buffer capacity — larger values allow more queued data at the cost of higher memory usage
        }

        /// <summary>
        /// Receive buffer capacity exposed as bytes. Internally converted to
        /// receive window packets for ACK advertisement.
        /// </summary>
        public int ReceiveBufferSize
        {
            get { return RecvWindowPackets * Mss; } // Converts the packet-based window to bytes for user-friendly display — RecvWindowPackets × MSS
            set { RecvWindowPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss))); } // Converts user-supplied bytes to packets, rounding up — floor of 1 packet ensures at least one segment fits
        }

        /// <summary>
        /// Initial congestion window exposed as bytes. Internally converted to packets.
        /// </summary>
        public uint InitialCwndBytes
        {
            get { return (uint)InitialCongestionWindowBytes; } // Returns the computed initial CWND in bytes (cast to uint for wire compatibility)
            set { InitialCwndPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss))); } // Converts user-supplied bytes to packet count, ceiling division with floor of 1
        }

        /// <summary>Alias for MinRtoMicros.</summary>
        public long MinRtoUs
        {
            get { return MinRtoMicros; } // Returns the minimum RTO — microsecond-precision alias for user convenience
            set { MinRtoMicros = value; } // Sets the minimum RTO — delegates to the canonical MinRtoMicros field
        }

        /// <summary>Alias for MaxRtoMicros.</summary>
        public long MaxRtoUs
        {
            get { return MaxRtoMicros; } // Returns the maximum RTO — microsecond-precision alias for user convenience
            set { MaxRtoMicros = value; } // Sets the maximum RTO — delegates to the canonical MaxRtoMicros field
        }

        /// <summary>Alias for RetransmitBackoffFactor.</summary>
        public double RtoBackoffFactor
        {
            get { return RetransmitBackoffFactor; } // Returns the backoff factor — alias matching common TCP literature naming
            set { RetransmitBackoffFactor = value; } // Sets the backoff factor — delegates to the canonical RetransmitBackoffFactor field
        }

        /// <summary>Delayed ACK timeout in microseconds before a standalone ACK is sent.</summary>
        public long DelayedAckTimeoutMicros
        {
            get { return _delayedAckTimeoutMicros; } // Returns the delayed ACK timeout — ACKs are only sent standalone when no outbound data is available within this window
            set { _delayedAckTimeoutMicros = value; } // Sets the delayed ACK timeout — shorter values increase ACK overhead, longer values increase sender idle time
        }

        /// <summary>Maximum acceptable bandwidth waste ratio for CWND calculation (e.g. 0.25 = 25%).</summary>
        public double MaxBandwidthWastePercent
        {
            get { return _maxBandwidthWastePercent; } // Returns the waste ceiling — caps how much of the link capacity may be consumed by retransmissions
            set { _maxBandwidthWastePercent = value; } // Sets the waste ceiling — higher values tolerate more retransmit overhead before sender throttles
        }

        /// <summary>Maximum tolerable bandwidth loss percentage before aggressive reduction.</summary>
        public double MaxBandwidthLossPercent
        {
            get { return _maxBandwidthLossPercent; } // Returns the loss ceiling — controls how much loss the sender tolerates before reducing pacing gain
            set { _maxBandwidthLossPercent = value; } // Sets the loss ceiling — clamped to [MIN_MAX_BANDWIDTH_LOSS_PERCENT, MAX_MAX_BANDWIDTH_LOSS_PERCENT] at consumption
        }

        /// <summary>Minimum interval between paced sends in microseconds.</summary>
        public long MinPacingIntervalMicros
        {
            get { return _minPacingIntervalMicros; } // Returns the minimum inter-packet gap — 0 μs means no floor, allowing line-rate bursts on fast links
            set { _minPacingIntervalMicros = value; } // Sets the minimum inter-packet gap — higher values cap throughput by forcing gaps between sends
        }

        /// <summary>Token bucket capacity window duration in microseconds.</summary>
        public long PacingBucketDurationMicros
        {
            get { return _pacingBucketDurationMicros; } // Returns the token bucket window — controls burst elasticity: larger window = more burst tolerance
            set { _pacingBucketDurationMicros = value; } // Sets the token bucket window — longer windows allow larger bursts but risk overwhelming shallow buffers
        }

        /// <summary>Number of RTT rounds in the BBR bandwidth filter window.</summary>
        public int BbrWindowRtRounds
        {
            get { return _bbrWindowRtRounds; } // Returns the BBR filter window size in RTT rounds — longer windows produce stabler estimates
            set { _bbrWindowRtRounds = value; } // Sets the BBR filter window size — the max-filter retains the best delivery rate over this many rounds
        }

        /// <summary>Alias for ProbeRttIntervalMicros.</summary>
        public long BbrMinRttWindowMicros
        {
            get { return ProbeRttIntervalMicros; } // Returns the ProbeRTT interval — alias matching common BBR literature naming for min-RTT window
            set { ProbeRttIntervalMicros = value; } // Sets the ProbeRTT interval — delegates to the canonical ProbeRttIntervalMicros field
        }

        /// <summary>BBR Startup pacing gain multiplier.</summary>
        public double StartupPacingGain
        {
            get { return _startupPacingGain; } // Returns the Startup pacing gain — controls how aggressively BBR fills the pipe during initial ramp
            set { _startupPacingGain = value; } // Sets the Startup pacing gain — higher values converge faster but create more standing queue
        }

        /// <summary>BBR Startup congestion window gain multiplier.</summary>
        public double StartupCwndGain
        {
            get { return _startupCwndGain; } // Returns the Startup CWND gain — inflight cap relative to BDP during Startup phase
            set { _startupCwndGain = value; } // Sets the Startup CWND gain — prevents inflight cap from being the bottleneck during rapid ramp
        }

        /// <summary>BBR Drain pacing gain multiplier.</summary>
        public double DrainPacingGain
        {
            get { return _drainPacingGain; } // Returns the Drain pacing gain — controls the rate at which standing queue is emptied after Startup
            set { _drainPacingGain = value; } // Sets the Drain pacing gain — 1.0× means draining at exactly the estimated bandwidth
        }

        /// <summary>BBR ProbeBW high-gain multiplier.</summary>
        public double ProbeBwHighGain
        {
            get { return _probeBwHighGain; } // Returns the ProbeBW high gain — used in one phase per cycle to probe for additional bandwidth
            set { _probeBwHighGain = value; } // Sets the ProbeBW high gain — higher values probe more aggressively at risk of queue buildup
        }

        /// <summary>BBR ProbeBW low-gain multiplier.</summary>
        public double ProbeBwLowGain
        {
            get { return _probeBwLowGain; } // Returns the ProbeBW low gain — used in one phase per cycle to drain queue from high-gain phase
            set { _probeBwLowGain = value; } // Sets the ProbeBW low gain — 0.85× drains queue while maintaining some forward progress
        }

        /// <summary>BBR ProbeBW congestion window gain multiplier.</summary>
        public double ProbeBwCwndGain
        {
            get { return _probeBwCwndGain; } // Returns the CWND gain during ProbeBW — inflight cap relative to BDP during steady-state probing
            set { _probeBwCwndGain = value; } // Sets the CWND gain during ProbeBW — 2.0× provides headroom for the pacer to operate unimpeded
        }

        /// <summary>Alias for KeepAliveIntervalMicros.</summary>
        public long KeepAliveIntervalUs
        {
            get { return KeepAliveIntervalMicros; } // Returns the keep-alive interval — microsecond-precision alias for user convenience
            set { KeepAliveIntervalMicros = value; } // Sets the keep-alive interval — delegates to the canonical KeepAliveIntervalMicros field
        }

        /// <summary>Alias for DisconnectTimeoutMicros.</summary>
        public long DisconnectTimeoutUs
        {
            get { return DisconnectTimeoutMicros; } // Returns the disconnect timeout — microsecond-precision alias for user convenience
            set { DisconnectTimeoutMicros = value; } // Sets the disconnect timeout — delegates to the canonical DisconnectTimeoutMicros field
        }

        /// <summary>Effective minimum RTO, never below the protocol constant floor.</summary>
        public long EffectiveMinRtoMicros
        {
            get { return MinRtoMicros <= 0 ? UcpConstants.MinRtoMicros : MinRtoMicros; } // Falls back to 20 ms protocol floor if configured RTO is ≤0 — protects against invalid configuration
        }

        /// <summary>Effective maximum RTO, never below the effective minimum RTO.</summary>
        public long EffectiveMaxRtoMicros
        {
            get
            {
                long minRtoMicros = EffectiveMinRtoMicros; // Capture the effective minimum RTO to use as the floor for max RTO
                long maxRtoMicros = MaxRtoMicros <= 0 ? UcpConstants.MaxRtoMicros : MaxRtoMicros; // Fall back to 60 s absolute max if configured RTO is ≤0
                return maxRtoMicros < minRtoMicros ? minRtoMicros : maxRtoMicros; // Enforce maxRto ≥ minRto — prevents inverted RTO range that would break timer logic
            }
        }

        /// <summary>Effective retransmit backoff factor, clamped to at least 1.0.</summary>
        public double EffectiveRetransmitBackoffFactor
        {
            get { return RetransmitBackoffFactor < 1.0d ? 1.0d : RetransmitBackoffFactor; } // Clamps to 1.0 floor — a backoff factor <1.0 would shrink RTO on each timeout, which is never correct
        }

        /// <summary>Effective maximum bandwidth loss percent, clamped to [15%, 35%].</summary>
        public double EffectiveMaxBandwidthLossPercent
        {
            get
            {
                double configuredValue = MaxBandwidthLossPercent; // Read the user-configured loss ceiling
                if (configuredValue < UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT) // Below 15% would throttle too aggressively on routine random-loss paths
                {
                    return UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT; // Return the 15% floor — prevents over-throttling on Wi-Fi/4G with natural packet loss
                }

                if (configuredValue > UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT) // Above 35% would tolerate loss rates where throughput collapses regardless
                {
                    return UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT; // Return the 35% ceiling — prevents the sender from operating at unusable loss rates
                }

                return configuredValue; // Value is within the safe range [15%, 35%] — return as-is
            }
        }

        /// <summary>Maximum user payload bytes per data packet (MSS - header overhead).</summary>
        public int MaxPayloadSize
        {
            get { return Mss - UcpConstants.DataHeaderSize; } // MSS minus 20-byte data header — the per-packet application-data budget (1200 bytes at default MSS)
        }

        /// <summary>Maximum SACK blocks that fit in an ACK packet given MSS constraints.</summary>
        public int MaxAckSackBlocks
        {
            get
            {
                int encodedLimit = Math.Max(1, (Mss - UcpConstants.AckFixedSize) / UcpConstants.SACK_BLOCK_SIZE); // Compute how many SACK blocks physically fit — (MSS - 28) / 8, floor 1
                int configuredLimit = AckSackBlockLimit <= 0 ? encodedLimit : AckSackBlockLimit; // If user didn't configure a limit (≤0), use the physical maximum
                return Math.Max(1, Math.Min(configuredLimit, encodedLimit)); // Return the tighter of the configured and physical limits, never below 1
            }
        }

        /// <summary>Advertised receive window size in bytes.</summary>
        public uint ReceiveWindowBytes
        {
            get { return (uint)(RecvWindowPackets * Mss); } // Converts packet-based window to bytes for wire advertisement in ACK packets
        }

        /// <summary>Initial congestion window in bytes.</summary>
        public int InitialCongestionWindowBytes
        {
            get { return Math.Max(Mss, InitialCwndPackets * Mss); } // At least one MSS worth of bytes — prevents zero-CWND edge case on misconfiguration
        }

        /// <summary>
        /// Creates a deep copy of this configuration.
        /// </summary>
        public UcpConfiguration Clone()
        {
            UcpConfiguration clone = new UcpConfiguration(); // Allocate a fresh config instance with default values
            CopyTo(clone); // Copy all field values from this instance into the new clone
            return clone; // Return the independent deep copy — no shared references between original and clone
        }

        /// <summary>
        /// Returns a pre-configured instance with production-tuned defaults:
        /// optimized RTO, ProbeRTT intervals, backoff factor, initial CWND,
        /// and loss control enabled.
        /// </summary>
        public static UcpConfiguration GetOptimizedConfig()
        {
            UcpConfiguration config = new UcpConfiguration(); // Start with a fresh default-constructed config
            config.MinRtoMicros = UcpConstants.DEFAULT_RTO_MICROS; // 50 ms — long enough for transient jitter, short enough for fast tail-loss recovery
            config.MaxRtoMicros = UcpConstants.DEFAULT_MAX_RTO_MICROS; // 15 s — connection is likely dead beyond this point
            config.ProbeRttIntervalMicros = UcpConstants.BBR_PROBE_RTT_INTERVAL_MICROS; // 30 s between ProbeRTT phases — amortizes throughput dip to <1%
            config.ProbeRttDurationMicros = UcpConstants.BBR_PROBE_RTT_DURATION_MICROS; // 100 ms minimum ProbeRTT duration — ensures one clean RTT sample
            config.RetransmitBackoffFactor = UcpConstants.RTO_BACKOFF_FACTOR; // 1.2× gentle backoff — avoids multi-second stalls on bursty-loss paths
            config.InitialCwndPackets = UcpConstants.INITIAL_CWND_PACKETS; // 20 packets initial CWND — aggressive but safe with BBR pacing
            config.ProbeBwLowGain = UcpConstants.BBR_PROBE_BW_LOW_GAIN; // 0.85× drain-phase gain — empties queue accumulated during high-gain phase
            config.AckSackBlockLimit = UcpConstants.DEFAULT_ACK_SACK_BLOCK_LIMIT; // 2 SACK blocks per ACK — matches QUIC default for efficient loss reporting
            config.MaxBandwidthLossPercent = UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT; // 25% loss ceiling — balanced for mobile/WiFi paths with routine packet loss
            config.LossControlEnable = true; // Enable loss-aware pacing — prevents the sender from overdriving lossy paths
            config.EnableAggressiveSackRecovery = true; // Enable short-grace SACK recovery — reduces tail latency on reordering paths
            return config; // Return the production-tuned configuration ready for use
        }

        /// <summary>
        /// Copies all configuration fields from this instance to the target.
        /// Used by Clone() to create an independent deep copy and by connection
        /// setup to inherit server-level defaults into a per-connection config.
        /// </summary>
        /// <param name="target">The destination configuration instance.  Must not be null;
        /// an <see cref="ArgumentNullException"/> is thrown otherwise.</param>
        internal void CopyTo(UcpConfiguration target)
        {
            if (target == null) // Guard against null target — CopyTo is meaningless without a destination
            {
                throw new ArgumentNullException(nameof(target)); // Fail fast with a clear exception message pointing to the target parameter
            }

            target.Mss = Mss; // Copy MSS — affects all packet-size derived calculations
            target._sendBufferSize = _sendBufferSize; // Copy send buffer capacity — controls blocking behavior of SendAsync
            target._delayedAckTimeoutMicros = _delayedAckTimeoutMicros; // Copy delayed ACK timeout — affects ACK responsiveness vs. overhead
            target._maxBandwidthWastePercent = _maxBandwidthWastePercent; // Copy retransmit waste ceiling — controls when sender throttles
            target._maxBandwidthLossPercent = _maxBandwidthLossPercent; // Copy loss tolerance ceiling — clamped to [15%, 35%] at consumption
            target._minPacingIntervalMicros = _minPacingIntervalMicros; // Copy minimum pacing gap — 0 μs allows line-rate bursts
            target._pacingBucketDurationMicros = _pacingBucketDurationMicros; // Copy token bucket window — controls burst elasticity
            target._bbrWindowRtRounds = _bbrWindowRtRounds; // Copy BBR filter window size — longer windows = stabler estimates
            target._startupPacingGain = _startupPacingGain; // Copy Startup pacing gain — controls fill aggressiveness
            target._startupCwndGain = _startupCwndGain; // Copy Startup CWND gain — inflight headroom during initial ramp
            target._drainPacingGain = _drainPacingGain; // Copy Drain pacing gain — queue drain rate after Startup
            target._probeBwHighGain = _probeBwHighGain; // Copy ProbeBW high gain — bandwidth probe aggressiveness
            target._probeBwLowGain = _probeBwLowGain; // Copy ProbeBW low gain — queue drain rate during ProbeBW cycle
            target._probeBwCwndGain = _probeBwCwndGain; // Copy CWND gain during ProbeBW — steady-state inflight headroom
            target.MaxRetransmissions = MaxRetransmissions; // Copy max retransmissions — connection teardown threshold after RTO failures
            target.MinRtoMicros = MinRtoMicros; // Copy minimum RTO — floor for the RTO timer computation
            target.MaxRtoMicros = MaxRtoMicros; // Copy maximum RTO — ceiling for the RTO timer computation
            target.RetransmitBackoffFactor = RetransmitBackoffFactor; // Copy RTO backoff multiplier — controls exponential growth on repeated timeouts
            target.ProbeRttIntervalMicros = ProbeRttIntervalMicros; // Copy ProbeRTT interval — how often to re-measure RTprop
            target.ProbeRttDurationMicros = ProbeRttDurationMicros; // Copy ProbeRTT duration — minimum time in ProbeRTT state
            target.KeepAliveIntervalMicros = KeepAliveIntervalMicros; // Copy keep-alive interval — NAT binding refresh frequency
            target.DisconnectTimeoutMicros = DisconnectTimeoutMicros; // Copy disconnect timeout — idle time before dead-peer detection
            target.TimerIntervalMilliseconds = TimerIntervalMilliseconds; // Copy timer tick granularity — affects pacing precision
            target.FairQueueRoundMilliseconds = FairQueueRoundMilliseconds; // Copy fair-queue round interval — credit distribution frequency
            target.ServerBandwidthBytesPerSecond = ServerBandwidthBytesPerSecond; // Copy server bandwidth — total egress capacity for fair-queue pool
            target.ConnectTimeoutMilliseconds = ConnectTimeoutMilliseconds; // Copy connect timeout — SYN handshake deadline
            target.InitialBandwidthBytesPerSecond = InitialBandwidthBytesPerSecond; // Copy initial bandwidth estimate — BBR Startup starting point
            target.MaxPacingRateBytesPerSecond = MaxPacingRateBytesPerSecond; // Copy max pacing rate — absolute ceiling on send rate
            target.MaxCongestionWindowBytes = MaxCongestionWindowBytes; // Copy max CWND — absolute ceiling on bytes in flight
            target.InitialCwndPackets = InitialCwndPackets; // Copy initial CWND packets — starting inflight budget
            target.RecvWindowPackets = RecvWindowPackets; // Copy receive window packets — flow control advertisement size
            target.SendQuantumBytes = SendQuantumBytes; // Copy send quantum — minimum bytes sent per scheduling round
            target.AckSackBlockLimit = AckSackBlockLimit; // Copy SACK block limit — max SACK ranges per ACK packet
            target.LossControlEnable = LossControlEnable; // Copy loss control toggle — enables loss-budgeted pacing
            target.EnableDebugLog = EnableDebugLog; // Copy debug log toggle — enables trace logging for CC decisions
            target.EnableAggressiveSackRecovery = EnableAggressiveSackRecovery; // Copy aggressive SACK toggle — lowers retransmit threshold for fast recovery
            target.FecRedundancy = FecRedundancy; // Copy FEC redundancy ratio — controls forward error correction overhead
            target.FecGroupSize = FecGroupSize; // Copy FEC group size — data packets per repair group
        }
    }
}
