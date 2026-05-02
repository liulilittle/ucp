using System;

namespace Ucp
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
        private int _sendBufferSize = UcpConstants.DEFAULT_SEND_BUFFER_BYTES;
        private long _delayedAckTimeoutMicros = UcpConstants.DEFAULT_DELAYED_ACK_TIMEOUT_MICROS;
        private double _maxBandwidthWastePercent = UcpConstants.DEFAULT_MAX_BANDWIDTH_WASTE_RATIO;
        private double _maxBandwidthLossPercent = UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT;
        private long _minPacingIntervalMicros = UcpConstants.DEFAULT_MIN_PACING_INTERVAL_MICROS;
        private long _pacingBucketDurationMicros = UcpConstants.DEFAULT_PACING_BUCKET_DURATION_MICROS;
        private int _bbrWindowRtRounds = UcpConstants.BBR_WINDOW_RTT_ROUNDS;
        private double _startupPacingGain = UcpConstants.BBR_STARTUP_PACING_GAIN;
        private double _startupCwndGain = UcpConstants.BBR_STARTUP_CWND_GAIN;
        private double _drainPacingGain = UcpConstants.BBR_DRAIN_PACING_GAIN;
        private double _probeBwHighGain = UcpConstants.BBR_PROBE_BW_HIGH_GAIN;
        private double _probeBwLowGain = UcpConstants.BBR_PROBE_BW_LOW_GAIN;
        private double _probeBwCwndGain = UcpConstants.BBR_PROBE_BW_CWND_GAIN;

        /// <summary>Maximum segment size (MSS) in bytes.</summary>
        public int Mss = UcpConstants.MSS;

        /// <summary>Maximum number of retransmission attempts per segment before giving up.</summary>
        public int MaxRetransmissions = UcpConstants.MAX_RETRANSMISSIONS;

        /// <summary>Minimum RTO in microseconds.</summary>
        public long MinRtoMicros = UcpConstants.DEFAULT_RTO_MICROS;

        /// <summary>Maximum RTO in microseconds.</summary>
        public long MaxRtoMicros = UcpConstants.DEFAULT_MAX_RTO_MICROS;

        /// <summary>RTO exponential backoff factor applied on each timeout.</summary>
        public double RetransmitBackoffFactor = UcpConstants.RTO_BACKOFF_FACTOR;

        /// <summary>Interval between ProbeRTT phases in microseconds.</summary>
        public long ProbeRttIntervalMicros = UcpConstants.BBR_PROBE_RTT_INTERVAL_MICROS;

        /// <summary>Minimum duration of a ProbeRTT phase in microseconds.</summary>
        public long ProbeRttDurationMicros = UcpConstants.BBR_PROBE_RTT_DURATION_MICROS;

        /// <summary>Interval between keep-alive transmissions in microseconds.</summary>
        public long KeepAliveIntervalMicros = UcpConstants.KEEP_ALIVE_INTERVAL_MICROS;

        /// <summary>Idle time before disconnecting due to inactivity, in microseconds.</summary>
        public long DisconnectTimeoutMicros = UcpConstants.DISCONNECT_TIMEOUT_MICROS;

        /// <summary>Timer tick interval in milliseconds.</summary>
        public int TimerIntervalMilliseconds = UcpConstants.TIMER_INTERVAL_MILLISECONDS;

        /// <summary>Fair-queue scheduling round interval in milliseconds.</summary>
        public int FairQueueRoundMilliseconds = UcpConstants.FAIR_QUEUE_ROUND_MILLISECONDS;

        /// <summary>Server aggregate bandwidth limit in bytes per second.</summary>
        public int ServerBandwidthBytesPerSecond = UcpConstants.DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Connect handshake timeout in milliseconds.</summary>
        public int ConnectTimeoutMilliseconds = UcpConstants.CONNECT_TIMEOUT_MILLISECONDS;

        /// <summary>Initial bandwidth estimate in bytes per second for BBR Startup.</summary>
        public long InitialBandwidthBytesPerSecond = UcpConstants.DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND;

        /// <summary>Maximum pacing rate ceiling in bytes per second (0 = unlimited).</summary>
        public long MaxPacingRateBytesPerSecond = UcpConstants.DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND;

        /// <summary>Maximum congestion window in bytes (0 = unlimited).</summary>
        public int MaxCongestionWindowBytes = UcpConstants.DEFAULT_MAX_CONGESTION_WINDOW_BYTES;

        /// <summary>Initial congestion window in packet units.</summary>
        public int InitialCwndPackets = UcpConstants.INITIAL_CWND_PACKETS;

        /// <summary>Receive window size in packets for flow control advertisement.</summary>
        public int RecvWindowPackets = 16384;

        /// <summary>Minimum send quantum in bytes (typically MSS).</summary>
        public int SendQuantumBytes = UcpConstants.MSS;

        /// <summary>Maximum SACK blocks to include in an ACK packet.</summary>
        public int AckSackBlockLimit = UcpConstants.DEFAULT_ACK_SACK_BLOCK_LIMIT;

        /// <summary>Enables loss detection and bandwidth-loss-budgeted pacing control.</summary>
        public bool LossControlEnable = true;

        /// <summary>Enables debug trace logging for congestion control decisions.</summary>
        public bool EnableDebugLog = false;

        /// <summary>
        /// Enables short-grace SACK repair for fast loss recovery.
        /// When enabled, SACK-based fast retransmit triggers after fewer
        /// observations, reducing tail latency on lossy and reordering paths.
        /// Matching QUIC's approach, this is true by default.
        /// </summary>
        internal bool EnableAggressiveSackRecovery = true;

        /// <summary>FEC redundancy ratio (0.0 = disabled, e.g. 0.125 = 1 repair per 8 data).</summary>
        public double FecRedundancy = 0.0d;

        /// <summary>Number of data packets per FEC group.</summary>
        public int FecGroupSize = 8;

        /// <summary>
        /// Send buffer capacity in bytes. Controls how many unsent segments
        /// may be queued before <c>SendAsync</c> blocks.
        /// </summary>
        public int SendBufferSize
        {
            get { return _sendBufferSize; }
            set { _sendBufferSize = value; }
        }

        /// <summary>
        /// Receive buffer capacity exposed as bytes. Internally converted to
        /// receive window packets for ACK advertisement.
        /// </summary>
        public int ReceiveBufferSize
        {
            get { return RecvWindowPackets * Mss; }
            set { RecvWindowPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss))); }
        }

        /// <summary>
        /// Initial congestion window exposed as bytes. Internally converted to packets.
        /// </summary>
        public uint InitialCwndBytes
        {
            get { return (uint)InitialCongestionWindowBytes; }
            set { InitialCwndPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss))); }
        }

        /// <summary>Alias for MinRtoMicros.</summary>
        public long MinRtoUs
        {
            get { return MinRtoMicros; }
            set { MinRtoMicros = value; }
        }

        /// <summary>Alias for MaxRtoMicros.</summary>
        public long MaxRtoUs
        {
            get { return MaxRtoMicros; }
            set { MaxRtoMicros = value; }
        }

        /// <summary>Alias for RetransmitBackoffFactor.</summary>
        public double RtoBackoffFactor
        {
            get { return RetransmitBackoffFactor; }
            set { RetransmitBackoffFactor = value; }
        }

        /// <summary>Delayed ACK timeout in microseconds before a standalone ACK is sent.</summary>
        public long DelayedAckTimeoutMicros
        {
            get { return _delayedAckTimeoutMicros; }
            set { _delayedAckTimeoutMicros = value; }
        }

        /// <summary>Maximum acceptable bandwidth waste ratio for CWND calculation (e.g. 0.25 = 25%).</summary>
        public double MaxBandwidthWastePercent
        {
            get { return _maxBandwidthWastePercent; }
            set { _maxBandwidthWastePercent = value; }
        }

        /// <summary>Maximum tolerable bandwidth loss percentage before aggressive reduction.</summary>
        public double MaxBandwidthLossPercent
        {
            get { return _maxBandwidthLossPercent; }
            set { _maxBandwidthLossPercent = value; }
        }

        /// <summary>Minimum interval between paced sends in microseconds.</summary>
        public long MinPacingIntervalMicros
        {
            get { return _minPacingIntervalMicros; }
            set { _minPacingIntervalMicros = value; }
        }

        /// <summary>Token bucket capacity window duration in microseconds.</summary>
        public long PacingBucketDurationMicros
        {
            get { return _pacingBucketDurationMicros; }
            set { _pacingBucketDurationMicros = value; }
        }

        /// <summary>Number of RTT rounds in the BBR bandwidth filter window.</summary>
        public int BbrWindowRtRounds
        {
            get { return _bbrWindowRtRounds; }
            set { _bbrWindowRtRounds = value; }
        }

        /// <summary>Alias for ProbeRttIntervalMicros.</summary>
        public long BbrMinRttWindowMicros
        {
            get { return ProbeRttIntervalMicros; }
            set { ProbeRttIntervalMicros = value; }
        }

        /// <summary>BBR Startup pacing gain multiplier.</summary>
        public double StartupPacingGain
        {
            get { return _startupPacingGain; }
            set { _startupPacingGain = value; }
        }

        /// <summary>BBR Startup congestion window gain multiplier.</summary>
        public double StartupCwndGain
        {
            get { return _startupCwndGain; }
            set { _startupCwndGain = value; }
        }

        /// <summary>BBR Drain pacing gain multiplier.</summary>
        public double DrainPacingGain
        {
            get { return _drainPacingGain; }
            set { _drainPacingGain = value; }
        }

        /// <summary>BBR ProbeBW high-gain multiplier.</summary>
        public double ProbeBwHighGain
        {
            get { return _probeBwHighGain; }
            set { _probeBwHighGain = value; }
        }

        /// <summary>BBR ProbeBW low-gain multiplier.</summary>
        public double ProbeBwLowGain
        {
            get { return _probeBwLowGain; }
            set { _probeBwLowGain = value; }
        }

        /// <summary>BBR ProbeBW congestion window gain multiplier.</summary>
        public double ProbeBwCwndGain
        {
            get { return _probeBwCwndGain; }
            set { _probeBwCwndGain = value; }
        }

        /// <summary>Alias for KeepAliveIntervalMicros.</summary>
        public long KeepAliveIntervalUs
        {
            get { return KeepAliveIntervalMicros; }
            set { KeepAliveIntervalMicros = value; }
        }

        /// <summary>Alias for DisconnectTimeoutMicros.</summary>
        public long DisconnectTimeoutUs
        {
            get { return DisconnectTimeoutMicros; }
            set { DisconnectTimeoutMicros = value; }
        }

        /// <summary>Effective minimum RTO, never below the protocol constant floor.</summary>
        public long EffectiveMinRtoMicros
        {
            get { return MinRtoMicros <= 0 ? UcpConstants.MinRtoMicros : MinRtoMicros; }
        }

        /// <summary>Effective maximum RTO, never below the effective minimum RTO.</summary>
        public long EffectiveMaxRtoMicros
        {
            get
            {
                long minRtoMicros = EffectiveMinRtoMicros;
                long maxRtoMicros = MaxRtoMicros <= 0 ? UcpConstants.MaxRtoMicros : MaxRtoMicros;
                return maxRtoMicros < minRtoMicros ? minRtoMicros : maxRtoMicros;
            }
        }

        /// <summary>Effective retransmit backoff factor, clamped to at least 1.0.</summary>
        public double EffectiveRetransmitBackoffFactor
        {
            get { return RetransmitBackoffFactor < 1.0d ? 1.0d : RetransmitBackoffFactor; }
        }

        /// <summary>Effective maximum bandwidth loss percent, clamped to [15%, 35%].</summary>
        public double EffectiveMaxBandwidthLossPercent
        {
            get
            {
                double configuredValue = MaxBandwidthLossPercent;
                if (configuredValue < UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT)
                {
                    return UcpConstants.MIN_MAX_BANDWIDTH_LOSS_PERCENT;
                }

                if (configuredValue > UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT)
                {
                    return UcpConstants.MAX_MAX_BANDWIDTH_LOSS_PERCENT;
                }

                return configuredValue;
            }
        }

        /// <summary>Maximum user payload bytes per data packet (MSS - header overhead).</summary>
        public int MaxPayloadSize
        {
            get { return Mss - UcpConstants.DataHeaderSize; }
        }

        /// <summary>Maximum SACK blocks that fit in an ACK packet given MSS constraints.</summary>
        public int MaxAckSackBlocks
        {
            get
            {
                int encodedLimit = Math.Max(1, (Mss - UcpConstants.AckFixedSize) / UcpConstants.SACK_BLOCK_SIZE);
                int configuredLimit = AckSackBlockLimit <= 0 ? encodedLimit : AckSackBlockLimit;
                return Math.Max(1, Math.Min(configuredLimit, encodedLimit));
            }
        }

        /// <summary>Advertised receive window size in bytes.</summary>
        public uint ReceiveWindowBytes
        {
            get { return (uint)(RecvWindowPackets * Mss); }
        }

        /// <summary>Initial congestion window in bytes.</summary>
        public int InitialCongestionWindowBytes
        {
            get { return Math.Max(Mss, InitialCwndPackets * Mss); }
        }

        /// <summary>
        /// Creates a deep copy of this configuration.
        /// </summary>
        public UcpConfiguration Clone()
        {
            UcpConfiguration clone = new UcpConfiguration();
            CopyTo(clone);
            return clone;
        }

        /// <summary>
        /// Returns a pre-configured instance with production-tuned defaults:
        /// optimized RTO, ProbeRTT intervals, backoff factor, initial CWND,
        /// and loss control enabled.
        /// </summary>
        public static UcpConfiguration GetOptimizedConfig()
        {
            UcpConfiguration config = new UcpConfiguration();
            config.MinRtoMicros = UcpConstants.DEFAULT_RTO_MICROS;
            config.MaxRtoMicros = UcpConstants.DEFAULT_MAX_RTO_MICROS;
            config.ProbeRttIntervalMicros = UcpConstants.BBR_PROBE_RTT_INTERVAL_MICROS;
            config.ProbeRttDurationMicros = UcpConstants.BBR_PROBE_RTT_DURATION_MICROS;
            config.RetransmitBackoffFactor = UcpConstants.RTO_BACKOFF_FACTOR;
            config.InitialCwndPackets = UcpConstants.INITIAL_CWND_PACKETS;
            config.ProbeBwLowGain = UcpConstants.BBR_PROBE_BW_LOW_GAIN;
            config.AckSackBlockLimit = UcpConstants.DEFAULT_ACK_SACK_BLOCK_LIMIT;
            config.MaxBandwidthLossPercent = UcpConstants.DEFAULT_MAX_BANDWIDTH_LOSS_PERCENT;
            config.LossControlEnable = true;
            config.EnableAggressiveSackRecovery = true;
            return config;
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
            if (target == null)
            {
                throw new ArgumentNullException(nameof(target));
            }

            target.Mss = Mss;
            target._sendBufferSize = _sendBufferSize;
            target._delayedAckTimeoutMicros = _delayedAckTimeoutMicros;
            target._maxBandwidthWastePercent = _maxBandwidthWastePercent;
            target._maxBandwidthLossPercent = _maxBandwidthLossPercent;
            target._minPacingIntervalMicros = _minPacingIntervalMicros;
            target._pacingBucketDurationMicros = _pacingBucketDurationMicros;
            target._bbrWindowRtRounds = _bbrWindowRtRounds;
            target._startupPacingGain = _startupPacingGain;
            target._startupCwndGain = _startupCwndGain;
            target._drainPacingGain = _drainPacingGain;
            target._probeBwHighGain = _probeBwHighGain;
            target._probeBwLowGain = _probeBwLowGain;
            target._probeBwCwndGain = _probeBwCwndGain;
            target.MaxRetransmissions = MaxRetransmissions;
            target.MinRtoMicros = MinRtoMicros;
            target.MaxRtoMicros = MaxRtoMicros;
            target.RetransmitBackoffFactor = RetransmitBackoffFactor;
            target.ProbeRttIntervalMicros = ProbeRttIntervalMicros;
            target.ProbeRttDurationMicros = ProbeRttDurationMicros;
            target.KeepAliveIntervalMicros = KeepAliveIntervalMicros;
            target.DisconnectTimeoutMicros = DisconnectTimeoutMicros;
            target.TimerIntervalMilliseconds = TimerIntervalMilliseconds;
            target.FairQueueRoundMilliseconds = FairQueueRoundMilliseconds;
            target.ServerBandwidthBytesPerSecond = ServerBandwidthBytesPerSecond;
            target.ConnectTimeoutMilliseconds = ConnectTimeoutMilliseconds;
            target.InitialBandwidthBytesPerSecond = InitialBandwidthBytesPerSecond;
            target.MaxPacingRateBytesPerSecond = MaxPacingRateBytesPerSecond;
            target.MaxCongestionWindowBytes = MaxCongestionWindowBytes;
            target.InitialCwndPackets = InitialCwndPackets;
            target.RecvWindowPackets = RecvWindowPackets;
            target.SendQuantumBytes = SendQuantumBytes;
            target.AckSackBlockLimit = AckSackBlockLimit;
            target.LossControlEnable = LossControlEnable;
            target.EnableDebugLog = EnableDebugLog;
            target.EnableAggressiveSackRecovery = EnableAggressiveSackRecovery;
            target.FecRedundancy = FecRedundancy;
            target.FecGroupSize = FecGroupSize;
        }
    }
}
