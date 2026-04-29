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
        public int Mss = UcpConstants.MSS;
        public int MaxRetransmissions = UcpConstants.MAX_RETRANSMISSIONS;
        public long MinRtoMicros = UcpConstants.DEFAULT_RTO_MICROS;
        public long MaxRtoMicros = UcpConstants.DEFAULT_MAX_RTO_MICROS;
        public double RetransmitBackoffFactor = UcpConstants.RTO_BACKOFF_FACTOR;
        public long ProbeRttIntervalMicros = UcpConstants.BBR_PROBE_RTT_INTERVAL_MICROS;
        public long ProbeRttDurationMicros = UcpConstants.BBR_PROBE_RTT_DURATION_MICROS;
        public long KeepAliveIntervalMicros = UcpConstants.KEEP_ALIVE_INTERVAL_MICROS;
        public long DisconnectTimeoutMicros = UcpConstants.DISCONNECT_TIMEOUT_MICROS;
        public int TimerIntervalMilliseconds = UcpConstants.TIMER_INTERVAL_MILLISECONDS;
        public int FairQueueRoundMilliseconds = UcpConstants.FAIR_QUEUE_ROUND_MILLISECONDS;
        public int ServerBandwidthBytesPerSecond = UcpConstants.DEFAULT_SERVER_BANDWIDTH_BYTES_PER_SECOND;
        public int ConnectTimeoutMilliseconds = UcpConstants.CONNECT_TIMEOUT_MILLISECONDS;
        public long InitialBandwidthBytesPerSecond = UcpConstants.DEFAULT_INITIAL_BANDWIDTH_BYTES_PER_SECOND;
        public long MaxPacingRateBytesPerSecond = UcpConstants.DEFAULT_MAX_PACING_RATE_BYTES_PER_SECOND;
        public int MaxCongestionWindowBytes = UcpConstants.DEFAULT_MAX_CONGESTION_WINDOW_BYTES;
        public int InitialCwndPackets = UcpConstants.INITIAL_CWND_PACKETS;
        public int RecvWindowPackets = 16384;
        public int SendQuantumBytes = UcpConstants.MSS;
        public int AckSackBlockLimit = UcpConstants.DEFAULT_ACK_SACK_BLOCK_LIMIT;
        public bool LossControlEnable = true;
        public bool EnableDebugLog = false;
        internal bool EnableAggressiveSackRecovery = false;
        public double FecRedundancy = 0.0d;
        public int FecGroupSize = 8;

        public int SendBufferSize
        {
            get { return _sendBufferSize; }
            set { _sendBufferSize = value; }
        }

        public int ReceiveBufferSize
        {
            get { return RecvWindowPackets * Mss; }
            set { RecvWindowPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss))); }
        }

        public uint InitialCwndBytes
        {
            get { return (uint)InitialCongestionWindowBytes; }
            set { InitialCwndPackets = Math.Max(1, (int)Math.Ceiling(value / (double)Math.Max(1, Mss))); }
        }

        public long MinRtoUs
        {
            get { return MinRtoMicros; }
            set { MinRtoMicros = value; }
        }

        public long MaxRtoUs
        {
            get { return MaxRtoMicros; }
            set { MaxRtoMicros = value; }
        }

        public double RtoBackoffFactor
        {
            get { return RetransmitBackoffFactor; }
            set { RetransmitBackoffFactor = value; }
        }

        public long DelayedAckTimeoutMicros
        {
            get { return _delayedAckTimeoutMicros; }
            set { _delayedAckTimeoutMicros = value; }
        }

        public double MaxBandwidthWastePercent
        {
            get { return _maxBandwidthWastePercent; }
            set { _maxBandwidthWastePercent = value; }
        }

        public double MaxBandwidthLossPercent
        {
            get { return _maxBandwidthLossPercent; }
            set { _maxBandwidthLossPercent = value; }
        }

        public long MinPacingIntervalMicros
        {
            get { return _minPacingIntervalMicros; }
            set { _minPacingIntervalMicros = value; }
        }

        public long PacingBucketDurationMicros
        {
            get { return _pacingBucketDurationMicros; }
            set { _pacingBucketDurationMicros = value; }
        }

        public int BbrWindowRtRounds
        {
            get { return _bbrWindowRtRounds; }
            set { _bbrWindowRtRounds = value; }
        }

        public long BbrMinRttWindowMicros
        {
            get { return ProbeRttIntervalMicros; }
            set { ProbeRttIntervalMicros = value; }
        }

        public double StartupPacingGain
        {
            get { return _startupPacingGain; }
            set { _startupPacingGain = value; }
        }

        public double StartupCwndGain
        {
            get { return _startupCwndGain; }
            set { _startupCwndGain = value; }
        }

        public double DrainPacingGain
        {
            get { return _drainPacingGain; }
            set { _drainPacingGain = value; }
        }

        public double ProbeBwHighGain
        {
            get { return _probeBwHighGain; }
            set { _probeBwHighGain = value; }
        }

        public double ProbeBwLowGain
        {
            get { return _probeBwLowGain; }
            set { _probeBwLowGain = value; }
        }

        public double ProbeBwCwndGain
        {
            get { return _probeBwCwndGain; }
            set { _probeBwCwndGain = value; }
        }

        public long KeepAliveIntervalUs
        {
            get { return KeepAliveIntervalMicros; }
            set { KeepAliveIntervalMicros = value; }
        }

        public long DisconnectTimeoutUs
        {
            get { return DisconnectTimeoutMicros; }
            set { DisconnectTimeoutMicros = value; }
        }

        public long EffectiveMinRtoMicros
        {
            get { return MinRtoMicros <= 0 ? UcpConstants.MinRtoMicros : MinRtoMicros; }
        }

        public long EffectiveMaxRtoMicros
        {
            get
            {
                long minRtoMicros = EffectiveMinRtoMicros;
                long maxRtoMicros = MaxRtoMicros <= 0 ? UcpConstants.MaxRtoMicros : MaxRtoMicros;
                return maxRtoMicros < minRtoMicros ? minRtoMicros : maxRtoMicros;
            }
        }

        public double EffectiveRetransmitBackoffFactor
        {
            get { return RetransmitBackoffFactor < 1.0d ? 1.0d : RetransmitBackoffFactor; }
        }

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

        public int MaxPayloadSize
        {
            get { return Mss - UcpConstants.DataHeaderSize; }
        }

        public int MaxAckSackBlocks
        {
            get
            {
                int encodedLimit = Math.Max(1, (Mss - UcpConstants.AckFixedSize) / UcpConstants.SACK_BLOCK_SIZE);
                int configuredLimit = AckSackBlockLimit <= 0 ? encodedLimit : AckSackBlockLimit;
                return Math.Max(1, Math.Min(configuredLimit, encodedLimit));
            }
        }

        public uint ReceiveWindowBytes
        {
            get { return (uint)(RecvWindowPackets * Mss); }
        }

        public int InitialCongestionWindowBytes
        {
            get { return Math.Max(Mss, InitialCwndPackets * Mss); }
        }

        public UcpConfiguration Clone()
        {
            UcpConfiguration clone = new UcpConfiguration();
            CopyTo(clone);
            return clone;
        }

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
            return config;
        }

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
