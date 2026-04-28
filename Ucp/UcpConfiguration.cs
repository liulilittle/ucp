using System;

namespace Ucp
{
    /// <summary>
    /// Runtime configuration for congestion control, windows, retransmission, pacing, and scheduling.
    /// </summary>
    public class UcpConfiguration
    {
        private int _sendBufferSize = 32 * 1024 * 1024;
        private long _delayedAckTimeoutMicros = 2000;
        private double _maxBandwidthWastePercent = 0.25d;
        private long _minPacingIntervalMicros = 1000;
        private long _pacingBucketDurationMicros = 1000000;
        private int _bbrWindowRtRounds = 10;
        private double _startupPacingGain = 2.0d;
        private double _startupCwndGain = 2.0d;
        private double _drainPacingGain = 0.75d;
        private double _probeBwHighGain = 1.25d;
        private double _probeBwLowGain = 0.75d;
        private double _probeBwCwndGain = 2.0d;
        public int Mss = 1220;
        public int MaxRetransmissions = 10;
        public long MinRtoMicros = 1000000;
        public long MaxRtoMicros = 60000000;
        public double RetransmitBackoffFactor = 1.5d;
        public long ProbeRttIntervalMicros = 10000000;
        public long ProbeRttDurationMicros = 200000;
        public long KeepAliveIntervalMicros = 1000000;
        public long DisconnectTimeoutMicros = 4000000;
        public int TimerIntervalMilliseconds = 20;
        public int FairQueueRoundMilliseconds = 10;
        public int ServerBandwidthBytesPerSecond = 100000000 / 8;
        public int ConnectTimeoutMilliseconds = 5000;
        public long InitialBandwidthBytesPerSecond = 100000000 / 8;
        public long MaxPacingRateBytesPerSecond = 100000000 / 8;
        public int MaxCongestionWindowBytes = 64 * 1024 * 1024;
        public int InitialCwndPackets = 10;
        public int RecvWindowPackets = 16384;
        public int SendQuantumBytes = 1220;
        public bool EnableDebugLog = false;

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

        public int MaxPayloadSize
        {
            get { return Mss - UcpConstants.DataHeaderSize; }
        }

        public int MaxAckSackBlocks
        {
            get { return Math.Max(1, (Mss - UcpConstants.AckFixedSize) / 8); }
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
            target.EnableDebugLog = EnableDebugLog;
        }
    }

}
