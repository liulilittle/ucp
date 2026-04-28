namespace Ucp
{
    /// <summary>
    /// Central protocol constants kept in one place for future C++ portability.
    /// </summary>
    internal static class UcpConstants
    {
        public const int Mss = 1220;
        public const int CommonHeaderSize = 12;
        public const int DataHeaderSize = CommonHeaderSize + 8;
        public const int AckFixedSize = CommonHeaderSize + 4 + 2 + 4 + 6;
        public const int NakFixedSize = CommonHeaderSize + 2;
        public const int MaxPayloadSize = Mss - DataHeaderSize;
        public const int DefaultReceiveWindowPackets = 4096;
        public const uint DefaultReceiveWindowBytes = (uint)(DefaultReceiveWindowPackets * Mss);
        public const int DefaultInitialCongestionWindow = 4 * Mss;
        public const int DefaultInitialBandwidthBytesPerSecond = DefaultServerBandwidthBytesPerSecond;
        public const long MinRtoMicros = 100000;
        public const long MaxRtoMicros = 60000000;
        public const long ProbeRttIntervalMicros = 10000000;
        public const long ProbeRttDurationMicros = 200000;
        public const long KeepAliveIntervalMicros = 1000000;
        public const long DisconnectTimeoutMicros = 4000000;
        public const long TimerIntervalMilliseconds = 20;
        public const int FairQueueRoundMilliseconds = 10;
        public const int DefaultServerBandwidthBytesPerSecond = 100000000 / 8;
        public const int ConnectTimeoutMilliseconds = 5000;
        public const int MaxRttSamples = 1024;
        public const int BbrProbeBwGainCount = 8;
        public const int MinBbrStartupFullBandwidthRounds = 3;
        public const double BbrStartupGrowthTarget = 1.25d;
        public const int MaxBufferedFairQueueRounds = 2;

        public static readonly int MaxAckSackBlocks = (Mss - AckFixedSize) / 8;
    }
}
