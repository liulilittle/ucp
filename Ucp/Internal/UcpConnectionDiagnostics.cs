namespace Ucp.Internal
{
    /// <summary>
    /// Internal connection diagnostics snapshot used by tests and reporting.
    /// </summary>
    internal sealed class UcpConnectionDiagnostics
    {
        public UcpConnectionState State;
        public int FlightBytes;
        public uint RemoteWindowBytes;
        public int BufferedReceiveBytes;
        public long BytesSent;
        public long BytesReceived;
        public int SentDataPackets;
        public int RetransmittedPackets;
        public int SentAckPackets;
        public int SentNakPackets;
        public int SentRstPackets;
        public int FastRetransmissions;
        public int TimeoutRetransmissions;
        public int CongestionWindowBytes;
        public double PacingRateBytesPerSecond;
        public long LastRttMicros;
        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>();
        public bool ReceivedReset;
    }
}
