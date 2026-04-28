namespace Ucp
{
    /// <summary>
    /// Reusable statistics snapshot for a connection or a single test scenario.
    /// </summary>
    public sealed class UcpTransferReport
    {
        public long BytesSent;
        public long BytesReceived;
        public int DataPacketsSent;
        public int RetransmittedPackets;
        public int AckPacketsSent;
        public int NakPacketsSent;
        public long LastRttMicros;
        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>();
        public int CongestionWindowBytes;
        public double PacingRateBytesPerSecond;
        public double EstimatedLossPercent;
        public uint RemoteWindowBytes;

        public double RetransmissionRatio
        {
            get { return DataPacketsSent == 0 ? 0 : (double)RetransmittedPackets / DataPacketsSent; }
        }
    }
}
