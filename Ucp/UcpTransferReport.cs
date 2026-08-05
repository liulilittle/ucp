namespace Ucp
{

    public sealed class UcpTransferReport
    {

        public long BytesSent;

        public long BytesReceived;

        public int DataPacketsSent;

        public int RetransmittedPackets;

        public int AckPacketsSent;

        public int NakPacketsSent;

        public int FastRetransmissions;

        public int TimeoutRetransmissions;

        public long LastRttMicros;

        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>();

        public long CongestionWindowBytes;

        public double PacingRateBytesPerSecond;

        public double EstimatedLossPercent;

        public double MeasuredBandwidthBytesPerSecond;

        public uint RemoteWindowBytes;

        public double RetransmissionRatio
        {
            get { return 0 == DataPacketsSent ? 0 : (double)RetransmittedPackets / DataPacketsSent; }
        }
    }
}
