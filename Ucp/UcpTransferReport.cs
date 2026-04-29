namespace Ucp
{
    /// <summary>
    /// Reusable statistics snapshot for a connection or a single test scenario.
    /// Packet-loss counters here are protocol-side counters; benchmark physical
    /// loss is measured separately by the test network simulator.
    /// </summary>
    public sealed class UcpTransferReport
    {
        /// <summary>Total user payload bytes accepted for sending.</summary>
        public long BytesSent;

        /// <summary>Total user payload bytes delivered in order to the receiver.</summary>
        public long BytesReceived;

        /// <summary>Original DATA packets sent by the connection.</summary>
        public int DataPacketsSent;

        /// <summary>DATA packets sent again to repair missing sequences.</summary>
        public int RetransmittedPackets;

        /// <summary>ACK packets emitted by the connection.</summary>
        public int AckPacketsSent;

        /// <summary>NAK packets emitted by the connection.</summary>
        public int NakPacketsSent;

        /// <summary>Retransmits triggered before RTO by SACK, NAK, or duplicate ACK.</summary>
        public int FastRetransmissions;

        /// <summary>Retransmits triggered by the RTO timer.</summary>
        public int TimeoutRetransmissions;

        /// <summary>Most recent accepted RTT sample in microseconds.</summary>
        public long LastRttMicros;

        /// <summary>Retained RTT samples in microseconds for diagnostics and reports.</summary>
        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>();

        /// <summary>Current congestion window in bytes.</summary>
        public int CongestionWindowBytes;

        /// <summary>Current pacing rate in bytes per second.</summary>
        public double PacingRateBytesPerSecond;

        /// <summary>Controller-estimated loss percentage used for congestion decisions.</summary>
        public double EstimatedLossPercent;

        /// <summary>Latest peer-advertised receive window in bytes.</summary>
        public uint RemoteWindowBytes;

        /// <summary>
        /// Sender retransmission overhead. This is not physical network loss;
        /// benchmark `Loss%` is simulator-observed packet loss before recovery.
        /// </summary>
        public double RetransmissionRatio
        {
            get { return DataPacketsSent == 0 ? 0 : (double)RetransmittedPackets / DataPacketsSent; }
        }
    }
}
