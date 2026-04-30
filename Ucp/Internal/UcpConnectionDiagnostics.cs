namespace Ucp.Internal
{
    /// <summary>
    /// Internal connection diagnostics snapshot used by tests and reporting.
    /// Captures all counters, window sizes, RTT history, and state at a point in time.
    /// </summary>
    internal sealed class UcpConnectionDiagnostics
    {
        /// <summary>Current connection state machine state.</summary>
        public UcpConnectionState State;

        /// <summary>Bytes currently in flight (sent but not yet acknowledged).</summary>
        public int FlightBytes;

        /// <summary>Peer-advertised receive window size in bytes.</summary>
        public uint RemoteWindowBytes;

        /// <summary>Bytes buffered in the receive queue waiting for application read.</summary>
        public int BufferedReceiveBytes;

        /// <summary>Cumulative user payload bytes sent.</summary>
        public long BytesSent;

        /// <summary>Cumulative user payload bytes received in order.</summary>
        public long BytesReceived;

        /// <summary>Count of original data packets transmitted.</summary>
        public int SentDataPackets;

        /// <summary>Count of retransmitted data packets.</summary>
        public int RetransmittedPackets;

        /// <summary>Count of ACK packets transmitted.</summary>
        public int SentAckPackets;

        /// <summary>Count of NAK packets transmitted.</summary>
        public int SentNakPackets;

        /// <summary>Count of RST packets transmitted.</summary>
        public int SentRstPackets;

        /// <summary>Count of fast retransmissions (SACK, NAK, duplicate ACK driven).</summary>
        public int FastRetransmissions;

        /// <summary>Count of RTO-timer-driven retransmissions.</summary>
        public int TimeoutRetransmissions;

        /// <summary>Current BBR congestion window in bytes.</summary>
        public int CongestionWindowBytes;

        /// <summary>Current pacing rate in bytes per second.</summary>
        public double PacingRateBytesPerSecond;

        /// <summary>Controller-estimated loss percentage.</summary>
        public double EstimatedLossPercent;

        /// <summary>Most recent accepted RTT sample in microseconds.</summary>
        public long LastRttMicros;

        /// <summary>Retained RTT samples in microseconds for diagnostics.</summary>
        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>();

        /// <summary>Whether a RST packet was received from the peer.</summary>
        public bool ReceivedReset;

        /// <summary>Current BBR network class as an integer for serialization.</summary>
        public int CurrentNetworkClass;
    }
}
