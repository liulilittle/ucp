namespace Ucp.Internal // Placed in the Internal namespace to limit visibility to tests and internal reporting
{
    /// <summary>
    /// Internal connection diagnostics snapshot used by tests and reporting.
    /// Captures all counters, window sizes, RTT history, and state at a point in time.
    /// </summary>
    internal sealed class UcpConnectionDiagnostics
    {
        /// <summary>Current connection state machine state.</summary>
        public UcpConnectionState State; // Snapshot of the connection's state enum at the time of capture

        /// <summary>Bytes currently in flight (sent but not yet acknowledged).</summary>
        public int FlightBytes; // Number of unacknowledged bytes in the network; zero when pipe is empty

        /// <summary>Peer-advertised receive window size in bytes.</summary>
        public uint RemoteWindowBytes; // The receiver's advertised buffer capacity; sender must not exceed this in flight

        /// <summary>Bytes buffered in the receive queue waiting for application read.</summary>
        public int BufferedReceiveBytes; // Number of received-but-not-yet-read bytes sitting in the local buffer

        /// <summary>Cumulative user payload bytes sent.</summary>
        public long BytesSent; // Running total of all application data bytes transmitted over the lifetime of the connection

        /// <summary>Cumulative user payload bytes received in order.</summary>
        public long BytesReceived; // Running total of in-order application data bytes delivered to the receiver

        /// <summary>Count of original data packets transmitted.</summary>
        public int SentDataPackets; // Running count of first-time (non-retransmitted) data packets sent

        /// <summary>Count of retransmitted data packets.</summary>
        public int RetransmittedPackets; // Running count of packets sent more than once due to loss or timeout

        /// <summary>Count of ACK packets transmitted.</summary>
        public int SentAckPackets; // Running count of acknowledgment packets sent to the peer

        /// <summary>Count of NAK packets transmitted.</summary>
        public int SentNakPackets; // Running count of negative acknowledgment packets sent when gaps are detected

        /// <summary>Count of RST packets transmitted.</summary>
        public int SentRstPackets; // Running count of reset packets sent to abort or reset the connection

        /// <summary>Count of fast retransmissions (SACK, NAK, duplicate ACK driven).</summary>
        public int FastRetransmissions; // Running count of retransmissions triggered by selective ACK or NAK (not by RTO timeout)

        /// <summary>Count of RTO-timer-driven retransmissions.</summary>
        public int TimeoutRetransmissions; // Running count of retransmissions triggered by the RTO timer expiring

        /// <summary>Current BBR congestion window in bytes.</summary>
        public int CongestionWindowBytes; // The congestion controller's current send window size in bytes

        /// <summary>Current pacing rate in bytes per second.</summary>
        public double PacingRateBytesPerSecond; // The pacing controller's current send rate ceiling

        /// <summary>Controller-estimated loss percentage.</summary>
        public double EstimatedLossPercent; // The congestion controller's estimated packet loss rate as a percentage

        /// <summary>Most recent accepted RTT sample in microseconds.</summary>
        public long LastRttMicros; // The most recent valid round-trip time measurement in microseconds

        /// <summary>Retained RTT samples in microseconds for diagnostics.</summary>
        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>(); // Initialize a new list to collect RTT samples for analysis; initialized inline to avoid null reference issues

        /// <summary>Whether a RST packet was received from the peer.</summary>
        public bool ReceivedReset; // True if the peer has sent a reset packet to terminate the connection abnormally

        /// <summary>Current BBR network class as an integer for serialization.</summary>
        public int CurrentNetworkClass; // Integer representation of the BBR network classification (e.g., STARTUP, DRAIN, PROBE_BW)
    }
}
