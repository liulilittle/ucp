namespace Ucp // Root namespace for the UCP reliable-transport protocol library
{
    /// <summary>
    /// Reusable statistics snapshot for a connection or a single test scenario.
    /// Packet-loss counters here are protocol-side counters; benchmark physical
    /// loss is measured separately by the test network simulator.
    /// This class is populated periodically during connection operation and
    /// serves as the public-facing diagnostics output (e.g., for throughput
    /// benchmarks, loss analysis, and congestion-control tuning).
    /// </summary>
    public sealed class UcpTransferReport // Diagnostics snapshot aggregating connection statistics for external reporting
    {
        /// <summary>Total user payload bytes accepted for sending via Send().</summary>
        public long BytesSent; // Cumulative application bytes pushed into the send pipeline

        /// <summary>Total user payload bytes delivered in order to the receiver via Recv().</summary>
        public long BytesReceived; // Cumulative application bytes successfully delivered to the caller

        /// <summary>Original DATA packets sent by the connection (first transmission of each payload).</summary>
        public int DataPacketsSent; // Count of unique data segments transmitted at least once

        /// <summary>DATA packets sent again to repair missing sequences detected by the peer.</summary>
        public int RetransmittedPackets; // Count of re-sent packets; may exceed DataPacketsSent if multiple re-sends occur

        /// <summary>ACK packets emitted by the connection to acknowledge received data.</summary>
        public int AckPacketsSent; // Cumulative acknowledgments sent; reflects receiver-side activity

        /// <summary>NAK packets emitted by the connection listing specifically missing sequences.</summary>
        public int NakPacketsSent; // Explicit loss reports sent to trigger fast retransmission

        /// <summary>Retransmits triggered before RTO by SACK, NAK, or duplicate ACK detection.</summary>
        public int FastRetransmissions; // Loss-repair retransmits that avoided waiting for a full timeout

        /// <summary>Retransmits triggered by the RTO timer expiring without acknowledgment.</summary>
        public int TimeoutRetransmissions; // Retransmits caused by the retransmission timer firing

        /// <summary>Most recent accepted RTT sample in microseconds (updated on each valid measurement).</summary>
        public long LastRttMicros; // The latest round-trip-time sample used for RTO estimation

        /// <summary>Retained RTT samples in microseconds for diagnostics and trend analysis reporting.</summary>
        public System.Collections.Generic.List<long> RttSamplesMicros = new System.Collections.Generic.List<long>(); // Historical RTT measurements for latency analysis

        /// <summary>Current congestion window in bytes as computed by the BBR controller.</summary>
        public int CongestionWindowBytes; // The sender's computed limit on unacknowledged data in flight

        /// <summary>Current pacing rate in bytes per second as computed by the BBR controller.</summary>
        public double PacingRateBytesPerSecond; // Rate at which the sender is allowed to inject data into the network

        /// <summary>Controller-estimated loss percentage used for congestion decisions (0-100 scale).</summary>
        public double EstimatedLossPercent; // BBR's internal loss-rate estimate influencing mode transitions

        /// <summary>Latest peer-advertised receive window in bytes, used for flow-control enforcement.</summary>
        public uint RemoteWindowBytes; // The receiver's advertised buffer capacity; sender must not exceed this

        /// <summary>
        /// Sender retransmission overhead expressed as a ratio of retransmitted
        /// packets to original data packets. This is not physical network loss;
        /// benchmark `Loss%` is simulator-observed packet loss before recovery.
        /// A value of 0.0 means no retransmissions occurred; 0.5 means half of
        /// all originally-sent packets required re-sending.
        /// </summary>
        public double RetransmissionRatio // Ratio of retransmitted packets to original data packets; 0 = perfect delivery
        {
            get { return DataPacketsSent == 0 ? 0 : (double)RetransmittedPackets / DataPacketsSent; } // Guard against division by zero; compute ratio only if any packets were sent
        }
    }
}
