using System; // Provides [Flags] attribute for UcpPacketFlags bitmask enum

namespace Ucp // Root namespace for the UCP reliable-transport protocol library
{
    /// <summary>
    /// UCP protocol packet type identifiers encoded as single-byte values.
    /// These constants occupy the first byte of every UCP packet header
    /// and tell the receiving peer how to interpret the remainder of the datagram.
    /// </summary>
    internal enum UcpPacketType : byte // Single-byte packet-type discriminant in every UCP header
    {
        /// <summary>Handshake open request sent by the initiating peer to establish a connection.</summary>
        Syn = UcpConstants.UCP_SYN_TYPE_VALUE, // Initiates the three-way handshake (SYN)

        /// <summary>Handshake acknowledgment of a Syn request, carrying the peer's initial sequence.</summary>
        SynAck = UcpConstants.UCP_SYN_ACK_TYPE_VALUE, // Second step of the three-way handshake (SYN-ACK)

        /// <summary>Cumulative acknowledgment of received data; all sequences before this are delivered.</summary>
        Ack = UcpConstants.UCP_ACK_TYPE_VALUE, // Standalone cumulative acknowledgment (ACK)

        /// <summary>Negative acknowledgment listing specific missing sequence numbers for fast retransmit.</summary>
        Nak = UcpConstants.UCP_NAK_TYPE_VALUE, // Explicit loss notification beyond duplicate ACKs (NAK)

        /// <summary>Data payload packet carrying a fragment of application data.</summary>
        Data = UcpConstants.UCP_DATA_TYPE_VALUE, // User payload; may be fragmented across multiple packets

        /// <summary>Forward error correction repair packet encoding parity for a group of data packets.</summary>
        FecRepair = 0x08, // XOR-based repair packet enabling loss recovery without retransmission

        /// <summary>Graceful connection close request; once both sides FIN the connection enters Closed.</summary>
        Fin = UcpConstants.UCP_FIN_TYPE_VALUE, // Begins the graceful teardown handshake (FIN)

        /// <summary>Hard connection reset that immediately aborts the connection without negotiation.</summary>
        Rst = UcpConstants.UCP_RST_TYPE_VALUE // Forcibly tears down the connection, discarding state
    }

    /// <summary>
    /// Bitmask flags carried in the second byte of every UCP packet header.
    /// Multiple flags may be OR'd together to combine semantics in a single packet
    /// (e.g., a retransmitted data packet with piggybacked ACK number).
    /// </summary>
    [Flags] // Marks this enum as a bitmask so Flag combinators (| & ~) work correctly for ToString and HasFlag
    internal enum UcpPacketFlags : byte // Second-byte bitmask in every UCP header controlling receiver behavior
    {
        /// <summary>No flags set; the packet carries only its base semantics.</summary>
        None = UcpConstants.UCP_FLAGS_NONE_VALUE, // Default: no special processing requested

        /// <summary>Receiver should send an immediate acknowledgment for this packet.</summary>
        NeedAck = UcpConstants.UCP_FLAG_NEED_ACK_VALUE, // Requests prompt ACK for RTT sampling or flow control

        /// <summary>Packet is a retransmission of previously sent data (not original).</summary>
        Retransmit = UcpConstants.UCP_FLAG_RETRANSMIT_VALUE, // Marks re-sent data so receiver can distinguish originals from re-sends

        /// <summary>Acknowledgment of a FIN packet, used during graceful connection teardown.</summary>
        FinAck = UcpConstants.UCP_FLAG_FIN_ACK_VALUE, // Finalizes the graceful close handshake from the receiver side

        /// <summary>Packet carries a cumulative acknowledgment number in its extended header.</summary>
        HasAckNumber = UcpConstants.UCP_FLAG_HAS_ACK_VALUE // Signals that the payload is prefixed with an AckNumber field
    }

    /// <summary>
    /// States of a UCP connection state machine, mirroring TCP-like lifecycle.
    /// Each connection transitions through these states from Init to Closed,
    /// either gracefully (via FIN exchange) or abruptly (via RST).
    /// </summary>
    internal enum UcpConnectionState // Finite-state-machine states governing connection lifecycle and operations
    {
        /// <summary>Connection object created but not yet started; no packets have been exchanged.</summary>
        Init, // Freshly constructed, awaiting Open() or incoming SYN

        /// <summary>SYN sent to the remote endpoint; awaiting SYN-ACK response.</summary>
        HandshakeSynSent, // Initiator's state after sending the first SYN

        /// <summary>SYN received from the remote endpoint; awaiting final ACK of the handshake.</summary>
        HandshakeSynReceived, // Responder's state after receiving a SYN and sending SYN-ACK

        /// <summary>Connection fully established; bidirectional data transfer is allowed.</summary>
        Established, // Normal operational state with full send/receive capability

        /// <summary>Local side has initiated graceful close with a FIN; may still receive data.</summary>
        ClosingFinSent, // Local FIN sent, waiting for remote FIN or final ACK

        /// <summary>Remote side has sent a FIN; local may still send remaining data before closing.</summary>
        ClosingFinReceived, // Remote FIN received, local side finishes draining before responding

        /// <summary>Connection is fully closed and may be cleaned up; all resources can be released.</summary>
        Closed // Terminal state; no further packet processing occurs
    }

    /// <summary>
    /// Quality-of-Service priority levels for data segments.
    /// Higher priority segments are transmitted before lower priority ones
    /// when the send buffer contains segments at multiple priority levels.
    /// </summary>
    public enum UcpPriority : byte // QoS priority tier controlling send-order within a connection
    {
        /// <summary>Best-effort background data (lowest priority).</summary>
        Background = 0, // Lowest-priority class; transmitted only when no higher-priority data is queued

        /// <summary>Default bulk transfer priority.</summary>
        Normal = 1, // Standard priority for typical application data transfers

        /// <summary>Interactive/low-latency data (e.g., chat, gaming input).</summary>
        Interactive = 2, // Elevated priority for latency-sensitive payloads

        /// <summary>Urgent control-plane or time-critical data (highest).</summary>
        Urgent = 3 // Maximum priority; preempts all other traffic for critical control messages
    }

    /// <summary>
    /// Operating modes of the BBR congestion control state machine.
    /// BBR cycles through these modes to continuously estimate available
    /// bandwidth and minimum RTT without relying on packet loss as a signal.
    /// </summary>
    internal enum BbrMode // BBR congestion-control phases that govern pacing and window behavior
    {
        /// <summary>Initial rapid bandwidth probing with exponential-paced gain to discover link capacity.</summary>
        Startup, // Aggressive probing phase; doubles sending rate each round until bottleneck detected

        /// <summary>Transient drain phase that reduces in-flight queue built up during startup probing.</summary>
        Drain, // Purges excess queue backlog after Startup exits, restoring low latency

        /// <summary>Steady-state cycling through high/low pacing gains to continuously probe for additional bandwidth.</summary>
        ProbeBw, // Long-term operational mode; alternates between probing and cruising

        /// <summary>Minimum-RTT probing phase that deliberately reduces in-flight data to refresh the min-RTT estimate.</summary>
        ProbeRtt // Periodic mode (every ~10s) that drains the pipe to measure true base RTT
    }
}
