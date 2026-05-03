using System; //< Provides the [Flags] attribute used to mark UcpPacketFlags as a bitmask enum for correct ToString/HasFlag behavior.

namespace Ucp //< Root namespace for the UCP reliable-transport protocol library.
{
    /// <summary>
    /// UCP protocol packet type identifiers encoded as single-byte values.
    /// These constants occupy the first byte of every UCP packet header
    /// and tell the receiving peer how to interpret the remainder of the datagram.
    /// </summary>
    internal enum UcpPacketType : byte //< Single-byte packet-type discriminant — each enum member maps directly to its wire-format byte value.
    {
        /// <summary>Handshake open request sent by the initiating peer to establish a connection.</summary>
        Syn = UcpConstants.UCP_SYN_TYPE_VALUE, //< 0x01 — Initiates the three-way handshake (SYN).  Carries the client's initial sequence number.

        /// <summary>Handshake acknowledgment of a Syn request, carrying the peer's initial sequence.</summary>
        SynAck = UcpConstants.UCP_SYN_ACK_TYPE_VALUE, //< 0x02 — Second step of the three-way handshake (SYN-ACK).  Server echoes the client's SYN and provides its own initial sequence.

        /// <summary>Cumulative acknowledgment of received data; all sequences before this are delivered.</summary>
        Ack = UcpConstants.UCP_ACK_TYPE_VALUE, //< 0x03 — Standalone cumulative acknowledgment (ACK).  May carry SACK blocks listing out-of-order received ranges.

        /// <summary>Negative acknowledgment listing specific missing sequence numbers for fast retransmit.</summary>
        Nak = UcpConstants.UCP_NAK_TYPE_VALUE, //< 0x04 — Explicit loss notification (NAK).  The receiver lists individual missing sequence numbers beyond duplicate ACK detection.

        /// <summary>Data payload packet carrying a fragment of application data.</summary>
        Data = UcpConstants.UCP_DATA_TYPE_VALUE, //< 0x05 — User payload packet.  May be fragmented across multiple packets using FragmentTotal/FragmentIndex.  Can piggyback ACK fields when HasAckNumber flag is set.

        /// <summary>Forward error correction repair packet encoding parity for a group of data packets.</summary>
        FecRepair = 0x08, //< 0x08 — XOR-based FEC repair packet enabling loss recovery without retransmission.  Carries parity computed over a group of preceding data packets.

        /// <summary>Graceful connection close request; once both sides FIN the connection enters Closed.</summary>
        Fin = UcpConstants.UCP_FIN_TYPE_VALUE, //< 0x06 — Begins the graceful teardown handshake (FIN).  After both sides exchange FIN, the connection transitions to Closed.

        /// <summary>Hard connection reset that immediately aborts the connection without negotiation.</summary>
        Rst = UcpConstants.UCP_RST_TYPE_VALUE //< 0x07 — Forcibly tears down the connection, discarding all state immediately.  No graceful handshake — the peer treats this as an unrecoverable error.
    }

    /// <summary>
    /// Bitmask flags carried in the second byte of every UCP packet header.
    /// Multiple flags may be OR'd together to combine semantics in a single packet
    /// (e.g., a retransmitted data packet with piggybacked ACK number).
    /// </summary>
    [Flags] //< Marks this enum as a bitmask so that flag combinations (|, &, ~) produce correct string representations and HasFlag results.
    internal enum UcpPacketFlags : byte //< Second-byte bitmask in every UCP header — each flag occupies a distinct power-of-2 bit position.
    {
        /// <summary>No flags set; the packet carries only its base semantics.</summary>
        None = UcpConstants.UCP_FLAGS_NONE_VALUE, //< 0x00 — Default: no special processing requested.  All flag bits are zero.

        /// <summary>Receiver should send an immediate acknowledgment for this packet.</summary>
        NeedAck = UcpConstants.UCP_FLAG_NEED_ACK_VALUE, //< 0x01 (bit 0) — Requests prompt ACK, bypassing the delayed-ACK timer.  Used for the last packet in a burst and for handshake packets to enable fast RTT sampling.

        /// <summary>Packet is a retransmission of previously sent data (not original).</summary>
        Retransmit = UcpConstants.UCP_FLAG_RETRANSMIT_VALUE, //< 0x02 (bit 1) — Marks re-sent data so the receiver can skip RTT sampling (Karn's algorithm) and distinguish originals from retransmissions.

        /// <summary>Acknowledgment of a FIN packet, used during graceful connection teardown.</summary>
        FinAck = UcpConstants.UCP_FLAG_FIN_ACK_VALUE, //< 0x04 (bit 2) — Finalizes the graceful close handshake.  Distinguishes a FIN-ACK from a regular cumulative ACK during teardown.

        /// <summary>Packet carries a cumulative acknowledgment number in its extended header.</summary>
        HasAckNumber = UcpConstants.UCP_FLAG_HAS_ACK_VALUE //< 0x08 (bit 3) — Signals that the packet's type-specific header is followed by piggybacked ACK fields (AckNumber, SackBlockCount, WindowSize, EchoTimestamp).
    }

    /// <summary>
    /// States of a UCP connection state machine, mirroring TCP-like lifecycle.
    /// Each connection transitions through these states from Init to Closed,
    /// either gracefully (via FIN exchange) or abruptly (via RST).
    /// </summary>
    internal enum UcpConnectionState //< Finite-state-machine states governing which operations are legal at each point in the connection lifecycle.
    {
        /// <summary>Connection object created but not yet started; no packets have been exchanged.</summary>
        Init, //< Freshly constructed, awaiting Open() or an incoming SYN.  No packets sent or received — all timers are stopped.

        /// <summary>SYN sent to the remote endpoint; awaiting SYN-ACK response.</summary>
        HandshakeSynSent, //< Initiator's state after sending the first SYN.  The RTO timer is armed for SYN retransmission.

        /// <summary>SYN received from the remote endpoint; awaiting final ACK of the handshake.</summary>
        HandshakeSynReceived, //< Responder's state after receiving a SYN and sending SYN-ACK.  Waiting for the client's ACK to complete the three-way handshake.

        /// <summary>Connection fully established; bidirectional data transfer is allowed.</summary>
        Established, //< Normal operational state with full send/receive capability.  The connection remains in this state for the bulk of its lifetime.

        /// <summary>Local side has initiated graceful close with a FIN; may still receive data.</summary>
        ClosingFinSent, //< Local FIN sent, waiting for the remote FIN or final ACK.  The local side may still receive and deliver inbound data in this half-closed state.

        /// <summary>Remote side has sent a FIN; local may still send remaining data before closing.</summary>
        ClosingFinReceived, //< Remote FIN received.  The local side finishes draining its send buffer before responding with its own FIN.

        /// <summary>Connection is fully closed and may be cleaned up; all resources can be released.</summary>
        Closed //< Terminal state — no further packet processing occurs.  All timers are stopped, buffers are freed, and the connection handle becomes invalid.
    }

    /// <summary>
    /// Quality-of-Service priority levels for data segments.
    /// Higher priority segments are transmitted before lower priority ones
    /// when the send buffer contains segments at multiple priority levels.
    /// </summary>
    public enum UcpPriority : byte //< QoS priority tier controlling send-order within a connection.  Encoded in bits [5:4] of the Flags byte (PriorityMask = 0x30).
    {
        /// <summary>Best-effort background data (lowest priority).</summary>
        Background = 0, //< Lowest-priority class — transmitted only when no higher-priority (Normal, Interactive, Urgent) data is queued.

        /// <summary>Default bulk transfer priority.</summary>
        Normal = 1, //< Standard priority for typical application data transfers.  The default when no explicit QoS level is specified by the application.

        /// <summary>Interactive/low-latency data (e.g., chat, gaming input).</summary>
        Interactive = 2, //< Elevated priority for latency-sensitive payloads.  Transmitted ahead of Background and Normal segments to minimize user-perceived delay.

        /// <summary>Urgent control-plane or time-critical data (highest).</summary>
        Urgent = 3 //< Maximum priority — preempts all other traffic for critical control messages and retransmissions that must minimize recovery latency.
    }

    /// <summary>
    /// Operating modes of the BBR congestion control state machine.
    /// BBR cycles through these modes to continuously estimate available
    /// bandwidth and minimum RTT without relying on packet loss as a signal.
    /// </summary>
    internal enum BbrMode //< BBR congestion-control phases that govern pacing gain, CWND gain, and inflight caps at each point in the state machine.
    {
        /// <summary>Initial rapid bandwidth probing with exponential-paced gain to discover link capacity.</summary>
        Startup, //< Aggressive probing phase — the sender doubles its sending rate each RTT round until the bottleneck bandwidth is detected.

        /// <summary>Transient drain phase that reduces in-flight queue built up during startup probing.</summary>
        Drain, //< Purges excess queue backlog after Startup exits.  Pacing gain drops to ≈1.0× to drain the standing queue, restoring low latency.

        /// <summary>Steady-state cycling through high/low pacing gains to continuously probe for additional bandwidth.</summary>
        ProbeBw, //< Long-term operational mode — alternates between high-gain (1.35×, 1 of 8 cycles), low-gain (0.85×, 1 of 8 cycles), and cruising (1.0×, 6 of 8 cycles).

        /// <summary>Minimum-RTT probing phase that deliberately reduces in-flight data to refresh the min-RTT estimate.</summary>
        ProbeRtt //< Periodic mode (at most once every 30 s) that drains the pipe to 4 packets to re-measure the true propagation delay (RTprop).
    }
}
