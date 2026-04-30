using System;

namespace Ucp
{
    /// <summary>
    /// UCP protocol packet type identifiers encoded as single-byte values.
    /// </summary>
    internal enum UcpPacketType : byte
    {
        /// <summary>Handshake open request.</summary>
        Syn = UcpConstants.UCP_SYN_TYPE_VALUE,

        /// <summary>Handshake acknowledgment of a Syn request.</summary>
        SynAck = UcpConstants.UCP_SYN_ACK_TYPE_VALUE,

        /// <summary>Cumulative acknowledgment of received data.</summary>
        Ack = UcpConstants.UCP_ACK_TYPE_VALUE,

        /// <summary>Negative acknowledgment listing missing sequence numbers.</summary>
        Nak = UcpConstants.UCP_NAK_TYPE_VALUE,

        /// <summary>Data payload packet.</summary>
        Data = UcpConstants.UCP_DATA_TYPE_VALUE,

        /// <summary>Forward error correction repair packet.</summary>
        FecRepair = 0x08,

        /// <summary>Graceful connection close request.</summary>
        Fin = UcpConstants.UCP_FIN_TYPE_VALUE,

        /// <summary>Hard connection reset.</summary>
        Rst = UcpConstants.UCP_RST_TYPE_VALUE
    }

    /// <summary>
    /// Bitmask flags carried in the second byte of every UCP packet header.
    /// </summary>
    [Flags]
    internal enum UcpPacketFlags : byte
    {
        /// <summary>No flags set.</summary>
        None = UcpConstants.UCP_FLAGS_NONE_VALUE,

        /// <summary>Receiver should send an immediate acknowledgment.</summary>
        NeedAck = UcpConstants.UCP_FLAG_NEED_ACK_VALUE,

        /// <summary>Packet is a retransmission of previously sent data.</summary>
        Retransmit = UcpConstants.UCP_FLAG_RETRANSMIT_VALUE,

        /// <summary>Acknowledgment of a FIN packet.</summary>
        FinAck = UcpConstants.UCP_FLAG_FIN_ACK_VALUE
    }

    /// <summary>
    /// States of a UCP connection state machine, mirroring TCP-like lifecycle.
    /// </summary>
    internal enum UcpConnectionState
    {
        /// <summary>Connection object created but not yet started.</summary>
        Init,

        /// <summary>SYN sent to the remote endpoint; awaiting SYN-ACK.</summary>
        HandshakeSynSent,

        /// <summary>SYN received from the remote endpoint; awaiting final ACK.</summary>
        HandshakeSynReceived,

        /// <summary>Connection fully established; data transfer is allowed.</summary>
        Established,

        /// <summary>Local side has initiated graceful close with a FIN.</summary>
        ClosingFinSent,

        /// <summary>Remote side has sent a FIN; local may still send data.</summary>
        ClosingFinReceived,

        /// <summary>Connection is fully closed and may be cleaned up.</summary>
        Closed
    }

    /// <summary>
    /// Operating modes of the BBR congestion control state machine.
    /// </summary>
    internal enum BbrMode
    {
        /// <summary>Initial rapid bandwidth probing with exponential-paced gain.</summary>
        Startup,

        /// <summary>Transient drain phase that reduces in-flight queue after startup.</summary>
        Drain,

        /// <summary>Steady-state cycling through high/low pacing gains to probe bandwidth.</summary>
        ProbeBw,

        /// <summary>Minimum-RTT probing phase that deliberately reduces in-flight data.</summary>
        ProbeRtt
    }
}
