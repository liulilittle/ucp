using System;

namespace Ucp
{
    internal enum UcpPacketType : byte
    {
        Syn = UcpConstants.UCP_SYN_TYPE_VALUE,
        SynAck = UcpConstants.UCP_SYN_ACK_TYPE_VALUE,
        Ack = UcpConstants.UCP_ACK_TYPE_VALUE,
        Nak = UcpConstants.UCP_NAK_TYPE_VALUE,
        Data = UcpConstants.UCP_DATA_TYPE_VALUE,
        Fin = UcpConstants.UCP_FIN_TYPE_VALUE,
        Rst = UcpConstants.UCP_RST_TYPE_VALUE
    }

    [Flags]
    internal enum UcpPacketFlags : byte
    {
        None = UcpConstants.UCP_FLAGS_NONE_VALUE,
        NeedAck = UcpConstants.UCP_FLAG_NEED_ACK_VALUE,
        Retransmit = UcpConstants.UCP_FLAG_RETRANSMIT_VALUE,
        FinAck = UcpConstants.UCP_FLAG_FIN_ACK_VALUE
    }

    internal enum UcpConnectionState
    {
        Init,
        HandshakeSynSent,
        HandshakeSynReceived,
        Established,
        ClosingFinSent,
        ClosingFinReceived,
        Closed
    }

    internal enum BbrMode
    {
        Startup,
        Drain,
        ProbeBw,
        ProbeRtt
    }
}
