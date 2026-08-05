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

        FecRepair = 0x08,

        Fin = UcpConstants.UCP_FIN_TYPE_VALUE,

        Rst = UcpConstants.UCP_RST_TYPE_VALUE
    }

    [Flags]
    internal enum UcpPacketFlags : byte
    {

        None = UcpConstants.UCP_FLAGS_NONE_VALUE,

        NeedAck = UcpConstants.UCP_FLAG_NEED_ACK_VALUE,

        Retransmit = UcpConstants.UCP_FLAG_RETRANSMIT_VALUE,

        FinAck = UcpConstants.UCP_FLAG_FIN_ACK_VALUE,

        HasAckNumber = UcpConstants.UCP_FLAG_HAS_ACK_VALUE,

        MtuProbe = UcpConstants.UCP_FLAG_MTU_PROBE_VALUE,

        PathChallenge = UcpConstants.UCP_FLAG_PATH_CHALLENGE_VALUE
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

    public enum UcpPriority : byte
    {

        Background = 0,

        Normal = 1,

        Interactive = 2,

        Urgent = 3
    }

    public enum UcpMode : byte
    {

        Startup = 0,

        Drain = 1,

        ProbeBw = 2,
    }

}
